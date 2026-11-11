//! A notification group's event queue (Linux fs/notify/notification.c),
//! shared by inotify and fanotify
//!
//! Events are allocated before the group's queue lock is taken (Linux
//! inotify_handle_inode_event, fanotify_alloc_event) and queued under it
//! (fsnotify_insert_event, under notification_lock); a read takes the
//! oldest off under it and frees it after. Past the group's
//! `max_events`, or with no memory for an event, the group's one
//! overflow event is queued in its place (Linux's preallocated
//! group->overflow_event): a position in the queue, so queueing it
//! allocates nothing. The caller owns the lock (`inner` of each group).

use alloc::boxed::Box;
use core::marker::PhantomData;

use crate::util::kalloc::try_box;
use crate::util::list::{Adapter, BoxList, Link};

/// A queued event (Linux struct fsnotify_event on notification_list)
pub struct EvNode<E> {
    link: Link,
    ev: E,
}

/// The adapter of `EvNode<E>.link`
struct EvAdapter<E>(PhantomData<E>);

// SAFETY: offset_of! gives the link's place in the node, so `item`
// inverts `link`
unsafe impl<E> Adapter for EvAdapter<E> {
    type Item = EvNode<E>;
    fn link(item: &EvNode<E>) -> &Link {
        &item.link
    }
    unsafe fn item(link: *const Link) -> *const EvNode<E> {
        // SAFETY: the caller passes the link of a live node
        unsafe {
            link.cast::<u8>()
                .sub(core::mem::offset_of!(EvNode<E>, link))
                .cast::<EvNode<E>>()
        }
    }
}

/// `ev` allocated for the queue, before its lock: None without memory
/// (the overflow event stands in)
pub fn ev_alloc<E>(ev: E) -> Option<Box<EvNode<E>>> {
    try_box(EvNode {
        link: Link::new(),
        ev,
    })
    .ok()
}

/// An event taken off the queue: the group's overflow event, or one
/// that is freed when this drops (after the queue lock)
pub enum Taken<E: 'static> {
    Overflow(&'static E),
    Ev(Box<EvNode<E>>),
}

impl<E> Taken<E> {
    pub fn ev(&self) -> &E {
        match self {
            Taken::Overflow(e) => e,
            Taken::Ev(n) => &n.ev,
        }
    }
}

/// A group's queued events (Linux group->notification_list, q_len,
/// max_events and overflow_event)
pub struct NotifQueue<E: 'static> {
    /// Queued events, oldest first
    events: BoxList<EvAdapter<E>>,
    /// The overflow event, while queued: how many of `events` are ahead
    /// of it
    overflow: Option<usize>,
    overflow_event: &'static E,
    max_events: usize,
}

impl<E> NotifQueue<E> {
    pub const fn new(max_events: usize, overflow_event: &'static E) -> Self {
        Self {
            events: BoxList::new(),
            overflow: None,
            overflow_event,
            max_events,
        }
    }

    /// Queued events, the overflow counted (Linux q_len)
    pub fn len(&self) -> usize {
        self.events.len() + usize::from(self.overflow.is_some())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Queue `ev` (Linux fsnotify_insert_event): at `max_events`, or
    /// without memory for it (None), the overflow event is queued in its
    /// place. Whether anything was queued (no wakeup if not), and the
    /// event if it was not, to free after the unlock.
    pub fn insert(&mut self, ev: Option<Box<EvNode<E>>>) -> (bool, Option<Box<EvNode<E>>>) {
        match ev {
            Some(e) if self.len() < self.max_events => {
                self.events.push_back(e);
                (true, None)
            }
            e => (self.queue_overflow(), e),
        }
    }

    /// Queue the overflow event unless it is queued (Linux
    /// fsnotify_queue_overflow)
    pub fn queue_overflow(&mut self) -> bool {
        if self.overflow.is_some() {
            return false;
        }
        self.overflow = Some(self.events.len());
        true
    }

    /// The oldest event (Linux fsnotify_peek_first_event)
    pub fn peek_first(&self) -> Option<&E> {
        match self.overflow {
            Some(0) => Some(self.overflow_event),
            _ => self.events.iter().next().map(|n| &n.ev),
        }
    }

    /// Take the oldest event (Linux fsnotify_remove_first_event)
    pub fn remove_first(&mut self) -> Option<Taken<E>> {
        match self.overflow {
            Some(0) => {
                self.overflow = None;
                Some(Taken::Overflow(self.overflow_event))
            }
            Some(n) => {
                self.overflow = Some(n - 1);
                self.events.pop_front().map(Taken::Ev)
            }
            None => self.events.pop_front().map(Taken::Ev),
        }
    }

    /// Every queued event, the overflow last (not in queue order)
    pub fn iter(&self) -> impl Iterator<Item = &E> {
        self.events
            .iter()
            .map(|n| &n.ev)
            .chain(self.overflow.map(|_| self.overflow_event))
    }
}
