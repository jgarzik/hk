//! Device IRQs: the handler table and its dispatch (Linux
//! kernel/irq/manage.c request_irq/free_irq, handle.c, spurious.c)
//!
//! Each device line (`arch::IrqChipOps`: x86 PIC lines 0-15, arm64 SPIs
//! 32-287) has a descriptor with a list of handlers; several may share
//! it (Linux IRQF_SHARED; each says whether its device raised the
//! interrupt). `request_irq` adds one and returns an `IrqRegistration`
//! whose drop removes it; the first handler unmasks the line, the last
//! one masks it.
//!
//! Unclaimed-interrupt accounting (Linux kernel/irq/spurious.c
//! note_interrupt): a line nobody claims - a device holding a shared
//! level-triggered line asserted with no driver for it - would storm
//! forever. Out of every 100,000 interrupts on a line, more than 99,900
//! unclaimed ones disable it ("nobody cared"). An unclaimed interrupt
//! more than 100 ms after the previous one restarts the unclaimed count,
//! so occasional strays on a busy line never add up. An interrupt on a
//! line without handlers masks it.
//!
//! Locking: each line's descriptor has its own `IrqSpinlock`
//! (`IrqDesc.lock`, Linux desc->lock), taken by `handle_irq` in IRQ
//! context and by request and free in thread context; different lines
//! never contend and no code holds two. The chip's mask and unmask run
//! under it (Linux irq_startup/irq_shutdown under desc->lock), and so do
//! the handlers: once a registration's drop returns its handler is not
//! running (Linux free_irq's synchronize_irq). Handlers must not request
//! or free IRQs. The line's reference to a freed handler is dropped
//! after unlocking.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::arch::{CurrentArch, IrqChipOps};
use crate::sync::IrqSpinlock;
use crate::util::error::{KernelError, KernelResult};

/// Whether a handler's device raised the interrupt (Linux irqreturn_t)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqReturn {
    /// Not this device's (a shared line)
    None,
    /// This device's, handled
    Handled,
}

/// Linux IRQ_RETVAL
impl From<bool> for IrqReturn {
    fn from(handled: bool) -> Self {
        if handled { Self::Handled } else { Self::None }
    }
}

/// An interrupt handler with its device state (Linux irq_handler_t and
/// its dev_id): the line holds a reference while it is registered
pub trait IrqHandler: Send + Sync {
    /// Handle interrupt `irq` (IRQ context, under the line's lock)
    fn handle(&self, irq: u32) -> IrqReturn;
}

/// A handler with no state of its own
pub struct IrqFn(pub fn(u32) -> IrqReturn);

impl IrqHandler for IrqFn {
    fn handle(&self, irq: u32) -> IrqReturn {
        (self.0)(irq)
    }
}

/// The device lines
static IRQ_TABLE: IrqTable<CurrentArch, { <CurrentArch as IrqChipOps>::NR_IRQS }> = IrqTable::new();

/// Add `handler` to line `irq` and unmask the line if it is the first
/// (Linux request_irq with IRQF_SHARED; the handler's address is its
/// dev_id). EINVAL for a line the controller lacks, EBUSY if `handler`
/// is on it already
pub fn request_irq<T: IrqHandler + 'static>(
    irq: u32,
    handler: Arc<T>,
) -> KernelResult<IrqRegistration<T>> {
    IRQ_TABLE.request(irq, handler)
}

/// Run the handlers of device line `irq` (IRQ context; Linux
/// generic_handle_irq). True if one claimed it
pub fn handle_irq(irq: u32) -> bool {
    let (handled, bad) = IRQ_TABLE.handle(irq, crate::time::monotonic_ns);
    if bad {
        report_nobody_cared(irq);
    }
    handled
}

/// The IRQ of a PCI function's INTx `pin` (arch routing)
pub fn pci_intx_irq(bus: u8, device: u8, function: u8, pin: u8, line: u8) -> Option<u32> {
    CurrentArch::pci_intx_irq(bus, device, function, pin, line)
}

/// A handler on an IRQ line of controller `C` (Linux request_irq to
/// free_irq): dropping it removes the handler, waiting out a running
/// call
#[must_use]
pub struct IrqRegistration<T: IrqHandler + 'static, C: IrqChipOps + 'static = CurrentArch> {
    handler: Arc<T>,
    irq: u32,
    desc: &'static IrqDesc<C>,
}

impl<T: IrqHandler + 'static, C: IrqChipOps + 'static> IrqRegistration<T, C> {
    /// The registered handler
    pub fn handler(&self) -> &Arc<T> {
        &self.handler
    }

    /// The line it is on
    pub fn irq(&self) -> u32 {
        self.irq
    }
}

impl<T: IrqHandler + 'static, C: IrqChipOps + 'static> Drop for IrqRegistration<T, C> {
    fn drop(&mut self) {
        // Released here, with the line unlocked
        drop(self.desc.free(self.irq, cookie(&self.handler)));
    }
}

/// A handler's identity on its line (Linux dev_id): its address
fn cookie<T: ?Sized>(h: &Arc<T>) -> *const () {
    Arc::as_ptr(h).cast()
}

/// A line's handlers (Linux irqaction list) and unclaimed-interrupt
/// state, under its descriptor's lock
struct Line {
    actions: Vec<Arc<dyn IrqHandler>>,
    spurious: Spurious,
}

impl Line {
    fn find(&self, cookie: *const ()) -> Option<usize> {
        self.actions.iter().position(|h| self::cookie(h) == cookie)
    }

    /// Every handler of a shared line gets a look; true if one claimed
    /// it (Linux __handle_irq_event_percpu)
    fn run(&self, irq: u32) -> bool {
        let mut handled = false;
        for h in &self.actions {
            crate::sync::lockdep::irq_enter();
            handled |= h.handle(irq) == IrqReturn::Handled;
            crate::sync::lockdep::irq_exit();
        }
        handled
    }
}

/// One line of controller `C` (Linux irq_desc) with its own lock
struct IrqDesc<C> {
    lock: IrqSpinlock<Line>,
    _chip: PhantomData<fn() -> C>,
}

impl<C: IrqChipOps> IrqDesc<C> {
    const fn new() -> Self {
        Self {
            lock: IrqSpinlock::new(Line {
                actions: Vec::new(),
                spurious: Spurious::new(),
            }),
            _chip: PhantomData,
        }
    }

    /// Linux __setup_irq: the first handler starts the line
    fn add(&self, irq: u32, h: Arc<dyn IrqHandler>) -> KernelResult<()> {
        let mut line = self.lock.lock();
        if line.find(cookie(&h)).is_some() {
            return Err(KernelError::Busy);
        }
        line.actions
            .try_reserve(1)
            .map_err(|_| KernelError::OutOfMemory)?;
        line.actions.push(h);
        line.spurious.reset();
        if line.actions.len() == 1 {
            C::irq_unmask(irq);
        }
        Ok(())
    }

    /// Linux __free_irq: the last handler shuts the line down; its
    /// reference comes back for the caller to drop unlocked
    fn free(&self, irq: u32, cookie: *const ()) -> Option<Arc<dyn IrqHandler>> {
        let mut line = self.lock.lock();
        let i = line.find(cookie)?;
        let h = line.actions.remove(i);
        if line.actions.is_empty() {
            C::irq_mask(irq);
        }
        Some(h)
    }

    /// Linux handle_irq_event + note_interrupt; `now_ns` is read only
    /// for an unclaimed interrupt. (claimed, line masked as nobody
    /// cared): the caller reports that unlocked
    fn handle(&self, irq: u32, now_ns: impl FnOnce() -> u64) -> (bool, bool) {
        let mut line = self.lock.lock();
        let handled = line.run(irq);
        let empty = line.actions.is_empty();
        let bad = !empty && line.spurious.note(handled, now_ns);
        if bad || empty {
            C::irq_mask(irq);
        }
        (handled, bad)
    }
}

/// The lines of interrupt controller `C`: `N` of them from
/// `C::FIRST_IRQ` (Linux irq_desc array; static, nothing allocated)
struct IrqTable<C, const N: usize>([IrqDesc<C>; N]);

impl<C: IrqChipOps + 'static, const N: usize> IrqTable<C, N> {
    const fn new() -> Self {
        Self([const { IrqDesc::new() }; N])
    }

    /// Line `irq`'s descriptor; EINVAL for one the controller lacks
    fn desc(&self, irq: u32) -> KernelResult<&IrqDesc<C>> {
        let i = irq
            .checked_sub(C::FIRST_IRQ)
            .and_then(|i| usize::try_from(i).ok())
            .ok_or(KernelError::InvalidArgument)?;
        self.0.get(i).ok_or(KernelError::InvalidArgument)
    }

    fn request<T: IrqHandler + 'static>(
        &'static self,
        irq: u32,
        handler: Arc<T>,
    ) -> KernelResult<IrqRegistration<T, C>> {
        let desc = self.desc(irq)?;
        desc.add(irq, handler.clone())?;
        Ok(IrqRegistration { handler, irq, desc })
    }

    /// Dispatch line `irq`: (claimed, masked as nobody cared)
    fn handle(&self, irq: u32, now_ns: impl FnOnce() -> u64) -> (bool, bool) {
        self.desc(irq)
            .map_or((false, false), |d| d.handle(irq, now_ns))
    }
}

/// Interrupts per accounting window (Linux note_interrupt)
const WINDOW: u32 = 100_000;

/// Unclaimed interrupts in a window that disable the line
const UNHANDLED_MAX: u32 = 99_900;

/// Gap after which an unclaimed interrupt restarts the count (Linux
/// HZ/10)
const UNHANDLED_GAP_NS: u64 = 100_000_000;

/// One line's unclaimed-interrupt state (Linux irq_desc irq_count,
/// irqs_unhandled, last_unhandled)
struct Spurious {
    count: u32,
    unhandled: u32,
    last_unhandled_ns: u64,
}

impl Spurious {
    const fn new() -> Self {
        Self {
            count: 0,
            unhandled: 0,
            last_unhandled_ns: 0,
        }
    }

    /// Start over (a handler was added)
    fn reset(&mut self) {
        *self = Self::new();
    }

    /// Account one interrupt; `now_ns` is read only for an unclaimed
    /// one (the claimed path stays cheap). True if the line must now be
    /// disabled (Linux note_interrupt)
    fn note(&mut self, handled: bool, now_ns: impl FnOnce() -> u64) -> bool {
        if !handled {
            let now_ns = now_ns();
            if now_ns.saturating_sub(self.last_unhandled_ns) > UNHANDLED_GAP_NS {
                self.unhandled = 1;
            } else {
                self.unhandled += 1;
            }
            self.last_unhandled_ns = now_ns;
        }
        self.count += 1;
        if self.count < WINDOW {
            return false;
        }
        let bad = self.unhandled > UNHANDLED_MAX;
        self.count = 0;
        self.unhandled = 0;
        bad
    }
}

/// Report a line `note` disabled (Linux __report_bad_irq); called after
/// dropping the line's lock
fn report_nobody_cared(irq: u32) {
    crate::printkln!("irq {}: nobody cared, disabling it", irq);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    /// A controller with lines 8-15; bit n of `UNMASKED`: line n is on
    struct Mock;

    static UNMASKED: AtomicU32 = AtomicU32::new(0);

    impl IrqChipOps for Mock {
        const FIRST_IRQ: u32 = 8;
        const NR_IRQS: usize = 8;
        fn irq_unmask(irq: u32) {
            UNMASKED.fetch_or(1 << irq, Ordering::SeqCst);
        }
        fn irq_mask(irq: u32) {
            UNMASKED.fetch_and(!(1 << irq), Ordering::SeqCst);
        }
        fn pci_intx_irq(_: u8, _: u8, _: u8, _: u8, _: u8) -> Option<u32> {
            None
        }
    }

    /// Each test uses lines of its own
    static TABLE: IrqTable<Mock, { Mock::NR_IRQS }> = IrqTable::new();

    fn unmasked(irq: u32) -> bool {
        UNMASKED.load(Ordering::SeqCst) & (1 << irq) != 0
    }

    /// A device that answers `ret` and counts its calls
    struct Dev {
        ret: IrqReturn,
        calls: AtomicU32,
    }

    fn dev(ret: IrqReturn) -> Arc<Dev> {
        Arc::new(Dev {
            ret,
            calls: AtomicU32::new(0),
        })
    }

    impl IrqHandler for Dev {
        fn handle(&self, _irq: u32) -> IrqReturn {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.ret
        }
    }

    fn calls(r: &IrqRegistration<Dev, Mock>) -> u32 {
        r.handler().calls.load(Ordering::SeqCst)
    }

    /// Lines outside the controller's range: EINVAL, never dispatched
    #[test]
    fn out_of_range() {
        for irq in [0, 7, 16, u32::MAX] {
            let r = TABLE.request(irq, dev(IrqReturn::Handled));
            assert_eq!(r.err(), Some(KernelError::InvalidArgument));
            assert_eq!(TABLE.handle(irq, || 0), (false, false));
        }
    }

    /// Every handler of a shared line runs; the line is claimed if one
    /// claims it; the first unmasks, the last one's drop masks
    #[test]
    fn shared_line() {
        let a = TABLE.request(8, dev(IrqReturn::None)).unwrap();
        assert!(unmasked(8));
        assert_eq!(a.irq(), 8);
        assert_eq!(TABLE.handle(8, || 0), (false, false));
        let b = TABLE.request(8, dev(IrqReturn::Handled)).unwrap();
        assert_eq!(TABLE.handle(8, || 0), (true, false));
        assert_eq!((calls(&a), calls(&b)), (2, 1));
        drop(b);
        assert!(unmasked(8));
        assert_eq!(TABLE.handle(8, || 0), (false, false));
        assert_eq!(calls(&a), 3);
        drop(a);
        assert!(!unmasked(8));
    }

    /// One handler twice on a line: EBUSY; on another line it may be
    #[test]
    fn same_handler_busy() {
        let d = dev(IrqReturn::Handled);
        let r = TABLE.request(9, d.clone()).unwrap();
        assert_eq!(TABLE.request(9, d.clone()).err(), Some(KernelError::Busy));
        let r2 = TABLE.request(10, d.clone()).unwrap();
        drop((r, r2));
        assert!(!unmasked(9) && !unmasked(10));
    }

    /// The drop removes the handler and the table's reference
    #[test]
    fn drop_unregisters() {
        let d = dev(IrqReturn::Handled);
        let r = TABLE.request(11, d.clone()).unwrap();
        assert_eq!(Arc::strong_count(&d), 3);
        drop(r);
        assert_eq!(Arc::strong_count(&d), 1);
        assert_eq!(TABLE.handle(11, || 0), (false, false));
        assert_eq!(d.calls.load(Ordering::SeqCst), 0);
    }

    /// An interrupt on a line without handlers masks it
    #[test]
    fn empty_line_masked() {
        Mock::irq_unmask(12);
        assert_eq!(TABLE.handle(12, || 0), (false, false));
        assert!(!unmasked(12));
    }

    /// A line nobody claims is masked at the window's end; a new
    /// handler restarts the count
    #[test]
    fn nobody_cared() {
        let r = TABLE.request(13, dev(IrqReturn::None)).unwrap();
        for _ in 1..WINDOW {
            assert_eq!(TABLE.handle(13, || 0), (false, false));
        }
        assert!(unmasked(13));
        assert_eq!(TABLE.handle(13, || 0), (false, true));
        assert!(!unmasked(13));
        assert_eq!(calls(&r), WINDOW);
    }

    /// A stuck line, nothing claims it: disabled at the window's end
    #[test]
    fn storm_disabled() {
        let mut s = Spurious::new();
        for i in 1..WINDOW {
            assert!(!s.note(false, || i as u64 * 1000));
        }
        assert!(s.note(false, || WINDOW as u64 * 1000));
    }

    /// The old consecutive count never fired when a driver claimed one
    /// interrupt now and then; the window count does (more than 99.9%
    /// unclaimed)
    #[test]
    fn mostly_unclaimed_disabled() {
        let mut s = Spurious::new();
        let mut bad = false;
        for i in 0..WINDOW {
            bad |= s.note(i % 2000 == 0, || i as u64 * 1000);
        }
        assert!(bad);
    }

    /// A busy line whose driver claims most interrupts stays on
    #[test]
    fn mostly_claimed_kept() {
        let mut s = Spurious::new();
        for i in 0..3 * WINDOW {
            assert!(!s.note(i % 10 != 0, || i as u64 * 1000));
        }
    }

    /// Strays 100 ms apart never add up
    #[test]
    fn sparse_strays_kept() {
        let mut s = Spurious::new();
        for i in 0..2 * WINDOW as u64 {
            assert!(!s.note(false, || i * (UNHANDLED_GAP_NS + 1)));
        }
    }
}
