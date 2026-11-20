//! Windowed min/max tracker (Linux lib/win_minmax.c, Kathleen Nichols'
//! algorithm): the best of the samples within a time window, kept as
//! the best, second best and third best over the window's quarters

/// A data point (Linux struct minmax_sample)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sample {
    /// When it was measured
    pub t: u32,
    /// Its value
    pub v: u32,
}

/// The tracker (Linux struct minmax)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Minmax {
    s: [Sample; 3],
}

impl Minmax {
    /// Linux minmax_get: the best in the window
    pub fn get(&self) -> u32 {
        self.s[0].v
    }

    /// Linux minmax_reset: `meas` at `t` is all there is
    pub fn reset(&mut self, t: u32, meas: u32) -> u32 {
        self.s = [Sample { t, v: meas }; 3];
        self.s[0].v
    }

    /// Linux minmax_subwin_update: age out choices past the window, or
    /// take new second and third choices a quarter and half way in
    fn subwin_update(&mut self, win: u32, val: Sample) -> u32 {
        let dt = val.t.wrapping_sub(self.s[0].t);
        if dt > win {
            // The whole window passed without a new best: the second
            // choice is the best, the third the second (perhaps twice)
            self.s[0] = self.s[1];
            self.s[1] = self.s[2];
            self.s[2] = val;
            if val.t.wrapping_sub(self.s[0].t) > win {
                self.s[0] = self.s[1];
                self.s[1] = self.s[2];
                self.s[2] = val;
            }
        } else if self.s[1].t == self.s[0].t && dt > win / 4 {
            // A quarter of the window without a new best: a second
            // choice from the second quarter
            self.s[1] = val;
            self.s[2] = val;
        } else if self.s[2].t == self.s[1].t && dt > win / 2 {
            // Half the window without a new best: a third choice from
            // the second half
            self.s[2] = val;
        }
        self.s[0].v
    }

    /// Linux minmax_running_min: `meas` at `t` in a window of `win`;
    /// the minimum
    pub fn running_min(&mut self, win: u32, t: u32, meas: u32) -> u32 {
        let val = Sample { t, v: meas };
        if val.v <= self.s[0].v || val.t.wrapping_sub(self.s[2].t) > win {
            return self.reset(t, meas);
        }
        if val.v <= self.s[1].v {
            self.s[1] = val;
            self.s[2] = val;
        } else if val.v <= self.s[2].v {
            self.s[2] = val;
        }
        self.subwin_update(win, val)
    }

    /// Linux minmax_running_max: as `running_min` for the maximum
    pub fn running_max(&mut self, win: u32, t: u32, meas: u32) -> u32 {
        let val = Sample { t, v: meas };
        if val.v >= self.s[0].v || val.t.wrapping_sub(self.s[2].t) > win {
            return self.reset(t, meas);
        }
        if val.v >= self.s[1].v {
            self.s[1] = val;
            self.s[2] = val;
        } else if val.v >= self.s[2].v {
            self.s[2] = val;
        }
        self.subwin_update(win, val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_ages_out() {
        let mut m = Minmax::default();
        m.reset(0, !0);
        assert_eq!(m.running_min(100, 0, 50), 50);
        // Larger samples do not replace the minimum in the window
        assert_eq!(m.running_min(100, 30, 70), 50);
        assert_eq!(m.running_min(100, 60, 60), 50);
        // Past the window, the best later choice takes over
        assert_eq!(m.running_min(100, 101, 80), 60);
        assert_eq!(m.running_min(100, 300, 90), 90);
        // A new minimum resets
        assert_eq!(m.running_min(100, 301, 10), 10);
        assert_eq!(m.s, [Sample { t: 301, v: 10 }; 3]);
    }

    #[test]
    fn max_tracks() {
        let mut m = Minmax::default();
        m.reset(0, 0);
        assert_eq!(m.running_max(10, 1, 5), 5);
        assert_eq!(m.running_max(10, 2, 3), 5);
        // Nothing left in the window: reset
        assert_eq!(m.running_max(10, 12, 2), 2);
    }
}
