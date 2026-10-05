//! Progress bar position arithmetic.
//!
//! The scanner phases each advance an `indicatif` progress bar while iterating
//! over items. That arithmetic used to be written out at every call site.

/// Position for item `i` of `total`, given the position the loop started from.
///
/// The formula is floating point on purpose. The inline copies this replaces
/// were `((i as f64 / total as f64) * 100.0) as u64`, and the nearest integer
/// form, `(i + 1) * 100 / total`, is not equivalent: at i=1 of 3 the float form
/// gives 33 and the integer form 66, so the bar would advance twice as fast over
/// the first half of the loop.
pub fn progress_position(base: u64, i: usize, total: usize) -> u64 {
    if total == 0 {
        return base;
    }
    base + ((i as f64 / total as f64) * 100.0) as u64
}
