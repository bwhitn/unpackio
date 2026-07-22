//! Per-operation cancellation and deterministic work accounting.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::{Error, LimitKind, Result};

/// A cloneable, per-operation cancellation token.
///
/// It contains no global state and may be shared by all readers and decoders
/// participating in one archive operation.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Creates a token in the running state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. Repeated calls are harmless.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Returns whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Returns [`Error::Cancelled`] when cancellation was requested.
    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// A deterministic work-unit budget for parser and decoder checkpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkBudget {
    remaining: Option<u64>,
    consumed: u64,
}

impl WorkBudget {
    /// Creates a bounded budget.
    #[must_use]
    pub const fn bounded(units: u64) -> Self {
        Self {
            remaining: Some(units),
            consumed: 0,
        }
    }

    /// Creates an unlimited budget. Cancellation and byte limits still apply.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            remaining: None,
            consumed: 0,
        }
    }

    /// Returns the remaining units, or `None` for an unlimited budget.
    #[must_use]
    pub const fn remaining(self) -> Option<u64> {
        self.remaining
    }

    /// Returns successfully charged work units.
    ///
    /// This counter is available for bounded and unlimited budgets. A failed
    /// charge does not change it.
    #[must_use]
    pub const fn consumed(self) -> u64 {
        self.consumed
    }

    /// Charges work before it is performed.
    pub fn charge(&mut self, units: u64) -> Result<()> {
        let updated_remaining = match self.remaining {
            Some(remaining) => Some(remaining.checked_sub(units).ok_or(Error::LimitExceeded {
                limit: LimitKind::WorkUnits,
                requested: units,
                maximum: remaining,
            })?),
            None => None,
        };
        let Some(updated_consumed) = self.consumed.checked_add(units) else {
            let maximum = u64::MAX
                .checked_sub(self.consumed)
                .ok_or(Error::LimitExceeded {
                    limit: LimitKind::WorkUnits,
                    requested: units,
                    maximum: 0,
                })?;
            return Err(Error::LimitExceeded {
                limit: LimitKind::WorkUnits,
                requested: units,
                maximum,
            });
        };
        self.remaining = updated_remaining;
        self.consumed = updated_consumed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CancellationToken, WorkBudget};
    use crate::{ErrorKind, LimitKind};

    #[test]
    fn cancellation_is_shared_by_clones() {
        let token = CancellationToken::new();
        let worker = token.clone();
        assert!(worker.check().is_ok());
        token.cancel();
        let error = worker.check().err();
        assert_eq!(
            error.as_ref().map(crate::Error::kind),
            Some(ErrorKind::Cancelled)
        );
    }

    #[test]
    fn bounded_work_is_charged_before_use() {
        let mut budget = WorkBudget::bounded(3);
        assert!(budget.charge(2).is_ok());
        assert_eq!(budget.remaining(), Some(1));
        assert_eq!(budget.consumed(), 2);

        let error = budget.charge(2);
        assert!(matches!(
            error,
            Err(crate::Error::LimitExceeded {
                limit: LimitKind::WorkUnits,
                requested: 2,
                maximum: 1,
            })
        ));
        assert_eq!(budget.remaining(), Some(1));
        assert_eq!(budget.consumed(), 2);
    }

    #[test]
    fn unlimited_work_does_not_use_a_numeric_sentinel() {
        let mut budget = WorkBudget::unlimited();
        assert!(budget.charge(u64::MAX).is_ok());
        assert_eq!(budget.remaining(), None);
        assert_eq!(budget.consumed(), u64::MAX);
        assert!(matches!(
            budget.charge(1),
            Err(crate::Error::LimitExceeded {
                limit: LimitKind::WorkUnits,
                requested: 1,
                maximum: 0,
            })
        ));
        assert_eq!(budget.consumed(), u64::MAX);
    }
}
