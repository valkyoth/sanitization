//! Loom model for the `ConsumeOnceSecret` atomic ownership transition.
//!
//! This tool is intentionally outside the publishable workspace. It mirrors
//! the production `AtomicBool::swap(true, AcqRel)` claim and the cleanup-before-
//! return ordering without adding Loom to the runtime crate's dependency graph.

#[cfg(test)]
mod tests {
    use loom::{
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        thread,
    };

    struct ConsumeModel {
        claimed: AtomicBool,
        active: AtomicUsize,
        cleared: AtomicBool,
    }

    impl ConsumeModel {
        fn new() -> Self {
            Self {
                claimed: AtomicBool::new(false),
                active: AtomicUsize::new(0),
                cleared: AtomicBool::new(false),
            }
        }

        fn claim(&self) -> Option<CleanupGuard<'_>> {
            if self.claimed.swap(true, Ordering::AcqRel) {
                return None;
            }

            assert_eq!(
                self.active.fetch_add(1, Ordering::AcqRel),
                0,
                "two accessors entered the protected value"
            );
            Some(CleanupGuard { owner: self })
        }
    }

    struct CleanupGuard<'a> {
        owner: &'a ConsumeModel,
    }

    impl Drop for CleanupGuard<'_> {
        fn drop(&mut self) {
            assert_eq!(self.owner.active.fetch_sub(1, Ordering::AcqRel), 1);
            self.owner.cleared.store(true, Ordering::Release);
        }
    }

    #[test]
    fn exactly_one_racing_consumer_enters_and_cleanup_completes() {
        loom::model(|| {
            let model = Arc::new(ConsumeModel::new());
            let successes = Arc::new(AtomicUsize::new(0));

            let first_model = Arc::clone(&model);
            let first_successes = Arc::clone(&successes);
            let first = thread::spawn(move || {
                if let Some(_guard) = first_model.claim() {
                    first_successes.fetch_add(1, Ordering::AcqRel);
                    thread::yield_now();
                }
            });

            let second_model = Arc::clone(&model);
            let second_successes = Arc::clone(&successes);
            let second = thread::spawn(move || {
                if let Some(_guard) = second_model.claim() {
                    second_successes.fetch_add(1, Ordering::AcqRel);
                    thread::yield_now();
                }
            });

            first.join().unwrap();
            second.join().unwrap();

            assert_eq!(successes.load(Ordering::Acquire), 1);
            assert_eq!(model.active.load(Ordering::Acquire), 0);
            assert!(model.claimed.load(Ordering::Acquire));
            assert!(model.cleared.load(Ordering::Acquire));
        });
    }

    #[test]
    fn cleanup_precedes_the_end_of_the_winning_scope() {
        loom::model(|| {
            let model = ConsumeModel::new();

            {
                let _guard = model.claim().expect("first claim must succeed");
                assert_eq!(model.active.load(Ordering::Acquire), 1);
                assert!(!model.cleared.load(Ordering::Acquire));
                assert!(model.claim().is_none());
            }

            assert_eq!(model.active.load(Ordering::Acquire), 0);
            assert!(model.cleared.load(Ordering::Acquire));
        });
    }
}
