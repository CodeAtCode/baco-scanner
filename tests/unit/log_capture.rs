//! Capture `tracing` events so a test can assert that production code records
//! what it did.
//!
//! AGENTS.md requires that a path which skips work says so out loud. Asserting
//! that means reading the log, not the return value: `Ok(vec![])` looks the same
//! whether the code explained itself or swallowed the failure.
//!
//! Usage:
//!
//! ```ignore
//! let logs = capture_logs(|| { /* call the production code */ });
//! assert!(logs.contains("Skipping /path/to/file"));
//! ```

use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

/// The events recorded during a [`capture_logs`] call.
#[derive(Clone, Default)]
pub struct CapturedLogs(Arc<Mutex<Vec<String>>>);

impl CapturedLogs {
    /// Every recorded event message, in order.
    pub fn messages(&self) -> Vec<String> {
        self.0.lock().expect("log buffer is not poisoned").clone()
    }

    /// Whether any recorded message contains `needle`.
    pub fn contains(&self, needle: &str) -> bool {
        self.0
            .lock()
            .expect("log buffer is not poisoned")
            .iter()
            .any(|message| message.contains(needle))
    }
}

struct Capture(Arc<Mutex<Vec<String>>>);

impl Subscriber for Capture {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        struct Message(String);
        impl Visit for Message {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }

        let mut message = Message(String::new());
        event.record(&mut message);
        self.0
            .lock()
            .expect("log buffer is not poisoned")
            .push(message.0);
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

/// Run `f` with a subscriber that records every event, and return what it saw.
pub fn capture_logs<F: FnOnce()>(f: F) -> CapturedLogs {
    let logs = CapturedLogs::default();
    let subscriber = Capture(Arc::clone(&logs.0));
    tracing::subscriber::with_default(subscriber, f);
    logs
}
