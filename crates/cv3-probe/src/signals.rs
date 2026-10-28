//! Co-operative shutdown for catchable signals.
//!
//! A handler can only set a flag; it cannot touch the USB device. The probe installs a watcher
//! before it opens anything and checks it between steps, so an interrupt unwinds through the same
//! RAII teardown as any other error and the interface is released before the process exits.

use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

/// The signals the probe treats as a request to stop.
pub const SHUTDOWN_SIGNALS: [i32; 3] = [
    signal_hook::consts::signal::SIGINT,
    signal_hook::consts::signal::SIGTERM,
    signal_hook::consts::signal::SIGHUP,
];

/// Somewhere the probe can ask whether a shutdown has been requested.
pub trait Shutdown {
    /// The first shutdown signal received, if any.
    fn signalled(&self) -> Option<i32>;
}

/// A watched signal, stored as `0` for "none" so the handler needs no lock.
#[derive(Debug, Clone, Default)]
pub struct SignalFlag(Arc<AtomicI32>);

impl SignalFlag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn raise(&self, signal: i32) {
        // Keep the first signal: which one arrived does not matter beyond the exit status, and a
        // second signal must not overwrite the first for no reason.
        let _ = self
            .0
            .compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
    }

    pub fn get(&self) -> Option<i32> {
        match self.0.load(Ordering::Relaxed) {
            0 => None,
            signal => Some(signal),
        }
    }
}

impl Shutdown for SignalFlag {
    fn signalled(&self) -> Option<i32> {
        self.get()
    }
}

/// Watches the process for the shutdown signals on a dedicated thread.
///
/// The handler thread only records the signal number; it never touches the device. Dropping the
/// watcher closes the iterator and joins the thread.
pub struct SignalWatch {
    flag: SignalFlag,
    handle: signal_hook::iterator::Handle,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl SignalWatch {
    /// Starts watching [`SHUTDOWN_SIGNALS`].
    pub fn install() -> std::io::Result<Self> {
        Self::install_for(&SHUTDOWN_SIGNALS)
    }

    fn install_for(signals: &[i32]) -> std::io::Result<Self> {
        let mut source = signal_hook::iterator::Signals::new(signals)?;
        let handle = source.handle();
        let flag = SignalFlag::new();
        let raised = flag.clone();
        let thread = std::thread::spawn(move || {
            if let Some(signal) = source.forever().next() {
                raised.raise(signal);
            }
        });
        Ok(Self {
            flag,
            handle,
            thread: Some(thread),
        })
    }
}

impl Shutdown for SignalWatch {
    fn signalled(&self) -> Option<i32> {
        self.flag.get()
    }
}

impl Drop for SignalWatch {
    fn drop(&mut self) {
        self.handle.close();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn a_raised_signal_is_recorded() {
        let watch = SignalWatch::install_for(&[signal_hook::consts::signal::SIGUSR1])
            .expect("signal handler installs");

        signal_hook::low_level::raise(signal_hook::consts::signal::SIGUSR1)
            .expect("signal is raised");

        let deadline = Instant::now() + Duration::from_secs(2);
        while watch.signalled().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(
            watch.signalled(),
            Some(signal_hook::consts::signal::SIGUSR1)
        );
    }

    #[test]
    fn no_signal_means_no_shutdown() {
        let watch = SignalWatch::install_for(&[signal_hook::consts::signal::SIGUSR2])
            .expect("signal handler installs");

        assert_eq!(watch.signalled(), None);
    }
}
