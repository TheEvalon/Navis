//! Idle auto-lock for the vault.
//!
//! Renderer "ticks" the autolocker on every meaningful interaction. If
//! `idle_secs` elapses without a tick, the vault is locked. This is a
//! simple wall-clock timer — we accept that a frozen process won't lock
//! while frozen; that's not the threat we're modeling here. (See
//! `docs/THREATS.md` for the full memory-disclosure analysis.)

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::time;
use tracing::info;

use crate::core::vault::Vault;

/// Default idle timeout. Override at runtime from settings.
pub const DEFAULT_IDLE_SECS: u64 = 15 * 60;

#[derive(Clone)]
pub struct AutoLocker {
    inner: Arc<Inner>,
}

struct Inner {
    vault: Arc<Vault>,
    last_activity: Mutex<Instant>,
    idle_secs: Mutex<u64>,
}

impl AutoLocker {
    /// Constructs the locker without spawning the background task. Call
    /// [`Self::spawn_task`] from a context where a Tokio runtime is
    /// running (e.g. inside a Tauri setup hook via
    /// `tauri::async_runtime::spawn`).
    pub fn new(vault: Arc<Vault>) -> Self {
        Self {
            inner: Arc::new(Inner {
                vault,
                last_activity: Mutex::new(Instant::now()),
                idle_secs: Mutex::new(DEFAULT_IDLE_SECS),
            }),
        }
    }

    /// Spawns the background timer onto Tauri's async runtime.
    pub fn spawn_task(&self) {
        let task = self.clone();
        tauri::async_runtime::spawn(async move {
            let mut tick = time::interval(Duration::from_secs(15));
            tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                task.maybe_lock();
            }
        });
    }

    /// Renderer-driven heartbeat.
    pub fn touch(&self) {
        *self.inner.last_activity.lock() = Instant::now();
    }

    /// Update the idle timeout (in seconds). Pass 0 to disable.
    pub fn set_idle_secs(&self, secs: u64) {
        *self.inner.idle_secs.lock() = secs;
    }

    pub fn idle_secs(&self) -> u64 {
        *self.inner.idle_secs.lock()
    }

    fn maybe_lock(&self) {
        let secs = *self.inner.idle_secs.lock();
        if secs == 0 {
            return;
        }
        if !self.inner.vault.is_unlocked() {
            return;
        }
        let elapsed = self.inner.last_activity.lock().elapsed();
        if elapsed >= Duration::from_secs(secs) {
            info!("auto-locking vault after {}s idle", elapsed.as_secs());
            self.inner.vault.lock();
        }
    }
}
