use std::sync::atomic::{AtomicBool, Ordering};
use std::cell::UnsafeCell;
use std::ops::{Deref, DerefMut};

/// A lightweight spin-lock that keeps threads busy-waiting instead of blocking in the kernel.
/// Use it only for **very short** critical sections—think a few instructions, not syscalls.
/// If you aren’t sure whether the section is “short enough”, use `std::sync::Mutex` instead.
pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: we only hand out `&mut T` while the caller holds the lock,
// and we never create aliasing `&mut T`.  The user must still ensure
// that `T: Send` so it is safe to move across threads.
unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Building a new lock protecting `data`.
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    /// Acquiring the lock, spinning until successful
    ///
    /// The returned guard automatically unlocks on drop
    #[inline]
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        let mut pause = 1;

        // Fast-path: try once
        while self
            .locked
            .compare_exchange_weak(
                false,
                true,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_err()
        {
            // Slow-path: fuck off politely
            for _ in 0..pause {
                std::hint::spin_loop();
            }
            if pause < 64 {
                pause *= 2;
            } else {
                std::thread::yield_now();
            }
        }

        SpinLockGuard { lock: self }
    }
}

/// A live lock guard.
///
/// Derefs to the protected data, dropping the guard releases the lock
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}
