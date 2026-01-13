use std::sync::{Mutex, MutexGuard};
use std::marker::PhantomData;

//
// 1. Mock BottomHalfDisabled
//
#[derive(Clone, Copy, Debug)]
pub struct BottomHalfDisabled;

//
// 2. Mock SpinLock<T, Ctx>
//    注意：lock() 必须返回 SpinLockGuard，而不是 MutexGuard
//
pub struct SpinLock<T, Ctx = ()> {
    inner: Mutex<T>,
    _marker: PhantomData<Ctx>,
}

impl<T, Ctx> SpinLock<T, Ctx> {
    pub fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
            _marker: PhantomData,
        }
    }

    pub fn lock(&self) -> SpinLockGuard<'_, T, Ctx> {
        SpinLockGuard {
            guard: self.inner.lock().unwrap(),
            _marker: PhantomData,
        }
    }
}

//
// 2.1 Mock SpinLockGuard
//
pub struct SpinLockGuard<'a, T, Ctx = ()> {
    pub(crate) guard: MutexGuard<'a, T>,
    pub(crate) _marker: PhantomData<Ctx>,
}

impl<'a, T, Ctx> std::ops::Deref for SpinLockGuard<'a, T, Ctx> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &*self.guard
    }
}

impl<'a, T, Ctx> std::ops::DerefMut for SpinLockGuard<'a, T, Ctx> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.guard
    }
}

//
// 3. Mock SoftIRQ
//
#[derive(Clone, Copy, Debug)]
pub struct SoftIrq;

impl SoftIrq {
    pub fn new() -> Self {
        SoftIrq
    }

    pub fn raise(&self) {
        // no-op
    }
}

//
// 4. Mock Time
//
pub struct Time;

impl Time {
    pub fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
}

//
// 5. Mock Device
//
pub struct FakeDevice;

impl FakeDevice {
    pub fn new() -> Self {
        FakeDevice
    }

    pub fn transmit(&self, _buf: &[u8]) {
        // no-op
    }
}

//
// 6. Mock Jiffies
//
pub struct Jiffies;

impl Jiffies {
    pub fn elapsed() -> std::time::Duration {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
    }
}


#[macro_export]
macro_rules! const_assert {
    ($cond:expr) => {
        const _: () = assert!($cond);
    };
}