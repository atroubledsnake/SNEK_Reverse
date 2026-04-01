/// You're free to use the threading module I made for this project on different terms to the license protecting the rest of the project
/// As long as you credit ATroubledSnake ofc ;P
/// License: MIT
/// Copyright (C) 2026-present ATroubledSnake & SNEK initiative

/// Permission is hereby granted, free of charge, to any person obtaining a copy of this software (Snek ThreadPool) and associated documentation files (the “Software”) (/src/threading/), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
/// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
/// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.



pub mod spinlock;
pub mod pool;

pub use pool::SnekThreadPool;
// pub use spinlock::SpinLock;
