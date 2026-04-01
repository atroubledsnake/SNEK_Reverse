use std::sync::Arc;
use std::thread;

use super::spinlock::SpinLock;

type Job = Box<dyn FnOnce() + Send + 'static>;

/// A smol thread pool that keeps a fixed-size team of workers for any tasks
pub struct SnekThreadPool {
    workers: Vec<Worker>,
    sender: Arc<SpinLock<Option<std::sync::mpsc::Sender<Job>>>>,
}

impl SnekThreadPool {
    /// Spin up `size` background threads and return a pool that can talk to them
    /// Panics if you ask for zero threads,  that would be a very boring pool
    pub fn new(size: usize) -> Self {
        assert!(size > 0, "Thread pool size must be greater than zero");

        let (sender, receiver) = std::sync::mpsc::channel();
        let receiver = Arc::new(SpinLock::new(receiver));

        let workers = (0..size)
            .map(|id| Worker::new(id, Arc::clone(&receiver)))
            .collect();

        SnekThreadPool {
            workers,
            sender: Arc::new(SpinLock::new(Some(sender))),
        }
    }

    /// Hand a closure to the pool, it will run on the first free worker
    /// If the pool is already shutting down the task is dropped
    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);
        if let Some(sender) = self.sender.lock().as_ref() {
            let _ = sender.send(job);
        }
    }
}

// Channel closing
impl Drop for SnekThreadPool {
    fn drop(&mut self) {
        *self.sender.lock() = None;

        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

struct Worker {
    _id: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl Worker {
    fn new(id: usize, receiver: Arc<SpinLock<std::sync::mpsc::Receiver<Job>>>) -> Worker {
        let thread = thread::Builder::new()
            .name(format!("snek-worker-{id}"))
            .spawn(move || {
                loop {
                    match receiver.lock().try_recv() {
                        Ok(task) => task(),
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        }
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            break;
                        }
                    }
                }
            })
            .expect("failed to spawn worker thread");

        Worker {
            _id: id,
            thread: Some(thread),
        }
    }
}
