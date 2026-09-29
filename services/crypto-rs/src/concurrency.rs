//! Nexis Core Financial Ledger Platform - Rust Crypto Engine
//! Module: Concurrency Controller & Thread Pool Manager
//!
//! Provides thread pool execution, background task coordination,
//! and channel-based dispatch pipelines for parallel transaction processing.

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

type Task = Box<dyn FnOnce() + Send + 'static>;

enum Message {
    NewTask(Task),
    Terminate,
}

/// Worker thread representation in pool.
struct Worker {
    id: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl Worker {
    fn new(id: usize, receiver: Arc<Mutex<Receiver<Message>>>) -> Self {
        let handle = thread::spawn(move || loop {
            let message = receiver.lock().unwrap().recv().unwrap();

            match message {
                Message::NewTask(job) => {
                    job();
                }
                Message::Terminate => {
                    break;
                }
            }
        });

        Self {
            id,
            thread: Some(handle),
        }
    }
}

/// Fixed-size thread pool managing concurrent ledger worker tasks.
pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: Option<Sender<Message>>,
}

impl ThreadPool {
    /// Creates a new ThreadPool with the specified number of threads.
    pub fn new(size: usize) -> Self {
        assert!(size > 0, "ThreadPool size must be greater than zero");

        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(size);

        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&receiver)));
        }

        Self {
            workers,
            sender: Some(sender),
        }
    }

    /// Dispatches a closure task to an available worker thread.
    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);
        if let Some(ref sender) = self.sender {
            sender.send(Message::NewTask(job)).unwrap();
        }
    }

    /// Returns the configured capacity of the thread pool.
    pub fn pool_size(&self) -> usize {
        self.workers.len()
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            for _ in &self.workers {
                sender.send(Message::Terminate).unwrap();
            }
        }

        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap();
            }
        }
    }
}
