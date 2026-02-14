//! Simple periodic task scheduler for background jobs.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};
use tracing::info;

type ScheduledFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
type ScheduledFactory = Box<dyn Fn() -> ScheduledFuture + Send + Sync>;

/// One scheduled task definition.
pub struct ScheduledTask {
    pub name: &'static str,
    pub interval: Duration,
    pub last_run: Instant,
    pub task: ScheduledFactory,
}

/// Cooperative scheduler that polls due tasks every second.
pub struct Scheduler {
    tasks: Vec<ScheduledTask>,
}

impl Scheduler {
    /// Creates empty scheduler.
    ///
    /// Parameters: none.
    /// Returns: empty scheduler instance.
    pub fn new() -> Self {
        Self { tasks: Vec::new() }
    }

    /// Registers a new task.
    ///
    /// Parameters: `name` - task name, `interval` - run interval, `task` - async task factory.
    /// Returns: none.
    pub fn add<F>(&mut self, name: &'static str, interval: Duration, task: F)
    where
        F: Fn() -> ScheduledFuture + Send + Sync + 'static,
    {
        self.tasks.push(ScheduledTask {
            name,
            interval,
            last_run: Instant::now(),
            task: Box::new(task),
        });
    }

    /// Runs scheduler loop forever.
    ///
    /// Parameters: none.
    /// Returns: never returns under normal operation.
    pub async fn run(mut self) {
        loop {
            for task in &mut self.tasks {
                if task.last_run.elapsed() >= task.interval {
                    info!(task = task.name, "Scheduler: running task");
                    (task.task)().await;
                    task.last_run = Instant::now();
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}
