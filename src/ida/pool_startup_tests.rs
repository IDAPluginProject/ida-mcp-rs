//! Subprocess tests for the supervisor; these fake workers do not load IDA.

use crate::error::ToolError;
use crate::ida::pool::{ChildState, WorkerPool, WorkerPoolConfig};
use std::path::PathBuf;
use std::time::Duration;

struct Fixture {
    directory: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("ida-mcp-startup-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create private fixture");
        Self { directory }
    }

    fn ready(&self) {
        std::fs::write(self.directory.join("ready"), b"").expect("release handshake");
    }

    fn pool(&self, startup_timeout: Duration) -> WorkerPool {
        // Record the PID only after receiving initialize. Withhold its response
        // until the test releases it, then behave like an idle MCP server.
        let script = r#"
IFS= read -r request || exit 1
printf '%s\n' "$$" > "$1/pid"
while [ ! -e "$1/ready" ]; do sleep 0.05; done
id=$(printf '%s\n' "$request" | sed -n 's/.*"id":\([^,}]*\).*/\1/p')
printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"startup-test","version":"1"}}}\n' "$id"
while IFS= read -r request; do :; done
"#;
        let mut pool = WorkerPool::new(WorkerPoolConfig {
            max_workers: 1,
            min_workers: 1,
            worker_idle_timeout: Duration::ZERO,
            worker_op_timeout: Duration::from_secs(60),
            exe_path: PathBuf::from("/bin/sh"),
            worker_args: vec![
                "-c".into(),
                script.into(),
                "startup-test".into(),
                self.directory.clone().into_os_string(),
            ],
        });
        pool.startup_timeout = startup_timeout;
        pool
    }

    async fn pid(&self) -> i32 {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(contents) = std::fs::read_to_string(self.directory.join("pid"))
                    && let Ok(pid) = contents.trim().parse::<i32>()
                {
                    assert!(pid > 0);
                    return pid;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("fake worker received initialize")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

async fn assert_process_exited(pid: i32) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            // SAFETY: pid is positive and signal 0 only queries process
            // existence; no memory or process state is modified.
            if unsafe { libc::kill(pid, 0) } != 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("worker process exited and was reaped");
}

#[tokio::test]
async fn timed_out_replacement_releases_capacity_and_a_later_lease_recovers() {
    let fixture = Fixture::new();
    let pool = fixture.pool(Duration::from_secs(1));
    tokio::time::timeout(Duration::from_secs(1), pool.schedule_replenishment())
        .await
        .expect("retirement does not wait for replacement initialization");
    assert!(matches!(
        pool.lease("too-early").await,
        Err(ToolError::PoolExhausted { .. })
    ));
    let first_pid = fixture.pid().await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while pool.live_or_reserved_count().await != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("timed out startup releases its reservation");
    assert_process_exited(first_pid).await;

    fixture.ready();
    let handle = pool.lease("retry").await.expect("later startup succeeds");
    let second_pid = fixture.pid().await;
    assert_ne!(first_pid, second_pid);
    assert_eq!(pool.live_or_reserved_count().await, 1);
    drop(handle);
    pool.shutdown_all().await;
    assert_process_exited(second_pid).await;
}

#[tokio::test]
async fn shutdown_cancels_and_joins_a_stalled_replacement() {
    let fixture = Fixture::new();
    let pool = fixture.pool(Duration::from_secs(60));
    pool.schedule_replenishment().await;
    let pid = fixture.pid().await;
    tokio::time::timeout(Duration::from_secs(2), pool.shutdown_all())
        .await
        .expect("shutdown cancels startup instead of waiting for its deadline");
    assert_process_exited(pid).await;
    fixture.ready();
    pool.schedule_replenishment().await;
    assert_eq!(pool.live_or_reserved_count().await, 0);
    assert!(matches!(
        pool.lease("closed").await,
        Err(ToolError::WorkerClosed)
    ));
    assert!(matches!(
        pool.warm_min().await,
        Err(ToolError::WorkerClosed)
    ));
}

#[tokio::test]
async fn shutdown_rejects_a_worker_that_finished_handshaking_before_installation() {
    let fixture = Fixture::new();
    fixture.ready();
    let pool = fixture.pool(Duration::from_secs(3));
    let reservation = pool.reserve_spawn_slot().await.expect("reserve worker");
    let slot = pool
        .spawn_slot(reservation.worker_id(), ChildState::Idle)
        .await
        .expect("worker handshake completes");
    let pid = fixture.pid().await;

    let shutdown_pool = pool.clone();
    let shutdown = tokio::spawn(async move { shutdown_pool.shutdown_all().await });
    pool.shutdown.cancelled().await;
    assert!(
        !shutdown.is_finished(),
        "shutdown waits for pending installation"
    );
    assert!(matches!(
        reservation.finish(Some(slot)).await,
        Err(ToolError::WorkerClosed)
    ));
    tokio::time::timeout(Duration::from_secs(7), shutdown)
        .await
        .expect("shutdown finishes")
        .expect("shutdown task succeeds");
    assert_eq!(pool.live_or_reserved_count().await, 0);
    assert_process_exited(pid).await;
}
