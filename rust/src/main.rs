use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::{Semaphore, Mutex, RwLock, mpsc, watch},
    time::{Duration, timeout},
};
use std::{
    collections::{HashSet},
    env,
    sync::{Arc, atomic::{AtomicUsize, Ordering, AtomicBool}},
};
use mailparse::{parse_mail, MailHeaderMap};
use sqlx::postgres::{PgPool, PgPoolOptions};
use tracing::{info, warn, error, debug};
use arc_swap::ArcSwap;

// ─────────────────────────────────────────────────────────────────────────────
// Constants & Tunables
// ─────────────────────────────────────────────────────────────────────────────
const MAX_EMAIL_SIZE_BYTES: usize = 50 * 1024 * 1024; // 50 MB hard cap
const BATCH_CHANNEL_SIZE: usize = 5000;                // was 2000
const BATCH_FLUSH_SIZE: usize = 1000;                   // flush when buffer reaches this
const BATCH_FLUSH_INTERVAL_MS: u64 = 100;               // flush every 100ms minimum
const BATCH_FLUSH_TIMEOUT_SECS: u64 = 30;              // hard timeout per flush
const DOMAIN_POLL_INTERVAL_SECS: u64 = 60;
const BANS_POLL_INTERVAL_SECS: u64 = 60;
const PRIVATE_EMAIL_POLL_INTERVAL_SECS: u64 = 30;
const HEARTBEAT_INTERVAL_SECS: u64 = 60;
const DB_POOL_MAX: u32 = 80;
const DB_POOL_MIN: u32 = 10;
const DB_ACQUIRE_TIMEOUT_SECS: u64 = 5;
const DB_IDLE_TIMEOUT_SECS: u64 = 600;
const DB_MAX_LIFETIME_SECS: u64 = 1800;
const DEFAULT_SMTP_MAX_SESSIONS: usize = 500;
const DEFAULT_SMTP_MAX_QUEUE: usize = 5000;
const DEFAULT_SMTP_SESSION_TIMEOUT_SECS: u64 = 60;
// Per-line idle timeout: if a client doesn't send the next SMTP command within
// this window, drop the connection. Stops dead/stalled senders from squatting
// on a session slot for the full session timeout.
const DEFAULT_SMTP_IDLE_TIMEOUT_SECS: u64 = 30;

// ─────────────────────────────────────────────────────────────────────────────
// Circuit Breaker for DB failures
// ─────────────────────────────────────────────────────────────────────────────
// FIX #9: Circuit breaker — when the DB is down, reject new emails fast (451)
// instead of filling the bounded channel buffer and risking OOM.
//
// Design: pure atomics, no mutex. The SMTP handler reads cb_open (cheap).
// The batch worker updates cb_failures on each flush result.
// A background task auto-resets the circuit after CB_RECOVERY_SECS.
const CB_FAILURE_THRESHOLD: usize = 5;   // trips after 5 consecutive flush failures
const CB_RECOVERY_SECS: u64 = 30;        // auto-reset after 30s of no failures

// ─────────────────────────────────────────────────────────────────────────────
// Data Structures
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
struct Ban {
    scope: String,
    value: String,
    match_type: String,
}

/// In-memory ban cache with O(1) lookups for all common cases.
#[derive(Debug, Default)]
struct BansCache {
    email_exact:    HashSet<String>,  // O(1) exact sender match
    email_contains: Vec<String>,       // O(n) substring check — only for pathological cases
    domain:         HashSet<String>,   // O(1) exact domain match
    domain_tlds:    HashSet<String>,   // O(1) TLD wildcard (e.g. "com" from "*.com")
}



#[derive(Debug, Clone)]
struct EmailInsert {
    mailbox_owner: String,
    mailbox: String,
    subject: String,
    body: String,
    html: String,
    from_addr: String,
    to_addrs: Vec<String>,
    size: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct Domain {
    domain: String,
}

/// Result of email processing — tells the caller whether the email was accepted
/// for async processing so the SMTP response can be sent accordingly.
enum ProcessResult {
    Accepted,
    Rejected(String), // reason
}

/// Bundles everything process_email needs from the SMTP handler's scope.
/// Avoids the clippy `too_many_arguments` warning and makes call sites cleaner.
struct ProcessContext {
    postgres_pool:      PgPool,
    whitelist_exact:    Arc<RwLock<HashSet<String>>>,
    whitelist_tlds:     Arc<RwLock<HashSet<String>>>,
    bans_cache:         Arc<RwLock<BansCache>>,
    private_email_cache: Arc<ArcSwap<HashSet<String>>>,
    batch_sender:       Arc<ArcSwap<mpsc::Sender<EmailInsert>>>,
    cb_open:            Arc<AtomicBool>,
    instance:           Arc<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Entry Point
// ─────────────────────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    // Build tokio runtime with configurable worker threads. Defaults to 2× CPU
    // count (I/O-bound workload — most session time is spent waiting on the
    // network). Override with TOKIO_WORKER_THREADS env var.
    let worker_threads: usize = env::var("TOKIO_WORKER_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| (num_cpus_or_default() * 2).max(4));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?;

    rt.block_on(async_main(worker_threads))
}

/// Best-effort CPU count without pulling in num_cpus crate.
fn num_cpus_or_default() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
}

async fn async_main(worker_threads: usize) -> anyhow::Result<()> {

    let connection_counter = Arc::new(AtomicUsize::new(0));

    // RUST_LOG controls verbosity. Default is INFO; set RUST_LOG=debug to see
    // per-SMTP-command tracing.
    let log_filter = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(log_filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .compact()
        .init();
    info!("=== SMTP Service (Receive Only) ===");
    info!("Tokio runtime: {} worker threads", worker_threads);

    // ── Environment Variables ──────────────────────────────────────────────
    let database_url = env::var("DATABASE_URL")?;
    let heartbeat_url = env::var("HEARTBEAT_URL").ok();
    let use_bans: bool = env::var("USE_BANS")
        .or_else(|_| env::var("USE_SUPABASE_BANS"))
        .unwrap_or_else(|_| "true".to_string())
        .parse()
        .unwrap_or(true);
    let use_domains: bool = env::var("USE_DOMAIN_WHITELIST")
        .or_else(|_| env::var("USE_SUPABASE_DOMAINS"))
        .unwrap_or_else(|_| "true".to_string())
        .parse()
        .unwrap_or(true);
    let listen_port: u16 = env::var("SMTP_RECEIVE_PORT").unwrap_or("25".into()).parse()?;
    let smtp_max_sessions: usize = env::var("SMTP_MAX_SESSIONS")
        .unwrap_or_else(|_| DEFAULT_SMTP_MAX_SESSIONS.to_string())
        .parse()
        .unwrap_or(DEFAULT_SMTP_MAX_SESSIONS);
    let smtp_max_queue: usize = env::var("SMTP_MAX_QUEUE")
        .unwrap_or_else(|_| DEFAULT_SMTP_MAX_QUEUE.to_string())
        .parse()
        .unwrap_or(DEFAULT_SMTP_MAX_QUEUE);
    let smtp_session_timeout_secs: u64 = env::var("SMTP_SESSION_TIMEOUT_SECS")
        .unwrap_or_else(|_| DEFAULT_SMTP_SESSION_TIMEOUT_SECS.to_string())
        .parse()
        .unwrap_or(DEFAULT_SMTP_SESSION_TIMEOUT_SECS);
    let smtp_idle_timeout_secs: u64 = env::var("SMTP_IDLE_TIMEOUT_SECS")
        .unwrap_or_else(|_| DEFAULT_SMTP_IDLE_TIMEOUT_SECS.to_string())
        .parse()
        .unwrap_or(DEFAULT_SMTP_IDLE_TIMEOUT_SECS);

    // ── PostgreSQL Pool with Health Check ─────────────────────────────────
    let postgres_pool = PgPoolOptions::new()
        .max_connections(DB_POOL_MAX)
        .min_connections(DB_POOL_MIN)
        .acquire_timeout(Duration::from_secs(DB_ACQUIRE_TIMEOUT_SECS))
        .idle_timeout(Duration::from_secs(DB_IDLE_TIMEOUT_SECS))
        .max_lifetime(Duration::from_secs(DB_MAX_LIFETIME_SECS))
        .connect(&database_url)
        .await?;

    // FIX #5: Verify database actually responds and required tables exist
    sqlx::query("SELECT 1")
        .execute(&postgres_pool)
        .await
        .map_err(|e| anyhow::anyhow!("Database health check failed: {}", e))?;
    info!("✓ Connected to PostgreSQL database (verified)");

    // FIX #20: Verify required tables exist before accepting connections
    let required_tables = ["inbox", "emails"];
    for table in required_tables {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = $1)"
        )
        .bind(table)
        .fetch_one(&postgres_pool)
        .await
        .map_err(|e| anyhow::anyhow!("Schema check query failed: {}", e))?;
        if !exists {
            return Err(anyhow::anyhow!(
                "Required table '{}' does not exist. Run schema.sql first.", table
            ));
        }
    }
    // FIX #20: private_email is optional — log presence/absence for operator awareness
    let has_private_email = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'private_email')"
    )
    .fetch_one(&postgres_pool)
    .await
    .unwrap_or(false);
    if has_private_email {
        info!("✓ private_email table present (private email feature enabled)");
    } else {
        info!("ℹ private_email table absent — private email feature disabled");
    }
    // If use_bans is true, verify bans table exists
    if use_bans {
        let has_bans: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'bans')"
        )
        .fetch_one(&postgres_pool)
        .await
        .unwrap_or(false);
        if !has_bans {
            return Err(anyhow::anyhow!(
                "Bans are enabled (use_bans=true) but the 'bans' table does not exist. Run schema.sql first, or set use_bans=false."
            ));
        }
        info!("✓ bans table verified");
    }

    // ── Shared State ───────────────────────────────────────────────────────
    // Domain whitelist split into exact matches and TLD wildcards for O(1) lookups.
    let domain_whitelist_exact: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));
    let domain_whitelist_tlds:  Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));
    let bans_cache: Arc<RwLock<BansCache>> = Arc::new(RwLock::new(BansCache::default()));
    // FIX: in-memory cache of private_email addresses to avoid a per-message
    // SELECT round-trip. Refreshed on a background poll.
    let private_email_cache: Arc<ArcSwap<HashSet<String>>> =
        Arc::new(ArcSwap::from_pointee(HashSet::new()));

    // ── Circuit Breaker for DB failures ────────────────────────────────
    // Tracks consecutive DB flush failures so we reject new emails fast
    // (451) instead of filling the channel buffer when the DB is down.
    let cb_failures: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let cb_open: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let cb_last_failure: Arc<std::sync::Mutex<std::time::Instant>> =
        Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
    let cb_failures_for_supervisor = cb_failures.clone();
    let cb_open_for_supervisor = cb_open.clone();
    let cb_last_failure_for_supervisor = cb_last_failure.clone();
    let cb_open_for_handler = cb_open.clone();

    // ── Batch Channel & Shutdown ───────────────────────────────────────
    // FIX #2 & #7: Larger channel + restartable supervisor
    let (batch_tx, _batch_rx) = mpsc::channel::<EmailInsert>(BATCH_CHANNEL_SIZE);
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    // ArcSwap so the sender can be atomically replaced on worker restart
    // without serializing every handler through a mutex.
    let batch_sender: Arc<ArcSwap<mpsc::Sender<EmailInsert>>> =
        Arc::new(ArcSwap::from_pointee(batch_tx));
    let batch_sender_for_swap = batch_sender.clone();
    let pool_for_supervisor = postgres_pool.clone();

    // FIX #1: Restartable batch worker supervisor
    // Owns the worker handle across its full lifetime. When the worker exits
    // (panic or channel close), it creates fresh channels and swaps the Arc
    // pointer so new SMTP sessions immediately use the new live channel.
    tokio::spawn(async move {
        let mut shutdown_rx = Some(shutdown_rx);

        loop {
            // Create a fresh channel pair for each worker incarnation
            let (tx, rx) = mpsc::channel::<EmailInsert>(BATCH_CHANNEL_SIZE);
            let worker_shutdown_rx = shutdown_rx.take()
                .unwrap_or_else(|| watch::channel(()).1);

            // Atomically swap the new sender into the ArcSwap — new sends
            // see the fresh sender on their next load(); in-flight retries
            // re-load on each attempt.
            batch_sender_for_swap.store(Arc::new(tx));

            warn!("Batch supervisor: spawning new worker");
            let handle = tokio::spawn(batch_worker(
                rx,
                pool_for_supervisor.clone(),
                worker_shutdown_rx,
                cb_failures_for_supervisor.clone(),
                cb_open_for_supervisor.clone(),
                cb_last_failure_for_supervisor.clone(),
            ));

            // Wait for this worker to exit (panic or clean exit)
            let result = handle.await;
            if result.is_err() {
                error!("Batch worker panicked — restarting in 1s");
            } else {
                info!("Batch worker exited cleanly");
            }

            // Small delay to prevent tight panic loops consuming CPU
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    // ── Domain & Bans Initialization ───────────────────────────────────────
    if use_domains {
        if let Err(e) = load_domain_whitelist(&postgres_pool, domain_whitelist_exact.clone(), domain_whitelist_tlds.clone()).await {
            warn!("✗ Failed to load domain whitelist: {}", e);
        }
    } else {
        info!("✓ Domain whitelist disabled - accepting all domains");
    }

    if use_bans {
        load_bans(&postgres_pool, bans_cache.clone()).await
            .map_err(|e| anyhow::anyhow!("Bans are enabled but failed to load: {}", e))?;
    } else {
        info!("✓ Bans disabled - no external bans loaded");
    }

    // ── Background Polling Tasks ───────────────────────────────────────────
    if use_domains {
        let exact = domain_whitelist_exact.clone();
        let tlds  = domain_whitelist_tlds.clone();
        let pool  = postgres_pool.clone();
        tokio::spawn(async move {
            poll_domain_updates(pool, exact, tlds).await;
        });
    }

    if use_bans {
        let cache = bans_cache.clone();
        let pool  = postgres_pool.clone();
        tokio::spawn(async move {
            poll_bans(pool, cache).await;
        });
    }

    // Private-email cache: only enable polling if the table actually exists.
    if has_private_email {
        // Initial load
        if let Err(e) = load_private_emails(&postgres_pool, private_email_cache.clone()).await {
            warn!("⚠ Initial private_email load failed: {} — will retry on next poll", e);
        }
        let cache = private_email_cache.clone();
        let pool  = postgres_pool.clone();
        tokio::spawn(async move {
            poll_private_emails(pool, cache).await;
        });
    }

    // ── Heartbeat (with reusable client) ────────────────────────────────
    if let Some(hb_url) = heartbeat_url {
        tokio::spawn(heartbeat_loop(hb_url));
    }

    // ── Circuit Breaker auto-reset task ─────────────────────────────────
    tokio::spawn(circuit_breaker_recovery_task(
        cb_failures.clone(),
        cb_open.clone(),
        cb_last_failure.clone(),
    ));

    // ── Shutdown Flag ─────────────────────────────────────────────────────
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    let handlers: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let shutdown_requested_clone = shutdown_requested.clone();
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        warn!("Received SIGINT/SIGTERM — initiating graceful shutdown");
        shutdown_requested_clone.store(true, Ordering::SeqCst);
        let _ = shutdown_tx_clone.send(());
    });

    // ── SMTP Listener ──────────────────────────────────────────────────────
    info!("Concurrency: max_sessions={} max_queue={} session_timeout={}s idle_timeout={}s",
          smtp_max_sessions, smtp_max_queue, smtp_session_timeout_secs, smtp_idle_timeout_secs);
    let semaphore = Arc::new(Semaphore::new(smtp_max_sessions));
    let max_queue = smtp_max_queue;
    let queue_counter = Arc::new(AtomicUsize::new(0));

    let listener = TcpListener::bind(("0.0.0.0", listen_port)).await?;
    info!("✓ SMTP Receiver running on port {}", listen_port);

    loop {
        // Check shutdown flag
        if shutdown_requested.load(Ordering::SeqCst) {
            info!("Shutting down — no longer accepting new connections");
            break;
        }

        let (socket, addr) = match tokio::time::timeout(Duration::from_secs(1), listener.accept()).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => { error!("Accept error: {}", e); continue; }
            Err(_) => continue, // timeout — check shutdown flag next iteration
        };

        let postgres_pool    = postgres_pool.clone();
        let whitelist_exact = domain_whitelist_exact.clone();
        let whitelist_tlds  = domain_whitelist_tlds.clone();
        let bans_cache      = bans_cache.clone();
        let private_cache   = private_email_cache.clone();
        let semaphore       = semaphore.clone();
        let queue_counter   = queue_counter.clone();
        let connection_counter = connection_counter.clone();
        let batch_sender    = batch_sender.clone();
        let cb_open         = cb_open_for_handler.clone();
        let session_timeout = Duration::from_secs(smtp_session_timeout_secs);
        let idle_timeout    = Duration::from_secs(smtp_idle_timeout_secs);
        let handlers         = handlers.clone();
        let shutdown_req     = shutdown_requested.clone();

        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();

            let conn_slot = (connection_counter.fetch_add(1, Ordering::Relaxed) % 50) + 1;
            let instance = Arc::new(format!("slot:{}", conn_slot));

            // Lock-free reservation: fetch_add then bail+rollback if over cap.
            let reserved = queue_counter.fetch_add(1, Ordering::AcqRel) + 1;
            if reserved > max_queue {
                queue_counter.fetch_sub(1, Ordering::AcqRel);
                warn!("Server busy, rejecting {} [Queue: full/{}] [inst: {}]",
                      addr, max_queue, instance.as_str());
                let (_, mut w) = socket.into_split();
                let _ = w.write_all(b"421 Service temporarily unavailable - try again later\r\n").await;
                return;
            }

            debug!("[SMTP IN] New connection from {} -> local [Queue: {}/{}] [inst: {}]",
                  addr, reserved, max_queue, instance.as_str());

            let result = tokio::time::timeout(
                session_timeout,
                handle_smtp(socket, SmtpHandlerContext {
                    postgres_pool:       postgres_pool.clone(),
                    whitelist_exact:     whitelist_exact.clone(),
                    whitelist_tlds:      whitelist_tlds.clone(),
                    bans_cache:          bans_cache.clone(),
                    private_email_cache: private_cache.clone(),
                    batch_sender:        batch_sender.clone(),
                    cb_open:             cb_open.clone(),
                    shutdown_requested:  shutdown_req,
                    idle_timeout,
                }, instance.clone()),
            ).await;

            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => error!("Error handling {}: {:?}", addr, e),
                Err(_) => warn!("SMTP session timeout for {} [inst: {}]", addr, instance.as_str()),
            }

            let queue_size = queue_counter.fetch_sub(1, Ordering::AcqRel).saturating_sub(1);
            debug!("[SMTP OUT] Connection closed from {} [Queue: {}/{}] [inst: {}]",
                  addr, queue_size, max_queue, instance.as_str());
        });

        // FIX #16: Register handler so shutdown can await in-flight connections
        {
            let mut h = handlers.lock().await;
            h.push(handle);
        }
    }

    // FIX #16: Await all in-flight SMTP handlers before shutdown
    info!("Waiting for {} in-flight handler(s) to finish...", handlers.lock().await.len());
    let handles: Vec<_> = handlers.lock().await.drain(..).collect();
    for h in handles {
        if let Err(e) = h.await {
            warn!("Handler panicked or errored: {:?}", e);
        }
    }

    // Give batch worker time to flush remaining emails
    info!("Waiting for batch worker to flush...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    info!("SMTP server stopped");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch Worker — restartable
// ─────────────────────────────────────────────────────────────────────────────

async fn batch_worker(
    mut batch_rx: mpsc::Receiver<EmailInsert>,
    postgres_pool: PgPool,
    mut shutdown_rx: watch::Receiver<()>,
    cb_failures: Arc<AtomicUsize>,
    cb_open: Arc<AtomicBool>,
    cb_last_failure: Arc<std::sync::Mutex<std::time::Instant>>,
) {
    let mut buffer: Vec<EmailInsert> = Vec::with_capacity(BATCH_FLUSH_SIZE);
    let mut flush_interval = tokio::time::interval(Duration::from_millis(BATCH_FLUSH_INTERVAL_MS));
    flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;

            // Check shutdown first
            _ = shutdown_rx.changed() => {
                if !buffer.is_empty() {
                    flush_batch(&postgres_pool, &mut buffer,
                                &cb_failures, &cb_open, &cb_last_failure).await;
                }
                warn!("Batch worker: shutdown signal received");
                break;
            }

            result = batch_rx.recv() => {
                match result {
                    Some(email) => {
                        buffer.push(email);
                        if buffer.len() >= BATCH_FLUSH_SIZE {
                            flush_batch(&postgres_pool, &mut buffer,
                                        &cb_failures, &cb_open, &cb_last_failure).await;
                        }
                    }
                    None => {
                        if !buffer.is_empty() {
                            flush_batch(&postgres_pool, &mut buffer,
                                        &cb_failures, &cb_open, &cb_last_failure).await;
                        }
                        warn!("Batch worker: channel closed, shutting down");
                        break;
                    }
                }
            }

            _ = flush_interval.tick() => {
                if !buffer.is_empty() {
                    flush_batch(&postgres_pool, &mut buffer,
                                &cb_failures, &cb_open, &cb_last_failure).await;
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SMTP Handler
// ─────────────────────────────────────────────────────────────────────────────

/// Shared read-only state passed to every SMTP handler.
struct SmtpHandlerContext {
    postgres_pool:      PgPool,
    whitelist_exact:    Arc<RwLock<HashSet<String>>>,
    whitelist_tlds:     Arc<RwLock<HashSet<String>>>,
    bans_cache:         Arc<RwLock<BansCache>>,
    private_email_cache: Arc<ArcSwap<HashSet<String>>>,
    batch_sender:       Arc<ArcSwap<mpsc::Sender<EmailInsert>>>,
    cb_open:            Arc<AtomicBool>,
    shutdown_requested: Arc<AtomicBool>,
    idle_timeout:       Duration,
}

async fn handle_smtp(
    socket: tokio::net::TcpStream,
    ctx: SmtpHandlerContext,
    instance: Arc<String>,
) -> anyhow::Result<()> {
    socket.set_nodelay(true)?;
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    let mut buf: Vec<u8> = Vec::with_capacity(1024);

    writer.write_all(b"220 Cybertemp Mail Receiver\r\n").await?;

    let mut mail_from  = String::new();
    let mut rcpt_to    = String::new();
    let mut data_mode  = false;
    let mut email_data: Vec<u8> = Vec::with_capacity(8192);

    loop {
        buf.clear();
        // Per-line idle timeout: if a sender stalls between commands, drop them
        // instead of holding the session slot for the full session timeout.
        let bytes = match tokio::time::timeout(
            ctx.idle_timeout,
            reader.read_until(b'\n', &mut buf),
        ).await {
            Ok(r) => r?,
            Err(_) => {
                warn!("[SMTP] Idle timeout ({}s) — closing connection [inst: {}]",
                      ctx.idle_timeout.as_secs(), instance.as_str());
                let _ = writer.write_all(b"421 Idle timeout - closing connection\r\n").await;
                break;
            }
        };
        if bytes == 0 { break; }

        // FIX #16: Check shutdown flag on every loop iteration
        if ctx.shutdown_requested.load(Ordering::Relaxed) {
            info!("[SMTP] Shutdown requested, closing connection [inst: {}]", instance.as_str());
            break;
        }

        if data_mode {
            let trimmed_len = trim_trailing_crlf_len(&buf);
            if trimmed_len == 1 && buf[0] == b'.' {
                data_mode = false;
                debug!("[SMTP IN] DATA stream completed [inst: {}]", instance.as_str());

                // FIX #1: Check email size BEFORE processing
                if email_data.len() > MAX_EMAIL_SIZE_BYTES {
                    warn!("[SMTP] Email too large ({} bytes) from {} [inst: {}]",
                          email_data.len(), rcpt_to, instance.as_str());
                    writer.write_all(b"552 Message too large\r\n").await?;
                    email_data.clear();
                    continue;
                }

                let email_bytes = std::mem::take(&mut email_data);
                let rcpt_clone  = rcpt_to.clone();
                let mail_clone  = mail_from.clone();

                // Inline processing (no spawn+oneshot) — saves a runtime hop and
                // a redundant 30s timeout on top of the existing session timeout.
                let process_ctx = ProcessContext {
                    postgres_pool:       ctx.postgres_pool.clone(),
                    whitelist_exact:     ctx.whitelist_exact.clone(),
                    whitelist_tlds:      ctx.whitelist_tlds.clone(),
                    bans_cache:          ctx.bans_cache.clone(),
                    private_email_cache: ctx.private_email_cache.clone(),
                    batch_sender:        ctx.batch_sender.clone(),
                    cb_open:             ctx.cb_open.clone(),
                    instance:            instance.clone(),
                };
                let process_result = process_email(
                    email_bytes,
                    &rcpt_clone,
                    &mail_clone,
                    &process_ctx,
                ).await;

                match process_result {
                    Ok(ProcessResult::Accepted) => {
                        writer.write_all(b"250 Ok: Message accepted\r\n").await?;
                        debug!("✓ Email accepted for processing [inst: {}]", instance.as_str());
                    }
                    Ok(ProcessResult::Rejected(reason)) => {
                        writer.write_all(format!("550 {}\r\n", reason).as_bytes()).await?;
                        warn!("[SMTP] Email rejected: {} [inst: {}]", reason, instance.as_str());
                    }
                    Err(e) => {
                        error!("Email processing error: {} [inst: {}]", e, instance.as_str());
                        writer.write_all(b"451 Requested action aborted - try again later\r\n").await?;
                    }
                }
                // FIX: Reset DATA session state after every email completes
                data_mode = false;
                email_data.clear();
                mail_from.clear();
                rcpt_to.clear();
            } else {
                // FIX #8: Streaming size check — reject oversized emails mid-transfer
                let body_slice = if buf.first() == Some(&b'.') { &buf[1..] } else { &buf[..] };
                let new_size = email_data.len().saturating_add(body_slice.len());
                if new_size > MAX_EMAIL_SIZE_BYTES {
                    warn!("[SMTP] Email too large during transfer ({} bytes) from {} [inst: {}]",
                          new_size, rcpt_to, instance.as_str());
                    writer.write_all(b"552 Message too large\r\n").await?;
                    data_mode = false;
                    email_data.clear();
                    continue;
                }
                email_data.extend_from_slice(body_slice);
            }
            continue;
        }

        let line_str = String::from_utf8_lossy(&buf);
        let cmd = line_str.trim_end();

        if cmd.starts_with("HELO") {
            let hostname = cmd.split_whitespace().nth(1).unwrap_or("unknown");
            debug!("[SMTP IN] HELO from {} [inst: {}]", hostname, instance.as_str());
            writer.write_all(b"250 Hello\r\n").await?;
        } else if cmd.starts_with("EHLO") {
            let hostname = cmd.split_whitespace().nth(1).unwrap_or("unknown");
            debug!("[SMTP IN] EHLO from {} [inst: {}]", hostname, instance.as_str());
            writer.write_all(
                b"250-Hello\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250 ENHANCEDSTATUSCODES\r\n"
            ).await?;
        } else if let Some(addr) = cmd.strip_prefix("MAIL FROM:") {
            mail_from = addr.trim().to_string();
            debug!("[SMTP IN] MAIL FROM: {} [inst: {}]", mail_from, instance.as_str());
            writer.write_all(b"250 Ok\r\n").await?;
        } else if let Some(addr) = cmd.strip_prefix("RCPT TO:") {
            rcpt_to = addr.trim().to_string();
            let email = extract_email(&rcpt_to);
            let domain = email.split('@').nth(1).unwrap_or("").to_lowercase();

            // FIX #9: O(1) domain check. Hold read guards over the sync lookup —
            // no per-email HashSet clone.
            let domain_allowed = {
                let ex = ctx.whitelist_exact.read().await;
                let tl = ctx.whitelist_tlds.read().await;
                is_domain_allowed_fast(&domain, &ex, &tl)
            };

            if !domain_allowed {
                warn!("[Domains] Rejected RCPT TO: {} (domain not allowed) [inst: {}]",
                      email, instance.as_str());
                writer.write_all(b"550 Domain not allowed\r\n").await?;
            } else if is_domain_banned(&domain, &ctx.bans_cache).await {
                warn!("[Bans] Rejected RCPT TO: {} (domain banned) [inst: {}]", email, instance.as_str());
                writer.write_all(b"550 Domain banned\r\n").await?;
            } else {
                debug!("[SMTP IN] RCPT TO: {} [inst: {}]", email, instance.as_str());
                writer.write_all(b"250 Ok\r\n").await?;
            }
        } else if cmd == "DATA" {
            data_mode = true;
            debug!("[SMTP IN] DATA command received [inst: {}]", instance.as_str());
            writer.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n").await?;
        } else if cmd == "QUIT" {
            debug!("[SMTP IN] QUIT command received [inst: {}]", instance.as_str());
            writer.write_all(b"221 Bye\r\n").await?;
            break;
        } else if cmd == "RSET" {
            mail_from.clear();
            rcpt_to.clear();
            email_data.clear();
            data_mode = false;
            writer.write_all(b"250 Ok\r\n").await?;
        } else if cmd == "NOOP" {
            writer.write_all(b"250 Ok\r\n").await?;
        } else {
            warn!("[SMTP IN] Unknown command: {} [inst: {}]", cmd, instance.as_str());
            writer.write_all(b"502 Command not implemented\r\n").await?;
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Email Processing
// ─────────────────────────────────────────────────────────────────────────────

async fn process_email(
    data: Vec<u8>,
    rcpt_to: &str,
    mail_from: &str,
    ctx: &ProcessContext,
) -> anyhow::Result<ProcessResult> {
    // FIX #9: Circuit breaker — reject fast without consuming channel buffer
    if ctx.cb_open.load(Ordering::Relaxed) {
        return Ok(ProcessResult::Rejected(
            "Service temporarily unavailable - please try again later".to_string()
        ));
    }

    let raw_size = data.len() as i64;

    if raw_size > MAX_EMAIL_SIZE_BYTES as i64 {
        return Ok(ProcessResult::Rejected("Message too large".to_string()));
    }

    debug!("📧 Processing email — Raw size: {} bytes [inst: {}]", data.len(), ctx.instance.as_str());

    let recipient_email = extract_email(rcpt_to).to_lowercase();
    let from_address    = extract_email(mail_from).to_lowercase();

    let domain = recipient_email.split('@').nth(1).unwrap_or("").to_lowercase();

    // Domain allowed check — hold read guards over the synchronous lookup
    // instead of cloning the entire HashSet on every email.
    {
        let ex = ctx.whitelist_exact.read().await;
        let tl = ctx.whitelist_tlds.read().await;
        if !is_domain_allowed_fast(&domain, &ex, &tl) {
            return Ok(ProcessResult::Rejected("Domain not allowed".to_string()));
        }
    }

    // Bans check
    if is_domain_banned(&domain, &ctx.bans_cache).await {
        return Ok(ProcessResult::Rejected("Domain banned".to_string()));
    }

    if is_email_banned(&from_address, &ctx.bans_cache).await {
        return Ok(ProcessResult::Rejected("Sender banned".to_string()));
    }

    // Parse email once — extract subject, text body, html body
    let (subject, text_body, html_body) = match parse_mail(&data) {
        Ok(parsed) => {
            let subject = parsed.get_headers()
                .get_first_value("Subject")
                .unwrap_or_else(|| "No Subject".to_string());

            let mut text_body = String::new();
            let mut html_body = String::new();

            fn walk_parts(part: &mailparse::ParsedMail, text: &mut String, html: &mut String) {
                if let Some(ct) = part.get_headers().get_first_value("Content-Type") {
                    let ct_l = ct.to_lowercase();
                    if ct_l.starts_with("text/html") {
                        if html.is_empty() {
                            if let Ok(b) = part.get_body() { *html = b; }
                        }
                        return;
                    } else if ct_l.starts_with("text/plain") {
                        if text.is_empty() {
                            if let Ok(b) = part.get_body() { *text = b; }
                        }
                        return;
                    } else if ct_l.starts_with("multipart/") {
                        for sub in &part.subparts {
                            walk_parts(sub, text, html);
                        }
                        return;
                    }
                    // FIX #17: Skip non-text leaf parts to avoid storing binary data as text_body
                    return;
                }
                if !part.subparts.is_empty() {
                    for sub in &part.subparts {
                        walk_parts(sub, text, html);
                    }
                }
                // No Content-Type header and no subparts: treat as plain text if valid UTF-8
                // and not binary (null bytes indicate binary content).
                if text.is_empty() {
                    if let Ok(b) = part.get_body() {
                        if !b.contains('\0') {
                            *text = b;
                        }
                    }
                }
            }

            if parsed.subparts.is_empty() {
                // Single-part message
                if let Ok(b) = parsed.get_body() {
                    if let Some(ct) = parsed.get_headers().get_first_value("Content-Type") {
                        if ct.to_lowercase().contains("text/html") {
                            html_body = b;
                        } else {
                            text_body = b;
                        }
                    } else {
                        text_body = b;
                    }
                }
            } else {
                for sub in &parsed.subparts {
                    walk_parts(sub, &mut text_body, &mut html_body);
                }
            }

            if text_body.trim().is_empty() && html_body.trim().is_empty() {
                let raw_lossy = String::from_utf8_lossy(&data);
                text_body = strip_email_headers(&raw_lossy);
            }

            (subject, text_body, html_body)
        }
        Err(e) => {
            warn!("mailparse failed: {} [inst: {}]", e, ctx.instance.as_str());
            let raw_lossy = String::from_utf8_lossy(&data).into_owned();
            let subject = extract_subject_from_raw(&raw_lossy)
                .unwrap_or_else(|| "No Subject".to_string());
            (subject, raw_lossy, String::new())
        }
    };

    // Sanitize
    let subject     = sanitize_for_postgres(&subject);
    let text_body   = sanitize_for_postgres(&text_body);
    let html_body   = sanitize_for_postgres(&html_body);
    let from_address = sanitize_for_postgres(&from_address);

    info!("✉ Parsed email for {} from {} — Subject: '{}' [inst: {}]",
          recipient_email, from_address, subject, ctx.instance.as_str());

    // Private email path — O(1) in-memory cache lookup instead of a per-message
    // SELECT. Cache is refreshed by poll_private_emails. New private addresses
    // may take up to PRIVATE_EMAIL_POLL_INTERVAL_SECS to propagate.
    let is_private = ctx.private_email_cache.load().contains(&recipient_email);
    if is_private {
        let to_addrs_vec = vec![recipient_email.clone()];
        let email_insert = EmailInsert {
            mailbox_owner: recipient_email.clone(),
            mailbox: "INBOX".to_string(),
            subject: subject.clone(),
            body: text_body.clone(),
            html: html_body.clone(),
            from_addr: from_address.clone(),
            to_addrs: to_addrs_vec,
            size: raw_size,
        };

        match send_with_retry(&ctx.batch_sender, email_insert).await {
            Ok(_) => {
                info!("✓ Queued email for private user: {} -> {} [inst: {}]",
                      from_address, recipient_email, ctx.instance.as_str());
                // Background update — fire and forget
                let pool = ctx.postgres_pool.clone();
                let email = recipient_email.clone();
                tokio::spawn(async move {
                    let _ = sqlx::query(
                        "UPDATE private_email SET last_updated_at = NOW() WHERE email = $1"
                    )
                    .bind(&email)
                    .execute(&pool)
                    .await;
                });
            }
            Err(e) => {
                error!("Failed to queue private email after retries: {} [inst: {}]", e, ctx.instance.as_str());
                return Err(anyhow::anyhow!("Failed to queue private email: {}", e));
            }
        }
        return Ok(ProcessResult::Accepted);
    }

    // Temp email path
    let to_addrs_vec = vec![recipient_email.clone()];
    let email_insert = EmailInsert {
        mailbox_owner: recipient_email.clone(),
        mailbox: "INBOX".to_string(),
        subject,
        body: text_body,
        html: html_body,
        from_addr: from_address,
        to_addrs: to_addrs_vec,
        size: raw_size,
    };

    match send_with_retry(&ctx.batch_sender, email_insert).await {
        Ok(_) => {
            info!("✓ Queued email for batch insert [inst: {}]", ctx.instance.as_str());
            Ok(ProcessResult::Accepted)
        }
        Err(e) => {
            error!("Failed to queue email after retries: {} [inst: {}]", e, ctx.instance.as_str());
            Err(anyhow::anyhow!("Failed to queue email: {}", e))
        }
    }
}

/// FIX #2: Retry send with exponential backoff (3 attempts, max 500ms delay).
/// Lock-free: ArcSwap::load() returns a guard with no contention. Each retry
/// re-loads, so a worker restart that swaps in a fresh sender is picked up
/// transparently.
async fn send_with_retry(
    sender: &Arc<ArcSwap<mpsc::Sender<EmailInsert>>>,
    email: EmailInsert,
) -> anyhow::Result<()> {
    let mut delay_ms: u64 = 10;
    for attempt in 1..=4 {
        let s = sender.load();
        match s.try_send(email.clone()) {
            Ok(()) => return Ok(()),
            Err(_e) if attempt <= 3 => {
                drop(s);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                delay_ms = delay_ms.saturating_mul(2).min(500);
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Channel send failed after 4 attempts: {}", e));
            }
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain & Bans Helpers (O(1) primary lookups)
// ─────────────────────────────────────────────────────────────────────────────

/// FIX #9: O(1) domain check using separate exact + TLD sets.
fn is_domain_allowed_fast(
    domain: &str,
    whitelist_exact: &HashSet<String>,
    whitelist_tlds:  &HashSet<String>,
) -> bool {
    if whitelist_exact.is_empty() && whitelist_tlds.is_empty() {
        return true; // no restrictions
    }

    let domain_lower = domain.to_lowercase();

    // O(1) exact match
    if whitelist_exact.contains(&domain_lower) {
        return true;
    }

    // O(1) TLD wildcard match — extract TLD from domain, e.g. "spam.ru" → "ru"
    if let Some(dot_pos) = domain_lower.find('.') {
        let tld = &domain_lower[dot_pos + 1..];
        if !tld.is_empty() && whitelist_tlds.contains(tld) {
            return true;
        }
    }

    false
}

async fn load_domain_whitelist(
    pool: &PgPool,
    whitelist_exact: Arc<RwLock<HashSet<String>>>,
    whitelist_tlds:  Arc<RwLock<HashSet<String>>>,
) -> anyhow::Result<()> {
    match sqlx::query_as::<_, Domain>("SELECT domain FROM domains;")
        .fetch_all(pool)
        .await
    {
        Ok(res) => {
            let mut exact = HashSet::new();
            let mut tlds  = HashSet::new();

            for domain in res {
                let d = domain.domain.to_lowercase();
                if let Some(stripped) = d.strip_prefix("*.") {
                    // It's a wildcard — strip prefix and add as TLD
                    tlds.insert(stripped.to_string());
                } else {
                    exact.insert(d.clone());
                    // Also add the TLD for convenience
                    if let Some(dot_pos) = d.find('.') {
                        let tld = &d[dot_pos + 1..];
                        if !tld.is_empty() {
                            tlds.insert(tld.to_string());
                        }
                    }
                }
            }

            {
                let mut ex_guard = whitelist_exact.write().await;
                *ex_guard = exact;
            }
            {
                let mut tl_guard = whitelist_tlds.write().await;
                *tl_guard = tlds;
            }

            let (ex_count, tl_count) = {
                let ex = whitelist_exact.read().await;
                let tl = whitelist_tlds.read().await;
                (ex.len(), tl.len())
            };
            info!("✅ Loaded {} whitelisted domains ({} exact, {} TLDs) from PostgreSQL",
                  ex_count + tl_count, ex_count, tl_count);
            if ex_count == 0 && tl_count == 0 {
                warn!("⚠ No domains configured — all emails will be accepted");
            }
            Ok(())
        }
        Err(e) => {
            warn!("⚠ Failed to load domains from PostgreSQL: {}", e);
            warn!("📧 SMTP server will accept all domains until connection is restored");
            Err(anyhow::anyhow!("Database connection error: {}", e))
        }
    }
}

async fn poll_domain_updates(
    pool: PgPool,
    whitelist_exact: Arc<RwLock<HashSet<String>>>,
    whitelist_tlds:  Arc<RwLock<HashSet<String>>>,
) {
    let mut poll_interval = tokio::time::interval(Duration::from_secs(DOMAIN_POLL_INTERVAL_SECS));
    // Add jitter to prevent thundering herd on restart
    tokio::time::sleep(Duration::from_millis(rand_u64(30_000))).await;

    loop {
        poll_interval.tick().await;
        info!("🔄 Polling PostgreSQL for domain updates...");
        if let Err(e) = load_domain_whitelist(&pool, whitelist_exact.clone(), whitelist_tlds.clone()).await {
            warn!("⚠ Domain poll failed: {}", e);
        }
    }
}

async fn load_bans(pool: &PgPool, bans_cache: Arc<RwLock<BansCache>>) -> Result<(), String> {
    let rows = sqlx::query_as::<_, Ban>(
        "SELECT scope, value, match_type FROM bans WHERE status = 'active'"
    ).fetch_all(pool).await
     .map_err(|e| format!("bans query failed: {}", e))?;

    let mut cache = BansCache::default();
    for b in rows {
        let scope  = b.scope.to_lowercase();
        let val    = b.value.trim().to_lowercase();
        let mtype  = b.match_type.to_lowercase();

        match scope.as_str() {
            "email" => {
                if mtype == "contains" {
                    if let Some(stripped) = val.strip_prefix("contains:") {
                        cache.email_contains.push(stripped.to_string());
                    } else {
                        cache.email_contains.push(val);
                    }
                } else {
                    cache.email_exact.insert(val);
                }
            }
            "domain" => {
                if val.starts_with("*.") {
                    // TLD wildcard ban (e.g. "*.ru" from nachthub bans table)
                    if let Some(stripped) = val.strip_prefix("*.") {
                        cache.domain_tlds.insert(stripped.to_string());
                    }
                } else {
                    cache.domain.insert(val);
                }
            }
            other => {
                // FIX #19: Log unknown ban scopes so operators notice schema mismatches
                warn!("⚠ Unknown ban scope '{}' — expected 'email' or 'domain'; ignoring", other);
            }
        }
    }

    let mut guard = bans_cache.write().await;
    *guard = cache;
    let c = &*guard;
    info!("✅ Loaded bans (email_exact={}, email_contains={}, domains={}, domain_tlds={})",
          c.email_exact.len(), c.email_contains.len(), c.domain.len(), c.domain_tlds.len());
    Ok(())
}

/// Load all private_email addresses into the in-memory cache.
async fn load_private_emails(
    pool: &PgPool,
    cache: Arc<ArcSwap<HashSet<String>>>,
) -> anyhow::Result<()> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT email FROM private_email")
        .fetch_all(pool)
        .await
        .map_err(|e| anyhow::anyhow!("private_email query failed: {}", e))?;

    let mut set = HashSet::with_capacity(rows.len());
    for (email,) in rows {
        set.insert(email.trim().to_lowercase());
    }
    let n = set.len();
    cache.store(Arc::new(set));
    info!("✅ Loaded {} private_email addresses into cache", n);
    Ok(())
}

async fn poll_private_emails(pool: PgPool, cache: Arc<ArcSwap<HashSet<String>>>) {
    let mut poll_interval = tokio::time::interval(
        Duration::from_secs(PRIVATE_EMAIL_POLL_INTERVAL_SECS)
    );
    // Jitter to avoid thundering herd on restart
    tokio::time::sleep(Duration::from_millis(rand_u64(15_000))).await;

    loop {
        poll_interval.tick().await;
        if let Err(e) = load_private_emails(&pool, cache.clone()).await {
            warn!("⚠ private_email poll failed: {} — keeping last known cache", e);
        }
    }
}

async fn poll_bans(pool: PgPool, bans_cache: Arc<RwLock<BansCache>>) {
    let mut poll_interval = tokio::time::interval(Duration::from_secs(BANS_POLL_INTERVAL_SECS));
    // FIX #15: Add jitter to prevent thundering herd
    tokio::time::sleep(Duration::from_millis(rand_u64(30_000))).await;

    // Initial load — warn but continue with empty cache if bans table missing
    if let Err(e) = load_bans(&pool, bans_cache.clone()).await {
        warn!("⚠ Initial ban load failed: {} — bans will be retried on next poll", e);
    }

    loop {
        poll_interval.tick().await;
        info!("🔄 Polling PostgreSQL for bans updates...");
        if let Err(e) = load_bans(&pool, bans_cache.clone()).await {
            warn!("⚠ Ban poll failed: {} — keeping last known ban state", e);
        }
    }
}

async fn is_domain_banned(domain: &str, bans_cache: &Arc<RwLock<BansCache>>) -> bool {
    let guard = bans_cache.read().await;
    let lower = domain.to_lowercase();
    if guard.domain.contains(&lower) {
        return true;
    }
    // TLD wildcard check: "*.ru" matches "anything.ru"
    if let Some(dot_pos) = lower.find('.') {
        let tld = &lower[dot_pos + 1..];
        if guard.domain_tlds.contains(tld) {
            return true;
        }
    }
    false
}

async fn is_email_banned(from_lower: &str, bans_cache: &Arc<RwLock<BansCache>>) -> bool {
    let guard = bans_cache.read().await;
    if guard.email_exact.contains(from_lower) {
        return true;
    }
    for sub in &guard.email_contains {
        if from_lower.contains(sub) {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch Flush with Timeout & Retry-on-failure
// ─────────────────────────────────────────────────────────────────────────────

/// FIX #6: Flush with hard timeout so a hung DB never blocks the worker forever.
/// FIX #3: Don't clear buffer on failure — keep emails for next flush attempt.
/// FIX #9: Returns Result so the caller (batch worker) can update circuit breaker.
async fn flush_batch(
    pool: &PgPool,
    buffer: &mut Vec<EmailInsert>,
    cb_failures: &Arc<AtomicUsize>,
    cb_open: &Arc<AtomicBool>,
    cb_last_failure: &Arc<std::sync::Mutex<std::time::Instant>>,
) {
    if buffer.is_empty() { return; }

    let batch_len = buffer.len();
    info!("🔄 Flushing batch of {} emails to database", batch_len);

    // FIX #6: Wrap entire flush in a 30-second timeout
    let result = timeout(
        Duration::from_secs(BATCH_FLUSH_TIMEOUT_SECS),
        flush_batch_inner(pool, buffer),
    ).await;

    match result {
        Ok(Ok(())) => {
            buffer.clear();
            // Circuit breaker: reset on success
            cb_failures.store(0, Ordering::Relaxed);
            cb_open.store(false, Ordering::Relaxed);
        }
        Ok(Err(e)) => {
            error!("✗ Batch insert failed: {} — {} emails KEPT for retry", e, batch_len);
            // Record failure for circuit breaker (buffer NOT cleared — retry next tick)
            record_failure(cb_failures, cb_open, cb_last_failure);
        }
        Err(_) => {
            error!("⏱ Batch flush timed out after {}s — {} emails KEPT for retry",
                   BATCH_FLUSH_TIMEOUT_SECS, batch_len);
            // Record failure for circuit breaker (buffer NOT cleared — retry next tick)
            record_failure(cb_failures, cb_open, cb_last_failure);
        }
    }
}

/// Record one consecutive flush failure. Trips the circuit breaker at threshold.
fn record_failure(
    cb_failures: &Arc<AtomicUsize>,
    cb_open: &Arc<AtomicBool>,
    cb_last_failure: &Arc<std::sync::Mutex<std::time::Instant>>,
) {
    let prev = cb_failures.fetch_add(1, Ordering::Relaxed);
    if prev + 1 >= CB_FAILURE_THRESHOLD {
        cb_open.store(true, Ordering::Relaxed);
        error!("⚡ Circuit breaker TRIPPED after {} consecutive flush failures", prev + 1);
    }
    *cb_last_failure.lock().unwrap() = std::time::Instant::now();
}

/// Background task: auto-resets circuit breaker after CB_RECOVERY_SECS of no failures.
async fn circuit_breaker_recovery_task(
    cb_failures: Arc<AtomicUsize>,
    cb_open: Arc<AtomicBool>,
    cb_last_failure: Arc<std::sync::Mutex<std::time::Instant>>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    loop {
        interval.tick().await;
        if cb_open.load(Ordering::Relaxed) {
            let elapsed = {
                let guard = cb_last_failure.lock().unwrap();
                guard.elapsed().as_secs()
            };
            if elapsed >= CB_RECOVERY_SECS {
                info!("⚡ Circuit breaker auto-resetting after {}s recovery period", elapsed);
                cb_failures.store(0, Ordering::Relaxed);
                cb_open.store(false, Ordering::Relaxed);
            }
        }
    }
}

async fn flush_batch_inner(pool: &PgPool, buffer: &mut [EmailInsert]) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;

    // Unique inbox owners
    let mut unique_owners: HashSet<&String> = HashSet::new();
    for email in buffer.iter() {
        unique_owners.insert(&email.mailbox_owner);
    }

    if !unique_owners.is_empty() {
        let mut inbox_query = sqlx::QueryBuilder::new(
            "INSERT INTO inbox (email_address) "
        );
        inbox_query.push_values(unique_owners.iter(), |mut b, owner| {
            b.push_bind(owner);
        });
        inbox_query.push(" ON CONFLICT (email_address) DO NOTHING");
        // FIX #18: Propagate inbox INSERT errors — do not silently swallow failures.
        inbox_query.build().execute(&mut *tx).await?;
    }

    let mut query = sqlx::QueryBuilder::new(
        "INSERT INTO emails (mailbox_owner, mailbox, subject, body, html, from_addr, to_addrs, size, created_at) "
    );
    query.push_values(buffer.iter(), |mut b, email| {
        b.push_bind(&email.mailbox_owner)
            .push_bind(&email.mailbox)
            .push_bind(&email.subject)
            .push_bind(&email.body)
            .push_bind(&email.html)
            .push_bind(&email.from_addr)
            .push_bind(&email.to_addrs)
            .push_bind(email.size)
            .push("NOW()");
    });

    query.build().execute(&mut *tx).await?;
    tx.commit().await?;
    info!("✓ Batch committed: {} emails saved", buffer.len());
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Heartbeat
// ─────────────────────────────────────────────────────────────────────────────

async fn heartbeat_loop(hb_url: String) {
    let mut interval = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
    loop {
        interval.tick().await;
        // FIX #12: Use top-level reqwest::get() — Client::get(url) does not exist
        match reqwest::get(&hb_url).await {
            Ok(response) => {
                if response.status().is_success() {
                    info!("✓ Heartbeat sent successfully");
                } else {
                    warn!("⚠ Heartbeat failed: {}", response.status());
                }
            }
            Err(e) => {
                error!("✗ Heartbeat error: {}", e);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility Functions
// ─────────────────────────────────────────────────────────────────────────────

fn trim_trailing_crlf_len(buf: &[u8]) -> usize {
    let mut end = buf.len();
    while end > 0 && (buf[end - 1] == b'\n' || buf[end - 1] == b'\r') {
        end -= 1;
    }
    end
}

fn extract_email(addr: &str) -> String {
    if addr.starts_with('<') && addr.ends_with('>') {
        addr[1..addr.len()-1].to_string()
    } else {
        addr.to_string()
    }
}

fn sanitize_for_postgres(s: &str) -> String {
    s.replace('\0', "")
}

fn extract_subject_from_raw(raw_email: &str) -> Option<String> {
    for line in raw_email.lines() {
        if line.to_lowercase().starts_with("subject:") {
            return Some(line[8..].trim().to_string());
        }
    }
    None
}

fn strip_email_headers(raw_email: &str) -> String {
    let mut in_headers = true;
    let mut result = String::new();

    for line in raw_email.lines() {
        if in_headers {
            if line.trim().is_empty() {
                in_headers = false;
            }
        } else {
            if result.is_empty() {
                result.push_str(line);
            } else {
                result.push_str("\r\n");
                result.push_str(line);
            }
        }
    }

    if in_headers && result.is_empty() {
        if let Some(body_start) = raw_email.find("\r\n\r\n") {
            let body = &raw_email[body_start + 4..];
            if body.len() > 2000 {
                body.chars().take(2000).collect()
            } else {
                body.to_string()
            }
        } else {
            raw_email.chars().take(1000).collect()
        }
    } else {
        result
    }
}

/// Returns a random u64 in [0, max_millis) for jitter.
fn rand_u64(max_millis: u64) -> u64 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    rng.gen_range(0..max_millis)
}

// ─────────────────────────────────────────────────────────────────────────────
// once_cell re-export (add to Cargo.toml)
// ─────────────────────────────────────────────────────────────────────────────
// Note: Add `once_cell = "1.19"` to [dependencies] in Cargo.toml
