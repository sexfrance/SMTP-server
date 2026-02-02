use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::{Semaphore, Mutex, RwLock, mpsc},
    time::Duration,
};
use std::{collections::{HashSet}, env, sync::{Arc, atomic::{AtomicUsize, Ordering}}};
use mailparse::{parse_mail, MailHeaderMap};
use sqlx::postgres::{PgPool, PgPoolOptions};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};
use tracing_subscriber;

// Ban structure returned by Supabase
#[derive(Debug, Deserialize, Serialize)]
struct Ban {
    scope: String,
    value: String,
    // Optional: match_type column in DB: 'exact' or 'contains'
    match_type: Option<String>,
}

// In-memory ban cache
#[derive(Debug, Default)]
struct BansCache {
    // global exact sender addresses
    email_exact: HashSet<String>,
    // global substrings to check
    email_contains: Vec<String>,
    // global blocked recipient domains
    domain: HashSet<String>,
}

// PostgreSQL inbox structure (no longer using Supabase)
#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize, sqlx::FromRow, Clone)]
struct Inbox {
    id: String,
    email_address: String,
    user_id: Option<String>,
}

// Email batch insert structure
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

// Supabase domain structure
#[derive(Debug, Deserialize)]
struct Domain {
    domain: String,
}

// Domain response for polling API
#[derive(Deserialize)]
struct DomainResponse {
    domain: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    // Connection slot counter for tracking which of the 50 slots is handling each connection
    let connection_counter = Arc::new(AtomicUsize::new(0));

    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .compact()
        .init();
    info!("=== SMTP Service (Receive Only) ===");

    // Environment variables
    let database_url = env::var("DATABASE_URL")?;
    
    let supabase_url = env::var("SUPABASE_URL")?;
    let supabase_key = env::var("SUPABASE_SERVICE_ROLE_KEY")
        .or_else(|_| env::var("SUPABASE_KEY"))?;
    let heartbeat_url = env::var("HEARTBEAT_URL").ok();
    let use_supabase_bans: bool = env::var("USE_SUPABASE_BANS")
        .unwrap_or_else(|_| "true".to_string())
        .parse()
        .unwrap_or(true);
    let use_supabase_domains: bool = env::var("USE_SUPABASE_DOMAINS")
        .unwrap_or_else(|_| "true".to_string())
        .parse()
        .unwrap_or(true);
    let listen_port: u16 = env::var("SMTP_RECEIVE_PORT").unwrap_or("25".into()).parse()?;

    // Create PostgreSQL connection pool for temporary emails
    let postgres_pool = PgPoolOptions::new()
        .max_connections(50)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&database_url)
        .await?;
    info!("✓ Connected to PostgreSQL database");

    // SurrealDB removed - using PostgreSQL for private emails

    // Domain whitelist
    let domain_whitelist: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    // No per-receiver scoping: this instance ignores receiver-specific bans

    // Bans cache (email exact, contains, domain)
    let bans_cache: Arc<RwLock<BansCache>> = Arc::new(RwLock::new(BansCache::default()));
    
    // Create batch insert channel for database efficiency
    let (batch_tx, mut batch_rx) = mpsc::channel::<EmailInsert>(500);
    
    // Spawn batch insert worker
    let postgres_pool_batch = postgres_pool.clone();
    tokio::spawn(async move {
        let mut buffer = Vec::with_capacity(50);
        let mut flush_interval = tokio::time::interval(Duration::from_millis(500));
        
        loop {
            tokio::select! {
                Some(email) = batch_rx.recv() => {
                    buffer.push(email);
                    
                    // Flush if buffer is full
                    if buffer.len() >= 50 {
                        flush_batch(&postgres_pool_batch, &mut buffer).await;
                    }
                }
                _ = flush_interval.tick() => {
                    // Flush periodically
                    if !buffer.is_empty() {
                        flush_batch(&postgres_pool_batch, &mut buffer).await;
                    }
                }
            }
        }
    });
    
    let batch_sender = Arc::new(batch_tx);
    
    // Initialize domain whitelist from Supabase (if enabled)
    if use_supabase_domains {
        if let Err(e) = load_domain_whitelist(&supabase_url, &supabase_key, domain_whitelist.clone()).await {
            warn!("✗ Failed to load domain whitelist: {}", e);
        }
    } else {
        info!("✓ Supabase domains disabled - accepting all domains");
    }

    // Initialize bans from Supabase (if enabled)
    if use_supabase_bans {
        // Perform an initial synchronous load of bans (same pattern as domains)
        // so bans are populated before the listener starts, mirroring domain behavior.
        load_bans(&supabase_url, &supabase_key, bans_cache.clone()).await;
    } else {
        info!("✓ Supabase bans disabled - no external bans loaded");
    }

    // Start domain updates polling (if enabled)
    if use_supabase_domains {
        let whitelist_clone = domain_whitelist.clone();
        let supabase_url_clone = supabase_url.clone();
        let supabase_key_clone = supabase_key.clone();
        tokio::spawn(async move {
            poll_domain_updates(supabase_url_clone, supabase_key_clone, whitelist_clone).await;
        });
    }

    // Start bans polling (if enabled)
    if use_supabase_bans {
        let bans_cache_clone = bans_cache.clone();
        let supabase_url_clone2 = supabase_url.clone();
        let supabase_key_clone2 = supabase_key.clone();
        tokio::spawn(async move {
            poll_bans(supabase_url_clone2, supabase_key_clone2, bans_cache_clone).await;
        });
    }

    // Start heartbeat task (if enabled)
    if let Some(hb_url) = heartbeat_url.clone() {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                match Client::new().get(&hb_url).send().await {
                    Ok(response) => {
                        if response.status().is_success() {
                            info!("✓ Heartbeat sent successfully");
                        } else {
                            warn!("⚠ Heartbeat failed: {}", response.status());
                        }
                    },
                    Err(e) => {
                        error!("✗ Heartbeat error: {}", e);
                    }
                }
            }
        });
    }

    // Concurrency control
    let semaphore = Arc::new(Semaphore::new(50));
    let max_queue = 2000;
    let queue_counter = Arc::new(Mutex::new(0usize));

    // Start TCP listener for SMTP
    let listener = TcpListener::bind(("0.0.0.0", listen_port)).await?;
    info!("✓ SMTP Receiver running on port {}", listen_port);

    loop {
        let (socket, addr) = listener.accept().await?;

        let postgres_pool = postgres_pool.clone();
        let whitelist = domain_whitelist.clone();
        let bans_cache = bans_cache.clone();
        let semaphore = semaphore.clone();
        let queue_counter = queue_counter.clone();
        let connection_counter = connection_counter.clone();
        let batch_sender = batch_sender.clone();

        tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            
            // Assign connection slot (1-50)
            let conn_slot = (connection_counter.fetch_add(1, Ordering::Relaxed) % 50) + 1;
            let instance = Arc::new(format!("slot:{}", conn_slot));
            
            let queue_size = {
                let mut q = queue_counter.lock().await;
                if *q >= max_queue {
                    warn!("Server busy, rejecting connection {} [Queue: {}/{}] [inst: {}]", addr, *q, max_queue, instance.as_str());
                    return;
                }
                *q += 1;
                *q
            };

            info!("[SMTP IN] New connection from {} -> local [Queue: {}/{}] [inst: {}]", addr, queue_size, max_queue, instance.as_str());
            if let Err(e) = handle_smtp(socket, postgres_pool, whitelist, bans_cache, batch_sender, instance.clone()).await {
                error!("Error handling {}: {:?}", addr, e);
            }

            let queue_size = {
                let mut q = queue_counter.lock().await;
                *q -= 1;
                *q
            };
            info!("[SMTP OUT] Connection closed from {} [Queue: {}/{}] [inst: {}]", addr, queue_size, max_queue, instance.as_str());
        });
    }
}

// SMTP handler
async fn handle_smtp(
    socket: tokio::net::TcpStream,
    postgres_pool: PgPool,
    whitelist: Arc<Mutex<HashSet<String>>>,
    bans_cache: Arc<RwLock<BansCache>>,
    batch_sender: Arc<mpsc::Sender<EmailInsert>>,
    instance: Arc<String>,
) -> anyhow::Result<()> {
    // Set timeouts to prevent hanging connections (30 seconds idle timeout)
    socket.set_nodelay(true)?;
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    writer.write_all(b"220 Cybertemp Mail Receiver\r\n").await?;

    let mut mail_from = String::new();
    let mut rcpt_to = String::new();
    let mut data_mode = false;
    let mut email_data = Vec::new();

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).await?;
        if bytes == 0 { break; }
        let cmd = line.trim_end();

        if data_mode {
            if cmd == "." {
                data_mode = false;
                info!("[SMTP IN] DATA stream completed [inst: {}]", instance.as_str());
                match process_email(&email_data, &rcpt_to, &mail_from, &postgres_pool, &whitelist, &bans_cache, &batch_sender, instance.clone()).await {
                    Ok(_) => {
                        writer.write_all(b"250 Ok: Message accepted\r\n").await?;
                        info!("✓ Email processed successfully [inst: {}]", instance.as_str());
                    },
                    Err(e) => {
                        error!("Failed to process email: {}", e);
                        writer.write_all(b"451 Temporary failure in email processing\r\n").await?;
                    }
                }
                email_data.clear();
            } else {
                email_data.push(cmd.to_string());
            }
            continue;
        }

        if cmd.starts_with("HELO") || cmd.starts_with("EHLO") {
            let hostname = cmd.split_whitespace().nth(1).unwrap_or("unknown");
            info!("[SMTP IN] {} from {} [inst: {}]", cmd.split_whitespace().next().unwrap_or("HELO"), hostname, instance.as_str());
            writer.write_all(b"250 Hello\r\n").await?;
        } else if cmd.starts_with("MAIL FROM:") {
            mail_from = cmd[10..].trim().to_string();
            info!("[SMTP IN] MAIL FROM: {} [inst: {}]", mail_from, instance.as_str());
            writer.write_all(b"250 Ok\r\n").await?;
        } else if cmd.starts_with("RCPT TO:") {
            rcpt_to = cmd[8..].trim().to_string();
            let email = extract_email(&rcpt_to);
            let domain = email.split('@').nth(1).unwrap_or("").to_lowercase();
            
            let whitelist_guard = whitelist.lock().await;
            let domain_allowed = if whitelist_guard.is_empty() {
                warn!("[Domains] No domains loaded - allowing all domains");
                true
            } else {
                is_domain_allowed(&domain, &whitelist_guard)
            };
            drop(whitelist_guard);
            
            if !domain_allowed {
                warn!("[Domains] Rejected RCPT TO: {} (domain not allowed)", email);
                writer.write_all(b"550 Domain not allowed\r\n").await?;
            } else {
                // Check domain bans from in-memory cache
                    // domain bans: check global bans
                    if is_domain_banned(&domain, &bans_cache).await {
                        warn!("[Bans] Rejected RCPT TO: {} (domain banned) [inst: {}]", email, instance.as_str());
                        writer.write_all(b"550 Domain banned\r\n").await?;
                    } else {
                        info!("[SMTP IN] RCPT TO: {} [inst: {}]", email, instance.as_str());
                        writer.write_all(b"250 Ok\r\n").await?;
                    }
            }
        } else if cmd == "DATA" {
            data_mode = true;
            info!("[SMTP IN] DATA command received [inst: {}]", instance.as_str());
            writer.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n").await?;
        } else if cmd == "QUIT" {
            info!("[SMTP IN] QUIT command received [inst: {}]", instance.as_str());
            writer.write_all(b"221 Bye\r\n").await?;
            break;
        } else if cmd == "RSET" {
            info!("[SMTP IN] RSET command received [inst: {}]", instance.as_str());
            mail_from.clear();
            rcpt_to.clear();
            email_data.clear();
            data_mode = false;
            writer.write_all(b"250 Ok\r\n").await?;
        } else if cmd == "NOOP" {
            info!("[SMTP IN] NOOP command received [inst: {}]", instance.as_str());
            writer.write_all(b"250 Ok\r\n").await?;
        } else {
            warn!("[SMTP IN] Unknown command: {} [inst: {}]", cmd, instance.as_str());
            writer.write_all(b"502 Command not implemented\r\n").await?;
        }
    }

    Ok(())
}

fn extract_email(addr: &str) -> String {
    if addr.starts_with('<') && addr.ends_with('>') {
        addr[1..addr.len()-1].to_string()
    } else {
        addr.to_string()
    }
}

// Process email content - FIXED VERSION
async fn process_email(
    data: &Vec<String>,
    rcpt_to: &str,
    mail_from: &str,
    postgres_pool: &PgPool,
    whitelist: &Arc<Mutex<HashSet<String>>>,
    bans_cache: &Arc<RwLock<BansCache>>,
    batch_sender: &Arc<mpsc::Sender<EmailInsert>>,
    instance: Arc<String>,
) -> anyhow::Result<()> {
    // Join all email data lines with CRLF (SMTP standard)
    let raw_email = data.join("\r\n");
    
    info!("📧 Processing email - Raw size: {} bytes [inst: {}]", raw_email.len(), instance.as_str());

    let recipient_email = extract_email(rcpt_to).to_lowercase();
    let from_address = extract_email(mail_from).to_lowercase();

    let domain = recipient_email.split('@').nth(1).unwrap_or("").to_lowercase();
    let whitelist_guard = whitelist.lock().await;
    let domain_allowed = if whitelist_guard.is_empty() {
        true
    } else {
        is_domain_allowed(&domain, &whitelist_guard)
    };
    drop(whitelist_guard);
    
    if !domain_allowed {
        warn!("[Domains] Email dropped - domain not allowed: {}", recipient_email);
        return Ok(());
    }

    // Check bans cache for recipient domain ban
    if is_domain_banned(&domain, bans_cache).await {
        warn!("[Bans] Dropped email to banned domain: {}", recipient_email);
        return Ok(());
    }

    // Check bans cache for sender (exact + contains)
    let from_lower = from_address.to_lowercase();
    if is_email_banned(&from_lower, bans_cache).await {
        warn!("[Bans] Dropped email from banned sender: {} -> {}", from_lower, recipient_email);
        return Ok(());
    }

    // Parse subject from raw email headers using mailparse for proper MIME decoding
    let subject = match parse_mail(raw_email.as_bytes()) {
        Ok(parsed) => {
            parsed.get_headers().get_first_value("Subject")
                .unwrap_or_else(|| "No Subject".to_string())
        }
        Err(_) => {
            // Fallback to manual extraction if parsing fails
            extract_subject_from_raw(&raw_email).unwrap_or_else(|| "No Subject".to_string())
        }
    };
    
    info!("✉ Parsed email for {} from {} - Subject: '{}' [inst: {}]", recipient_email, from_address, subject, instance.as_str());

    // First check if this is a private email (Postgres)
    match sqlx::query("SELECT id FROM private_email WHERE email = $1 LIMIT 1")
        .bind(&recipient_email)
        .fetch_optional(postgres_pool)
        .await
    {
        Ok(opt) => {
            if opt.is_some() {
                // Save directly into Postgres emails table for private users using the raw email as body
                let to_addrs_vec_local = vec![recipient_email.clone()];
                
                // Send to batch processor instead of direct insert
                let email_insert = EmailInsert {
                    mailbox_owner: recipient_email.clone(),
                    mailbox: "INBOX".to_string(),
                    subject: subject.clone(),
                    body: raw_email.clone(),
                    html: String::new(),
                    from_addr: from_address.clone(),
                    to_addrs: to_addrs_vec_local,
                    size: raw_email.len() as i64,
                };
                
                match batch_sender.send(email_insert).await {
                    Ok(_) => {
                        info!("✓ Queued email for private user (batch): {} -> {} [inst: {}]", from_address, recipient_email, instance.as_str());
                        // Update last_updated_at for the private_email row
                        let _ = sqlx::query("UPDATE private_email SET last_updated_at = NOW() WHERE email = $1")
                            .bind(&recipient_email)
                            .execute(postgres_pool)
                            .await;

                        return Ok(());
                    }
                    Err(e) => {
                        error!("Failed to queue private email for batch insert: {:?}", e);
                    }
                }
            }
        }
        Err(e) => {
            error!("Error checking private_email in Postgres: {:?}", e);
        }
    }

    // Handle as temp email - save to PostgreSQL

    // Get or create inbox and parse email in parallel
    let raw_email_clone = raw_email.clone();
    let ( _ , parsed_result ) = tokio::join!(
        get_or_create_inbox_pg(postgres_pool, &recipient_email, instance.clone()),
        tokio::task::spawn_blocking(move || {
            let data = raw_email_clone;
            let bodies_result = match parse_mail(data.as_bytes()) {
                Ok(parsed) => {
                    let mut text_body = String::new();
                    let mut html_body = String::new();

                    // If no subparts, try top-level body
                    if parsed.subparts.is_empty() {
                        if let Ok(b) = parsed.get_body() {
                            if let Some(ct) = parsed.get_headers().get_first_value("Content-Type") {
                                let ct_l = ct.to_lowercase();
                                if ct_l.contains("text/html") {
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
                            if let Some(ct) = sub.get_headers().get_first_value("Content-Type") {
                                let ct_l = ct.to_lowercase();
                                if ct_l.contains("text/html") {
                                    if let Ok(b) = sub.get_body() { html_body = b; }
                                } else if ct_l.contains("text/plain") {
                                    if let Ok(b) = sub.get_body() { text_body = b; }
                                } else {
                                    if text_body.is_empty() {
                                        if let Ok(b) = sub.get_body() { text_body = b; }
                                    }
                                }
                            } else {
                                if text_body.is_empty() {
                                    if let Ok(b) = sub.get_body() { text_body = b; }
                                }
                            }
                        }
                    }

                    if text_body.trim().is_empty() {
                        if let Ok(b) = parsed.get_body() { text_body = b; }
                    }

                    if text_body.trim().is_empty() && html_body.trim().is_empty() {
                        // Strip headers from raw email to avoid saving signatures and metadata
                        let body_only = strip_email_headers(&data);
                        text_body = body_only;
                    }

                    Ok((text_body, html_body))
                }
                Err(e) => Err(e)
            };
            (data, bodies_result)
        })
    );

    let (raw_email_owned, bodies_result) = match parsed_result {
        Ok((d, br)) => (d, br),
        Err(e) => {
            warn!("spawn_blocking failed, falling back to raw body: {}", e);
            // fallback: save raw as plain text
            let text_body = raw_email.clone();

            let to_addrs_vec = vec![recipient_email.clone()];
            info!("Saving to PostgreSQL (fallback): mailbox_owner={}, mailbox=INBOX, subject={}, from={}, size={} [inst: {}]", recipient_email, subject, from_address, text_body.len(), instance.as_str());

            let email_insert = EmailInsert {
                mailbox_owner: recipient_email.clone(),
                mailbox: "INBOX".to_string(),
                subject: subject.clone(),
                body: raw_email.clone(),
                html: String::new(),
                from_addr: from_address.clone(),
                to_addrs: to_addrs_vec,
                size: raw_email.len() as i64,
            };
            
            if let Err(e) = batch_sender.send(email_insert).await {
                error!("Failed to queue email for batch insert (fallback): {}", e);
            } else {
                info!("✓ Queued email (fallback batch). [inst: {}]", instance.as_str());
            }

            return Ok(());
        }
    };

    let (text_body, html_body) = match bodies_result {
        Ok((t, h)) => (t, h),
        Err(e) => {
            warn!("mailparse failed to parse message, falling back to raw body: {}", e);
            // fallback: save raw as plain text
            let text_body = raw_email_owned.clone();

            let to_addrs_vec = vec![recipient_email.clone()];
            info!("Saving to PostgreSQL (fallback): mailbox_owner={}, mailbox=INBOX, subject={}, from={}, size={} [inst: {}]", recipient_email, subject, from_address, text_body.len(), instance.as_str());

            let email_insert = EmailInsert {
                mailbox_owner: recipient_email.clone(),
                mailbox: "INBOX".to_string(),
                subject: subject.clone(),
                body: raw_email_owned.clone(),
                html: String::new(),
                from_addr: from_address.clone(),
                to_addrs: to_addrs_vec,
                size: raw_email_owned.len() as i64,
            };
            
            if let Err(e) = batch_sender.send(email_insert).await {
                error!("Failed to queue email for batch insert (fallback): {}", e);
            } else {
                info!("✓ Queued email (fallback batch). [inst: {}]", instance.as_str());
            }

            return Ok(());
        }
    };

    let to_addrs_vec = vec![recipient_email.clone()];
    info!("Saving to PostgreSQL: mailbox_owner={}, mailbox=INBOX, subject={}, from={}, text_len={}, html_len={} [inst: {}]", recipient_email, subject, from_address, text_body.len(), html_body.len(), instance.as_str());

    let email_insert = EmailInsert {
        mailbox_owner: recipient_email.clone(),
        mailbox: "INBOX".to_string(),
        subject: subject.clone(),
        body: text_body.clone(),
        html: html_body.clone(),
        from_addr: from_address.clone(),
        to_addrs: to_addrs_vec.clone(),
        size: raw_email_owned.len() as i64,
    };
    
    match batch_sender.send(email_insert).await {
        Ok(_) => {
            info!("✓ Queued email for batch insert [inst: {}]", instance.as_str());
            info!("✓ Email text size: {} bytes, html size: {} bytes [inst: {}]", text_body.len(), html_body.len(), instance.as_str());
        }
        Err(e) => {
            error!("Failed to queue email for batch insert: {}", e);
        }
    }

    Ok(())
}

// Helper function to extract subject from raw email (fallback only)
fn extract_subject_from_raw(raw_email: &str) -> Option<String> {
    for line in raw_email.lines() {
        if line.to_lowercase().starts_with("subject:") {
            return Some(line[8..].trim().to_string());
        }
    }
    None
}

// Helper function to strip email headers from raw email content
fn strip_email_headers(raw_email: &str) -> String {
    let mut in_headers = true;
    let mut result = String::new();
    
    for line in raw_email.lines() {
        if in_headers {
            // Empty line marks end of headers
            if line.trim().is_empty() {
                in_headers = false;
            }
            // Skip header lines (but keep them out of the body)
        } else {
            // We're in the body now
            if result.is_empty() {
                result.push_str(line);
            } else {
                result.push_str("\r\n");
                result.push_str(line);
            }
        }
    }
    
    // If we didn't find a body separator, return a truncated version to avoid signatures
    if in_headers && result.is_empty() {
        // Find the first occurrence of common body markers or just take a reasonable portion
        if let Some(body_start) = raw_email.find("\r\n\r\n") {
            let body = &raw_email[body_start + 4..];
            // Limit to first 2000 chars to avoid including signatures/metadata
            if body.len() > 2000 {
                body.chars().take(2000).collect()
            } else {
                body.to_string()
            }
        } else {
            // No clear body separator, take first 1000 chars
            raw_email.chars().take(1000).collect()
        }
    } else {
        result
    }
}

// PostgreSQL-based inbox management (replaces Supabase)
async fn get_or_create_inbox_pg(postgres_pool: &PgPool, email: &str, instance: Arc<String>) -> anyhow::Result<String> {
    // Try to find existing inbox
    let result = sqlx::query_as::<_, (String,)>(
        "SELECT id::text FROM inbox WHERE email_address = $1"
    )
    .bind(email)
    .fetch_optional(postgres_pool)
    .await;

    match result {
        Ok(Some((inbox_id,))) => {
            // Inbox exists
            return Ok(inbox_id);
        }
        Ok(None) => {
            // Inbox doesn't exist, create it
            let insert_result = sqlx::query_as::<_, (String,)>(
                "INSERT INTO inbox (email_address) VALUES ($1) RETURNING id::text"
            )
            .bind(email)
            .fetch_one(postgres_pool)
            .await;

            match insert_result {
                Ok((inbox_id,)) => {
                    info!("✓ Created inbox in PostgreSQL: {} [inst: {}]", inbox_id, instance.as_str());
                    Ok(inbox_id)
                }
                Err(e) => {
                    error!("Failed to create inbox in PostgreSQL: {:?}", e);
                    Err(anyhow::anyhow!("PostgreSQL inbox creation error: {}", e))
                }
            }
        }
        Err(e) => {
            error!("Error checking inbox in PostgreSQL: {:?}", e);
            Err(anyhow::anyhow!("PostgreSQL inbox query error: {}", e))
        }
    }
}

fn is_domain_allowed(domain: &str, whitelist: &HashSet<String>) -> bool {
    if whitelist.is_empty() {
        return true;
    }
    
    let domain_lower = domain.to_lowercase();
    
    if whitelist.contains(&domain_lower) {
        return true;
    }
    
    if whitelist.contains(&format!("*.{}", domain_lower)) {
        return true;
    }
    
    for whitelisted_domain in whitelist {
        if whitelisted_domain.starts_with("*.") {
            let base_domain = &whitelisted_domain[2..];
            if domain_lower.ends_with(base_domain) {
                if domain_lower == base_domain || domain_lower.ends_with(&format!(".{}", base_domain)) {
                    return true;
                }
            }
        }
    }
    
    false
}

async fn load_domain_whitelist(
    supabase_url: &str,
    supabase_key: &str,
    whitelist: Arc<Mutex<HashSet<String>>>,
) -> anyhow::Result<()> {
    let client = Client::new();
    let api_url = format!("{}/rest/v1/domains", supabase_url);
    match client
        .get(&api_url)
        .header("apikey", supabase_key)
        .header("Authorization", format!("Bearer {}", supabase_key))
        .send()
        .await {
            Ok(response) => {
                match response.json::<Vec<Domain>>().await {
                    Ok(res) => {
                        let mut wl = whitelist.lock().await;
                        for domain in res {
                            let domain_lower = domain.domain.to_lowercase();
                            wl.insert(domain_lower.clone());
                            if !domain_lower.starts_with("*.") {
                                wl.insert(format!("*.{}", domain_lower));
                            }
                        }
                        info!("✅ Loaded {} whitelisted domains from Supabase", wl.len() / 2);
                        if wl.is_empty() {
                            warn!("⚠ No domains configured - all emails will be accepted");
                        }
                        Ok(())
                    }
                    Err(e) => {
                        warn!("⚠ Failed to parse Supabase domains response: {}", e);
                        Err(anyhow::anyhow!("Supabase parse error: {}", e))
                    }
                }
            }
            Err(e) => {
                warn!("⚠ Failed to load domains from Supabase: {}", e);
                warn!("📧 SMTP server will accept all domains until connection is restored");
                Err(anyhow::anyhow!("Supabase connection error: {}", e))
            }
        }
}

async fn poll_domain_updates(
    supabase_url: String,
    supabase_key: String,
    whitelist: Arc<Mutex<HashSet<String>>>,
) {
    let client = Client::new();
    // Reduced from 60s to 120s for 1 vCore optimization
    let mut poll_interval = tokio::time::interval(Duration::from_secs(120));
    
    loop {
        poll_interval.tick().await;
        
        info!("🔄 Polling Supabase for domain updates...");
        
        let url = format!("{}/rest/v1/domains?select=domain", supabase_url);
        
        match client
            .get(&url)
            .header("apikey", &supabase_key)
            .header("Authorization", format!("Bearer {}", supabase_key))
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<Vec<DomainResponse>>().await {
                        Ok(domains) => {
                            let mut wl = whitelist.lock().await;
                            wl.clear();
                            
                            for domain_response in domains {
                                let domain_lower = domain_response.domain.to_lowercase();
                                wl.insert(domain_lower.clone());
                                if !domain_lower.starts_with("*.") {
                                    wl.insert(format!("*.{}", domain_lower));
                                }
                            }
                            
                            info!("✅ Updated {} domains from Supabase", wl.len() / 2);
                        }
                        Err(e) => {
                            warn!("⚠ Failed to parse domains response: {}", e);
                        }
                    }
                } else {
                    warn!("⚠ Failed to fetch domains: HTTP {}", response.status());
                }
            }
            Err(e) => {
                warn!("⚠ Failed to connect to Supabase for domain polling: {}", e);
            }
        }
    }
}

async fn load_bans(supabase_url: &str, supabase_key: &str, bans_cache: Arc<RwLock<BansCache>>) {
    let client = Client::new();
    let url = format!("{}/rest/v1/bans?status=eq.active", supabase_url);

    match client
        .get(&url)
        .header("apikey", supabase_key)
        .header("Authorization", format!("Bearer {}", supabase_key))
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                match resp.json::<Vec<Ban>>().await {
                    Ok(rows) => {
                        let mut cache = BansCache::default();
                        for b in rows {
                            let scope = b.scope.to_lowercase();
                            let mut val = b.value.trim().to_lowercase();
                            let mtype = b.match_type.unwrap_or_else(|| "exact".to_string()).to_lowercase();
                            match scope.as_str() {
                                "email" => {
                                    if mtype == "contains" {
                                        if val.starts_with("contains:") {
                                            val = val["contains:".len()..].to_string();
                                        }
                                        cache.email_contains.push(val.clone());
                                    } else {
                                        cache.email_exact.insert(val.clone());
                                    }
                                }
                                "domain" => {
                                    cache.domain.insert(val.clone());
                                }
                                _ => {}
                            }
                        }
                        // Swap caches atomically
                        let mut guard = bans_cache.write().await;
                        *guard = cache;
                        info!("✅ Loaded bans (global_exact={}, global_contains={}, global_domains={})", guard.email_exact.len(), guard.email_contains.len(), guard.domain.len());
                    }
                    Err(e) => {
                        warn!("⚠ Failed to parse bans JSON: {}", e);
                    }
                }
            } else {
                // read response body for diagnostics (avoid logging secrets)
                match resp.text().await {
                    Ok(body) => warn!("⚠ Bans fetch HTTP {}. Body: {}", status, body),
                    Err(e) => warn!("⚠ Bans fetch HTTP {} and failed to read body: {}", status, e),
                }
            }
        }
        Err(e) => {
            warn!("⚠ Failed to connect to Supabase for bans polling: {:?}", e);
            warn!("   reqwest::Error::is_timeout() = {} | status = {:?}", e.is_timeout(), e.status());
        }
    }
}

async fn poll_bans(supabase_url: String, supabase_key: String, bans_cache: Arc<RwLock<BansCache>>) {
    // Reduced from 30s to 60s for 1 vCore optimization
    let mut poll_interval = tokio::time::interval(Duration::from_secs(60));
    // Initial load
    load_bans(&supabase_url, &supabase_key, bans_cache.clone()).await;
    loop {
        poll_interval.tick().await;
        info!("🔄 Polling Supabase for bans updates...");
        load_bans(&supabase_url, &supabase_key, bans_cache.clone()).await;
    }
}

// Helper: check if a domain is banned globally
async fn is_domain_banned(domain: &str, bans_cache: &Arc<RwLock<BansCache>>) -> bool {
    let guard = bans_cache.read().await;
    let domain_lower = domain.to_lowercase();
    if guard.domain.contains(&domain_lower) {
        return true;
    }
    false
}

// Helper: check if an email/from address is banned (global exact/contains)
async fn is_email_banned(from_lower: &str, bans_cache: &Arc<RwLock<BansCache>>) -> bool {
    let guard = bans_cache.read().await;
    // global exact
    if guard.email_exact.contains(from_lower) {
        return true;
    }
    // global contains
    for sub in &guard.email_contains {
        if from_lower.contains(sub) {
            return true;
        }
    }
    false
}

// Batch flush function for efficient bulk inserts
async fn flush_batch(pool: &PgPool, buffer: &mut Vec<EmailInsert>) {
    if buffer.is_empty() {
        return;
    }
    
    info!("🔄 Flushing batch of {} emails to database", buffer.len());
    
    // Use a transaction for batch insert
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to start transaction for batch insert: {}", e);
            buffer.clear();
            return;
        }
    };

    let batch_len = buffer.len();
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

    let insert_result = query.build().execute(&mut *tx).await;
    buffer.clear();

    match insert_result {
        Ok(_) => match tx.commit().await {
            Ok(_) => info!("✓ Batch committed: {} emails", batch_len),
            Err(e) => error!("Failed to commit batch transaction: {}", e),
        },
        Err(e) => {
            error!("Failed to insert batch: {}", e);
            let _ = tx.rollback().await;
        }
    }
}