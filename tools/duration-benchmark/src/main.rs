use aster_agent::proto::aster::application::v1alpha1 as api;
use connectrpc::client::{ClientConfig, Http2Connection, SharedHttp2Connection};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;

type Client = api::AsterApplicationServiceClient<SharedHttp2Connection>;
type Result<T> = std::result::Result<T, &'static str>;
const TOPIC: &str = "mesh.messages";
const SCOPE: &str = "demo/playground";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    url: String,
    token_file: PathBuf,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    endpoints: Vec<Endpoint>,
    duration_seconds: f64,
    overall_seconds: f64,
    rate: f64,
    #[serde(default = "default_window")]
    window: usize,
    payload_bytes: usize,
    max_attempts: u64,
    output: PathBuf,
}
fn default_window() -> usize {
    8
}
impl Config {
    fn validate(&self) -> Result<()> {
        if !(2..=16).contains(&self.endpoints.len())
            || !self.duration_seconds.is_finite()
            || !(0.01..=600.0).contains(&self.duration_seconds)
            || !self.overall_seconds.is_finite()
            || self.overall_seconds <= self.duration_seconds
            || self.overall_seconds > 86400.0
            || !self.rate.is_finite()
            || !(0.0..=100000.0).contains(&self.rate)
            || !(8..=1024).contains(&self.payload_bytes)
            || !(1..=100000).contains(&self.max_attempts)
            || !(1..=8).contains(&self.window)
        {
            return Err("configuration_bounds");
        }
        if self
            .endpoints
            .iter()
            .any(|e| !e.url.starts_with("http://127.0.0.1:"))
        {
            return Err("loopback_required");
        }
        Ok(())
    }
}
#[derive(Serialize, Default)]
struct Attempt {
    publisher_node: usize,
    operation_sequence: u64,
    sequence: u64,
    due_s: f64,
    send_started_s: Option<f64>,
    send_completed_s: Option<f64>,
    response_s: Option<f64>,
    outcome: String,
    event_id: Option<String>,
    result_acknowledged: bool,
    result_acknowledged_s: Option<f64>,
}
#[derive(Serialize)]
struct Measurements {
    attempts: Vec<Attempt>,
    accepted: BTreeMap<String, u64>,
    delivered: Vec<BTreeMap<String, f64>>,
    delivery_acked: Vec<u64>,
    errors: Vec<String>,
    publication_finished: bool,
    publishers_remaining: usize,
    publication_started: bool,
    publication_start_monotonic_s: Option<f64>,
    publication_clock_uncertainty_s: Option<f64>,
    elapsed_s: f64,
    observed_sequences: BTreeMap<String, u64>,
}
impl Measurements {
    fn new(nodes: usize) -> Self {
        Self {
            attempts: vec![],
            accepted: BTreeMap::new(),
            delivered: vec![BTreeMap::new(); nodes],
            delivery_acked: vec![0; nodes],
            errors: vec![],
            publication_finished: false,
            publishers_remaining: nodes,
            publication_started: false,
            publication_start_monotonic_s: None,
            publication_clock_uncertainty_s: None,
            elapsed_s: 0.0,
            observed_sequences: BTreeMap::new(),
        }
    }
    fn record_delivery(
        &mut self,
        node: usize,
        id: String,
        sequence: u64,
        observed: f64,
    ) -> Result<()> {
        if self.accepted.get(&id).is_some_and(|s| *s != sequence)
            || self
                .observed_sequences
                .get(&id)
                .is_some_and(|s| *s != sequence)
        {
            return Err("delivery_payload_identity");
        }
        self.observed_sequences.insert(id.clone(), sequence);
        self.delivered[node].entry(id).or_insert(observed);
        Ok(())
    }
    fn record_acceptance(&mut self, id: String, sequence: u64) -> Result<()> {
        if self
            .observed_sequences
            .get(&id)
            .is_some_and(|s| *s != sequence)
        {
            return Err("delivery_payload_identity");
        }
        if self.accepted.insert(id, sequence).is_some() {
            return Err("publication_duplicate_id");
        }
        Ok(())
    }
    fn complete(&self) -> bool {
        self.delivered
            .iter()
            .all(|d| self.accepted.keys().all(|id| d.contains_key(id)))
    }
}
fn publication_identity(node: usize, sequence: u64, maximum: u64) -> u64 {
    node as u64 * maximum + sequence
}
fn payload(sequence: u64, bytes: usize) -> Vec<u8> {
    let mut p = vec![0; bytes];
    p[..8].copy_from_slice(&sequence.to_le_bytes());
    for (i, b) in p.iter_mut().enumerate().skip(8) {
        *b = (sequence.wrapping_mul(31).wrapping_add(i as u64) % 251) as u8;
    }
    p
}
fn payload_sequence(p: &[u8], bytes: usize, maximum: u64) -> Result<u64> {
    if p.len() != bytes || bytes < 8 {
        return Err("payload_length");
    }
    let seq = u64::from_le_bytes(p[..8].try_into().map_err(|_| "payload_length")?);
    if seq == 0 || seq > maximum || payload(seq, bytes) != p {
        return Err("payload_mismatch");
    }
    Ok(seq)
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn journal(file: &mut File, row: serde_json::Value) -> Result<()> {
    serde_json::to_writer(&mut *file, &row).map_err(|_| "journal_write")?;
    file.write_all(b"\n").map_err(|_| "journal_write")?;
    file.sync_all().map_err(|_| "journal_sync")
}

#[tokio::main]
async fn main() {
    let result = async {
        let path = std::env::args().nth(1).ok_or("configuration_path")?;
        let config: Config =
            serde_json::from_slice(&fs::read(path).map_err(|_| "configuration_read")?)
                .map_err(|_| "configuration_parse")?;
        config.validate()?;
        run(config).await
    }
    .await;
    if let Err(code) = result {
        eprintln!("Benchmark stopped: {code}");
        std::process::exit(2);
    }
}

async fn connect(endpoint: &Endpoint, timeout: f64) -> Result<Client> {
    let token = fs::read_to_string(&endpoint.token_file).map_err(|_| "token_read")?;
    let uri: http::Uri = endpoint.url.parse().map_err(|_| "endpoint_uri")?;
    let connection = Http2Connection::connect_plaintext(uri.clone())
        .await
        .map_err(|_| "connect")?
        .shared(8);
    Ok(Client::new(
        connection,
        ClientConfig::new(uri)
            .with_protocol(connectrpc::Protocol::Grpc)
            .with_default_timeout(Duration::from_secs_f64(timeout.min(900.0)))
            .with_default_header("authorization", format!("Bearer {}", token.trim())),
    ))
}

async fn initialize(client: &Client) -> Result<api::EventClientContext> {
    let client_id = b"duration-benchmark-v1".to_vec();
    let begin = client
        .begin_event_publication_session(api::BeginEventPublicationSessionRequest {
            client_id: client_id.clone(),
            claim_nonce: b"fresh-duration-benchmark-claim-v1".to_vec(),
            ..Default::default()
        })
        .await
        .map_err(|_| "begin_session")?
        .into_owned();
    if begin.session != 1
        || begin.snapshot_revision == 0
        || begin.allocated_through != 0
        || !begin.outstanding.is_empty()
    {
        return Err("nonfresh_session");
    }
    client
        .complete_event_publication_recovery(api::CompleteEventPublicationRecoveryRequest {
            client_id: client_id.clone(),
            session: begin.session,
            snapshot_revision: begin.snapshot_revision,
            ..Default::default()
        })
        .await
        .map_err(|_| "complete_initial_recovery")?;
    Ok(api::EventClientContext {
        client_id,
        session: begin.session,
        ..Default::default()
    })
}

async fn publish(
    node: usize,
    client: Client,
    context: api::EventClientContext,
    c: Config,
    start: Instant,
    state: Arc<Mutex<Measurements>>,
) -> Result<()> {
    let mut ledger = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(c.output.join(format!("publication-{node}.jsonl")))
        .map_err(|_| "journal_open")?;
    File::open(&c.output)
        .and_then(|f| f.sync_all())
        .map_err(|_| "journal_directory_sync")?;
    journal(
        &mut ledger,
        serde_json::json!({"kind":"session", "session":context.session, "client_id":hex(&context.client_id), "payload_bytes":c.payload_bytes}),
    )?;
    let stream = client
        .publish_numbered_events()
        .await
        .map_err(|_| "publication_stream_open")?;
    let end = start + Duration::from_secs_f64(c.duration_seconds);
    let (mut send, mut receive) = stream.into_split();
    let credits = Arc::new(tokio::sync::Semaphore::new(c.window));
    let (pending_tx, mut pending_rx) = tokio::sync::mpsc::channel(c.window);
    let ledger = Mutex::new(ledger);
    let sender = async {
        for sequence in 1..=c.max_attempts {
            let permit = match tokio::time::timeout_at(end, credits.clone().acquire_owned()).await {
                Ok(Ok(p)) => p,
                Err(_) => break,
                _ => return Err("publication_credit_closed"),
            };
            let due_s = due_seconds(sequence - 1, c.rate);
            if due_s >= c.duration_seconds {
                break;
            }
            tokio::time::sleep_until(start + Duration::from_secs_f64(due_s)).await;
            if Instant::now() >= end {
                break;
            }
            let index = {
                let mut s = state.lock().unwrap();
                s.attempts.push(Attempt {
                    publisher_node: node,
                    operation_sequence: sequence,
                    sequence: publication_identity(node, sequence, c.max_attempts),
                    due_s,
                    outcome: "unsent".into(),
                    ..Default::default()
                });
                s.attempts.len() - 1
            };
            journal(
                &mut ledger.lock().unwrap(),
                serde_json::json!({"kind":"intent", "sequence":sequence, "payload_bytes":c.payload_bytes}),
            )?;
            // Durable intent creation may cross the cutoff. Never send it afterward.
            if Instant::now() >= end {
                break;
            }
            {
                let mut s = state.lock().unwrap();
                s.attempts[index].send_started_s = Some(start.elapsed().as_secs_f64());
                s.attempts[index].outcome = "unresolved".into();
            }
            pending_tx
                .send((sequence, index, permit))
                .await
                .map_err(|_| "publication_receiver_closed")?;
            send.send(api::PublishNumberedEventsRequest {
                publication: api::PublishNumberedEventRequest {
                    client_id: context.client_id.clone(),
                    session: context.session,
                    operation_sequence: sequence,
                    topic: TOPIC.into(),
                    scope: SCOPE.into(),
                    priority: api::Priority::Routine.into(),
                    payload: payload(
                        publication_identity(node, sequence, c.max_attempts),
                        c.payload_bytes,
                    ),
                    ..Default::default()
                }
                .into(),
                ..Default::default()
            })
            .await
            .map_err(|_| "publication_send")?;
            state.lock().unwrap().attempts[index].send_completed_s =
                Some(start.elapsed().as_secs_f64());
        }
        send.close_send();
        drop(pending_tx);
        Ok::<_, &'static str>(())
    };
    let receiver = async {
        let mut acknowledgements = tokio::task::JoinSet::new();
        while let Some((sequence, index, permit)) = pending_rx.recv().await {
            while let Some(result) = acknowledgements.try_join_next() {
                result.map_err(|_| "publication_ack_join")??;
            }
            let response = receive
                .message::<api::PublishNumberedEventsResponse>()
                .await
                .map_err(|_| "publication_receive")?
                .ok_or("publication_eof")?
                .to_owned_message();
            let observed = start.elapsed().as_secs_f64();
            if observed >= c.overall_seconds {
                return Err("overall_timeout");
            }
            match response.outcome.ok_or("publication_missing_outcome")? {
                api::publish_numbered_events_response::Outcome::Published(p) => {
                    let r = p.result.as_option().ok_or("publication_missing_result")?;
                    let receipt = r.receipt.as_option().ok_or("publication_missing_receipt")?;
                    if r.operation_sequence != sequence
                        || receipt.event_id.len() != 32
                        || receipt.transfer_id.len() != 32
                        || receipt.acceptance_marker == 0
                        || r.content != api::CommittedContentStatus::Available
                    {
                        return Err("publication_invalid_result");
                    }
                    let id = hex(&receipt.event_id);
                    {
                        let mut s = state.lock().unwrap();
                        s.record_acceptance(
                            id.clone(),
                            publication_identity(node, sequence, c.max_attempts),
                        )?;
                        s.attempts[index].outcome = "accepted".into();
                        s.attempts[index].event_id = Some(id.clone());
                        s.attempts[index].response_s = Some(observed);
                    }
                    // Apply and durably record the result before compacting the agent's result.
                    journal(
                        &mut ledger.lock().unwrap(),
                        serde_json::json!({"kind":"accepted", "sequence":sequence, "event_id":id, "response_s":observed}),
                    )?;
                    let ack_client = client.clone();
                    let ack_context = context.clone();
                    let ack_state = state.clone();
                    acknowledgements.spawn(async move {
                        ack_client
                            .acknowledge_event_publication_result(
                                api::AcknowledgeEventPublicationResultRequest {
                                    client_id: ack_context.client_id.clone(),
                                    session: ack_context.session,
                                    operation_sequence: sequence,
                                    ..Default::default()
                                },
                            )
                            .await
                            .map_err(|_| "publication_ack")?;
                        {
                            let mut s = ack_state.lock().unwrap();
                            s.attempts[index].result_acknowledged = true;
                            s.attempts[index].result_acknowledged_s =
                                Some(start.elapsed().as_secs_f64());
                        }
                        drop(permit);
                        Ok::<_, &'static str>(())
                    });
                }
                api::publish_numbered_events_response::Outcome::Failure(f) => {
                    if f.operation != "publish_numbered_events"
                        || (f.reason != api::PublicErrorReason::ResourceExhaustion
                            && f.reason != api::PublicErrorReason::OperationCapacityExhausted)
                    {
                        return Err("publication_application_error");
                    }
                    {
                        let mut s = state.lock().unwrap();
                        s.attempts[index].outcome = "rejected".into();
                        s.attempts[index].response_s = Some(observed);
                    }
                    journal(
                        &mut ledger.lock().unwrap(),
                        serde_json::json!({"kind":"rejected", "sequence":sequence, "response_s":observed}),
                    )?;
                    client
                        .abandon_event_publication(api::AbandonEventPublicationRequest {
                            client_id: context.client_id.clone(),
                            session: context.session,
                            operation_sequence: sequence,
                            ..Default::default()
                        })
                        .await
                        .map_err(|_| "publication_abandon")?;
                    return Err("capacity_rejection_pipeline_stopped");
                }
            }
        }
        while let Some(result) = acknowledgements.join_next().await {
            result.map_err(|_| "publication_ack_join")??;
        }
        if receive
            .message::<api::PublishNumberedEventsResponse>()
            .await
            .map_err(|_| "publication_receive")?
            .is_some()
        {
            return Err("publication_extra_response");
        }
        Ok::<_, &'static str>(())
    };
    tokio::try_join!(sender, receiver)?;
    let attempts = state
        .lock()
        .unwrap()
        .attempts
        .iter()
        .filter(|a| a.publisher_node == node)
        .count() as u64;
    if attempt_limit_reached(attempts, c.max_attempts, c.duration_seconds, c.rate) {
        state.lock().unwrap().errors.push("attempt_limit".into());
    }
    tokio::time::sleep_until(end).await;
    Ok(())
}

async fn consume(
    client: Client,
    context: api::EventClientContext,
    subscription: Vec<u8>,
    node: usize,
    c: Config,
    start: Instant,
    state: Arc<Mutex<Measurements>>,
) -> Result<()> {
    let mut ledger = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(c.output.join(format!("delivery-{node}.jsonl")))
        .map_err(|_| "delivery_journal_open")?;
    File::open(&c.output)
        .and_then(|f| f.sync_all())
        .map_err(|_| "journal_directory_sync")?;
    let mut seen_sequences = BTreeMap::new();
    loop {
        if start.elapsed().as_secs_f64() >= c.overall_seconds {
            return Err("overall_timeout");
        }
        let response = client
            .poll_events(api::PollEventsRequest {
                client: context.clone().into(),
                subscription_id: subscription.clone(),
                delivery_limit: 32,
                scan_limit: 256,
                ..Default::default()
            })
            .await
            .map_err(|_| "delivery_poll")?
            .into_owned();
        let observed = start.elapsed().as_secs_f64();
        if observed >= c.overall_seconds {
            return Err("overall_timeout");
        }
        for delivery in response.deliveries {
            let e = delivery.event.as_option().ok_or("delivery_missing_event")?;
            let seq = payload_sequence(
                &e.payload,
                c.payload_bytes,
                c.max_attempts * c.endpoints.len() as u64,
            )?;
            if e.id.len() != 32 || e.topic != TOPIC || e.scope != SCOPE {
                return Err("delivery_metadata");
            }
            let id = hex(&e.id);
            if let Some(previous) = seen_sequences.insert(seq, id.clone())
                && previous != id
            {
                return Err("delivery_identity_conflict");
            }
            if seen_sequences.len() > c.max_attempts as usize * c.endpoints.len() {
                return Err("delivery_bound");
            }
            {
                let mut s = state.lock().unwrap();
                s.record_delivery(node, id.clone(), seq, observed)?;
            }
            journal(
                &mut ledger,
                serde_json::json!({"event_id":id,"sequence":seq,"observed_s":observed}),
            )?;
            client
                .acknowledge_event(api::AcknowledgeEventRequest {
                    client: context.clone().into(),
                    subscription_id: subscription.clone(),
                    event_id: e.id.clone(),
                    ..Default::default()
                })
                .await
                .map_err(|_| "delivery_ack")?;
        }
        state.lock().unwrap().delivery_acked[node] = seen_sequences.len() as u64;
        {
            let s = state.lock().unwrap();
            if s.publication_finished
                && s.accepted
                    .keys()
                    .all(|id| s.delivered[node].contains_key(id))
            {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn monotonic_seconds() -> Result<f64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: value is a valid writable timespec; CLOCK_MONOTONIC needs no ownership.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return Err("monotonic_clock");
    }
    Ok(value.tv_sec as f64 + value.tv_nsec as f64 / 1e9)
}

fn publication_clock() -> Result<(Instant, f64, f64)> {
    // Linux CLOCK_MONOTONIC is also Python time.monotonic(). Bracket the exact
    // Instant used by all workers, retaining the clock-read uncertainty.
    let before = monotonic_seconds()?;
    let start = Instant::now();
    let after = monotonic_seconds()?;
    Ok((start, (before + after) / 2.0, (after - before) / 2.0))
}

async fn run(c: Config) -> Result<()> {
    let state = Arc::new(Mutex::new(Measurements::new(c.endpoints.len())));
    let setup = async {
        let mut clients = vec![];
        for endpoint in &c.endpoints {
            let client = connect(endpoint, c.overall_seconds).await?;
            let context = initialize(&client).await?;
            let sub = client
                .create_event_subscription(api::CreateEventSubscriptionRequest {
                    client: context.clone().into(),
                    operation_key: b"duration-subscription-v1".to_vec(),
                    topic: TOPIC.into(),
                    scope: SCOPE.into(),
                    ..Default::default()
                })
                .await
                .map_err(|_| "subscription_create")?
                .into_owned();
            clients.push((client, context, sub.subscription_id));
        }
        Ok::<_, &'static str>(clients)
    };
    let clients = match tokio::time::timeout(Duration::from_secs(120), setup).await {
        Ok(Ok(c)) => c,
        other => {
            let code = match other {
                Ok(Err(e)) => e,
                _ => "setup_timeout",
            };
            state.lock().unwrap().errors.push(code.into());
            save(&c, &state)?;
            return Err(code);
        }
    };
    let (start, origin, uncertainty) = publication_clock()?;
    {
        let mut s = state.lock().unwrap();
        s.publication_started = true;
        s.publication_start_monotonic_s = Some(origin);
        s.publication_clock_uncertainty_s = Some(uncertainty);
    }
    let mut tasks = tokio::task::JoinSet::new();
    for (node, (client, context, _)) in clients.iter().enumerate() {
        let publisher_client = client.clone();
        let publisher_context = context.clone();
        let publisher_state = state.clone();
        let publisher_config = c.clone();
        tasks.spawn(async move {
            let result = publish(
                node,
                publisher_client,
                publisher_context,
                publisher_config,
                start,
                publisher_state.clone(),
            )
            .await;
            let mut s = publisher_state.lock().unwrap();
            s.publishers_remaining -= 1;
            s.publication_finished = s.publishers_remaining == 0;
            result
        });
    }
    for (node, (client, context, sub)) in clients.into_iter().enumerate() {
        tasks.spawn(consume(
            client,
            context,
            sub,
            node,
            c.clone(),
            start,
            state.clone(),
        ));
    }
    let deadline = start + Duration::from_secs_f64(c.overall_seconds);
    loop {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(Ok(Ok(())))) => {}
            Ok(None) => break,
            failed => {
                let code = match failed {
                    Ok(Some(Ok(Err(e)))) => e,
                    Ok(Some(Err(_))) => "worker_join",
                    _ => "overall_timeout",
                };
                state.lock().unwrap().errors.push(code.into());
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                break;
            }
        }
    }
    state.lock().unwrap().elapsed_s = start.elapsed().as_secs_f64();
    save(&c, &state)?;
    if !state.lock().unwrap().errors.is_empty() {
        return Err("incomplete_measurement");
    }
    Ok(())
}
fn save(c: &Config, state: &Arc<Mutex<Measurements>>) -> Result<()> {
    let s = state.lock().unwrap();
    let complete = s.publication_finished && s.complete() && s.errors.is_empty();
    let report = serde_json::json!({"status":if complete {"completed"} else {"incomplete"},"duration_seconds":c.duration_seconds,"overall_seconds":c.overall_seconds,"rate":c.rate,"payload_bytes":c.payload_bytes,"max_attempts":c.max_attempts,"publisher_nodes":c.endpoints.len(),"rate_scope":"per_agent","offered_total_rate":c.rate * c.endpoints.len() as f64,"application_window":c.window,"server_stream_window":8,"measurements": &*s});
    let mut file = File::create(c.output.join("measurement.json")).map_err(|_| "report_open")?;
    serde_json::to_writer_pretty(&mut file, &report).map_err(|_| "report_write")?;
    file.sync_all().map_err(|_| "report_sync")
}

fn attempt_limit_reached(count: u64, maximum: u64, duration: f64, rate: f64) -> bool {
    count == maximum && due_seconds(maximum, rate) < duration
}

fn due_seconds(index: u64, rate: f64) -> f64 {
    if rate == 0.0 {
        0.0
    } else {
        index as f64 / rate
    }
}
