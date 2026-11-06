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
    #[cfg(test)]
    fn example() -> Self {
        Self {
            endpoints: vec![
                Endpoint {
                    url: "http://127.0.0.1:1".into(),
                    token_file: "unused".into()
                };
                2
            ],
            duration_seconds: 60.0,
            overall_seconds: 1800.0,
            rate: 20.0,
            window: 8,
            payload_bytes: 256,
            max_attempts: 100000,
            output: "unused".into(),
        }
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
        eprintln!("{code}");
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
    let start = Instant::now();
    state.lock().unwrap().publication_started = true;
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct OwnedDir(PathBuf);
    impl OwnedDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "duration-rpc-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for OwnedDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    async fn rpc_fixture(
        mode: &'static str,
    ) -> (
        Client,
        Arc<Mutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
        String,
    ) {
        use connectrpc::{
            RequestContext, Response, Router, ServiceStream, bidi_streaming_handler_fn, handler_fn,
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let stream_calls = calls.clone();
        let ack_calls = calls.clone();
        let abandon_calls = calls.clone();
        let begin_calls = calls.clone();
        let recovery_calls = calls.clone();
        let service = api::ASTER_APPLICATION_SERVICE_SERVICE_NAME;
        let router = Router::new()
            .route(service, "BeginEventPublicationSession", handler_fn(move |ctx: RequestContext, req: api::BeginEventPublicationSessionRequest| {
                assert_eq!(ctx.headers().get("authorization").unwrap(), "Bearer test-token");
                assert_eq!(req.client_id, b"duration-benchmark-v1");
                assert_eq!(req.claim_nonce, b"fresh-duration-benchmark-claim-v1");
                begin_calls.lock().unwrap().push("begin".into());
                async move { Ok(Response::new(api::BeginEventPublicationSessionResponse {
                    session: if mode == "stale" { 2 } else { 1 }, snapshot_revision: 7, ..Default::default()
                })) }
            }))
            .route(service, "CompleteEventPublicationRecovery", handler_fn(move |ctx: RequestContext, req: api::CompleteEventPublicationRecoveryRequest| {
                assert_eq!(ctx.headers().get("authorization").unwrap(), "Bearer test-token");
                assert_eq!(req.client_id, b"duration-benchmark-v1");
                assert_eq!(req.session, 1);
                assert_eq!(req.snapshot_revision, 7);
                recovery_calls.lock().unwrap().push("recovery".into());
                async { Ok(Response::new(api::CompleteEventPublicationRecoveryResponse::default())) }
            }))
            .route_bidi_stream(service, "PublishNumberedEvents", bidi_streaming_handler_fn(move |ctx: RequestContext, requests: ServiceStream<api::PublishNumberedEventsRequest>| {
                assert_eq!(ctx.headers().get("authorization").unwrap(), "Bearer test-token");
                stream_calls.lock().unwrap().push("stream".into());
                async move {
                    Response::stream_ok(requests.then(move |request| async move {
                        let request = request?;
                        let seq = request.publication.operation_sequence;
                        if mode == "auth_error" { return Err(connectrpc::ConnectError::unauthenticated("test")); }
                        if mode == "disconnect" { return Err(connectrpc::ConnectError::unavailable("test")); }
                        if mode == "malformed" { return Ok(api::PublishNumberedEventsResponse::default()); }
                        if mode == "timeout" { tokio::time::sleep(Duration::from_secs(1)).await; }
                        if mode == "late" { tokio::time::sleep(Duration::from_millis(80)).await; }
                        let outcome = if mode == "reject" {
                            api::publish_numbered_events_response::Outcome::Failure(Box::new(api::PublicErrorDetail { operation: "publish_numbered_events".into(), reason: api::PublicErrorReason::OperationCapacityExhausted.into(), ..Default::default() }))
                        } else {
                            api::publish_numbered_events_response::Outcome::Published(Box::new(api::PublishNumberedEventResponse { result: api::CommittedPublicationResult { operation_sequence: if mode == "wrong_sequence" { seq + 1 } else { seq }, content: api::CommittedContentStatus::Available.into(), receipt: api::CommittedEventReceipt { event_id: vec![seq as u8;32], transfer_id: vec![3;32], acceptance_marker: if mode == "zero_marker" { 0 } else { seq }, ..Default::default() }.into(), ..Default::default() }.into(), inserted: true, ..Default::default() }))
                        };
                        Ok(api::PublishNumberedEventsResponse { outcome: Some(outcome), ..Default::default() })
                    }))
                }
            }))
            .route(service, "AcknowledgeEventPublicationResult", handler_fn(move |ctx: RequestContext, req: api::AcknowledgeEventPublicationResultRequest| {
                assert_eq!(ctx.headers().get("authorization").unwrap(), "Bearer test-token");
                ack_calls.lock().unwrap().push("ack".into());
                async move {
                    if mode == "ack_error" { return Err(connectrpc::ConnectError::unauthenticated("test")); }
                    if mode == "ack_delay" { tokio::time::sleep(Duration::from_millis(if req.operation_sequence == 1 {80} else {200})).await; }
                    Ok(Response::new(api::AcknowledgeEventPublicationResultResponse::default()))
                }
            }))
            .route(service, "AbandonEventPublication", handler_fn(move |ctx: RequestContext, _: api::AbandonEventPublicationRequest| {
                assert_eq!(ctx.headers().get("authorization").unwrap(), "Bearer test-token");
                abandon_calls.lock().unwrap().push("abandon".into());
                async { Ok(Response::new(api::AbandonEventPublicationResponse::default())) }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let uri: http::Uri = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let service = connectrpc::ConnectRpcService::new(router);
            let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(
                    hyper_util::rt::TokioIo::new(socket),
                    hyper_util::service::TowerToHyperService::new(service),
                )
                .await;
        });
        let connection = Http2Connection::connect_plaintext(uri.clone())
            .await
            .unwrap()
            .shared(8);
        let client = Client::new(
            connection,
            ClientConfig::new(uri.clone())
                .with_protocol(connectrpc::Protocol::Grpc)
                .with_default_header("authorization", "Bearer test-token"),
        );
        (client, calls, task, uri.to_string())
    }
    #[tokio::test]
    async fn native_rpc_multiple_frames_rejections_and_partial_errors() {
        for mode in [
            "accepted",
            "reject",
            "late",
            "malformed",
            "disconnect",
            "timeout",
        ] {
            let owned = OwnedDir::new();
            let mut c = Config::example();
            c.output = owned.0.clone();
            c.duration_seconds = 0.05;
            c.overall_seconds = 1.0;
            c.rate = 100.0;
            let state = Arc::new(Mutex::new(Measurements::new(2)));
            let (client, calls, server, _) = rpc_fixture(mode).await;
            let context = api::EventClientContext {
                client_id: b"test".to_vec(),
                session: 1,
                ..Default::default()
            };
            let result = tokio::time::timeout(
                Duration::from_millis(600),
                publish(0, client, context, c, Instant::now(), state.clone()),
            )
            .await;
            let s = state.lock().unwrap();
            match mode {
                "accepted" => {
                    assert!(matches!(result, Ok(Ok(()))), "{mode}: {result:?}");
                    assert!(s.attempts.len() > 1, "multiple frames on a live stream");
                    let calls = calls.lock().unwrap();
                    assert_eq!(calls.iter().filter(|x| *x == "stream").count(), 1);
                    let operation = if mode == "reject" { "abandon" } else { "ack" };
                    assert_eq!(
                        calls.iter().filter(|x| *x == operation).count(),
                        s.attempts.len()
                    );
                }
                "late" => {
                    assert!(matches!(result, Ok(Ok(()))));
                    assert!(s.attempts.len() > 1);
                    assert!(s.attempts[0].response_s.unwrap() >= 0.05);
                }
                "reject" => {
                    assert!(matches!(
                        result,
                        Ok(Err("capacity_rejection_pipeline_stopped"))
                    ));
                    assert_eq!(s.attempts[0].outcome, "rejected");
                }
                "timeout" => {
                    assert!(result.is_err());
                    assert_eq!(s.attempts[0].outcome, "unresolved");
                }
                _ => {
                    assert!(matches!(result, Ok(Err(_))));
                    assert_eq!(s.attempts[0].outcome, "unresolved");
                }
            }
            server.abort();
        }
    }

    #[tokio::test]
    async fn delayed_receipt_does_not_serialize_sends() {
        let owned = OwnedDir::new();
        let mut c = Config::example();
        c.output = owned.0.clone();
        c.duration_seconds = 0.05;
        c.overall_seconds = 2.0;
        c.rate = 100.0;
        let state = Arc::new(Mutex::new(Measurements::new(2)));
        let (client, _, server, _) = rpc_fixture("late").await;
        publish(
            0,
            client,
            api::EventClientContext {
                session: 1,
                ..Default::default()
            },
            c,
            Instant::now(),
            state.clone(),
        )
        .await
        .unwrap();
        let s = state.lock().unwrap();
        assert!(
            s.attempts.len() >= 3,
            "must send multiple paced frames before delayed first receipt"
        );
        assert!(s.attempts[2].send_started_s.unwrap() < s.attempts[0].response_s.unwrap());
        server.abort();
    }

    #[tokio::test]
    async fn initial_session_validates_freshness_and_completes_recovery() {
        for mode in ["accepted", "stale"] {
            let (client, calls, server, _) = rpc_fixture(mode).await;
            let result = initialize(&client).await;
            if mode == "stale" {
                assert_eq!(result.err(), Some("nonfresh_session"));
                assert!(!calls.lock().unwrap().iter().any(|c| c == "recovery"));
            } else {
                assert_eq!(result.unwrap().session, 1);
                assert_eq!(*calls.lock().unwrap(), vec!["begin", "recovery"]);
            }
            server.abort();
        }
    }

    #[tokio::test]
    async fn delayed_ack_bounds_window_and_refills_without_batch_barrier() {
        let owned = OwnedDir::new();
        let mut c = Config::example();
        c.output = owned.0.clone();
        c.duration_seconds = 0.18;
        c.overall_seconds = 2.0;
        c.rate = 1000.0;
        let state = Arc::new(Mutex::new(Measurements::new(2)));
        let (client, _, server, _) = rpc_fixture("ack_delay").await;
        publish(
            0,
            client,
            api::EventClientContext {
                session: 1,
                ..Default::default()
            },
            c,
            Instant::now(),
            state.clone(),
        )
        .await
        .unwrap();
        let s = state.lock().unwrap();
        let starts: Vec<_> = s.attempts.iter().filter_map(|a| a.send_started_s).collect();
        assert_eq!(starts.iter().filter(|t| **t < 0.08).count(), 8);
        assert!(
            starts.len() > 8,
            "first completed ack must refill without waiting for the other seven"
        );
        assert!(starts[8] >= 0.08 && starts[8] < 0.18);
        assert_eq!(
            s.attempts[8].due_s, 0.008,
            "refill must retain original monotonic deadline"
        );
        let mut timeline = Vec::new();
        for a in &s.attempts {
            timeline.push((a.send_started_s.unwrap(), 1i32));
            timeline.push((a.result_acknowledged_s.unwrap(), -1));
        }
        timeline.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
        let mut outstanding = 0;
        for (_, delta) in timeline {
            outstanding += delta;
            assert!((0..=8).contains(&outstanding));
        }
        assert_eq!(outstanding, 0);
        server.abort();
    }

    #[tokio::test]
    async fn invalid_receipts_and_authentication_are_partial_errors() {
        for mode in ["wrong_sequence", "zero_marker", "auth_error", "ack_error"] {
            let owned = OwnedDir::new();
            let mut c = Config::example();
            c.output = owned.0.clone();
            c.duration_seconds = 0.02;
            c.rate = 100.0;
            let state = Arc::new(Mutex::new(Measurements::new(2)));
            let (client, _, server, _) = rpc_fixture(mode).await;
            let result = publish(
                0,
                client,
                api::EventClientContext {
                    session: 1,
                    ..Default::default()
                },
                c,
                Instant::now(),
                state.clone(),
            )
            .await;
            assert!(result.is_err(), "{mode} must not succeed");
            assert!(!state.lock().unwrap().attempts[0].result_acknowledged);
            server.abort();
        }
    }

    #[test]
    fn publishers_have_distinct_payload_identities() {
        assert_eq!(publication_identity(0, 1, 100), 1);
        assert_eq!(publication_identity(1, 1, 100), 101);
        assert_eq!(publication_identity(4, 100, 100), 500);
    }

    #[test]
    fn delivery_before_receipt_still_checks_exact_payload_identity() {
        let mut state = Measurements::new(2);
        state.record_delivery(0, "aa".into(), 2, 0.1).unwrap();
        assert_eq!(
            state.record_acceptance("aa".into(), 1),
            Err("delivery_payload_identity")
        );
    }
    #[test]
    fn validates_config_and_exact_convergence() {
        let mut c = super::Config::example();
        assert!(c.validate().is_ok());
        c.window = 0;
        assert_eq!(c.validate(), Err("configuration_bounds"));
        c.window = 9;
        assert_eq!(c.validate(), Err("configuration_bounds"));
        c.window = 8;
        c.rate = f64::NAN;
        assert!(c.validate().is_err());
        c.rate = 1.0;
        c.overall_seconds = c.duration_seconds;
        assert!(c.validate().is_err());
        let mut s = super::Measurements::new(2);
        assert!(s.complete());
        s.accepted.insert("aa".into(), 1);
        assert!(!s.complete());
        s.delivered[0].insert("aa".into(), 1.0);
        assert!(!s.complete());
        s.delivered[1].insert("bb".into(), 1.0);
        assert!(!s.complete());
        s.delivered[1].insert("aa".into(), 2.0);
        assert!(s.complete());
    }
    #[test]
    fn payload_verifies_full_bytes_and_rejects_malformed() {
        let p = super::payload(12, 256);
        assert_eq!(super::payload_sequence(&p, 256, 20).unwrap(), 12);
        let mut bad = p;
        bad[255] ^= 1;
        assert!(super::payload_sequence(&bad, 256, 20).is_err());
        assert!(super::payload_sequence(&[], 256, 20).is_err());
    }
    #[test]
    fn exact_scheduled_count_is_not_an_attempt_limit() {
        assert!(!super::attempt_limit_reached(2, 2, 0.05, 40.0));
        assert!(super::attempt_limit_reached(2, 2, 0.05, 0.0));
        assert!(super::attempt_limit_reached(2, 2, 0.05, 100.0));
    }
    #[test]
    fn absolute_schedule_does_not_accumulate_wake_jitter() {
        for n in 0..1000 {
            assert_eq!(super::due_seconds(n, 20.0), n as f64 / 20.0);
        }
    }
}
