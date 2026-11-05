//! Line IPC for workload generators retaining one durable SDK owner.
use crate::{api, journal::describe_error};
use aster_agent::sdk::{NumberedEventSdk, RecoveredState, RecoveryReport};
use connectrpc::client::HttpClient;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, Read, Write};
use std::num::NonZeroU64;
use std::time::Instant;

// Base64 plus JSON for the SDK's bounded Event payload, not an unbounded stream.
const MAX_LINE: u64 = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(tag = "action", deny_unknown_fields)]
enum Request {
    #[serde(rename = "publish")]
    Publish {
        intent: Box<api::PublishNumberedEventRequest>,
    },
    #[serde(rename = "publication-recover")]
    Recover,
    #[serde(rename = "publication-show")]
    Show { sequence: NonZeroU64 },
    #[serde(rename = "publication-retry")]
    Retry { sequence: NonZeroU64 },
    #[serde(rename = "publication-ack")]
    Ack { sequence: NonZeroU64 },
}

fn outstanding(report: &RecoveryReport) -> BTreeSet<u64> {
    report
        .operations
        .iter()
        .filter(|operation| operation.state != RecoveredState::Retired)
        .map(|operation| operation.sequence)
        .collect()
}

fn report_json(report: RecoveryReport) -> Value {
    let operations: Vec<_> = report
        .operations
        .into_iter()
        .map(|operation| {
            let sequence = operation.sequence.to_string();
            match operation.state {
                RecoveredState::Pending => json!({"operationSequence":sequence,"state":"pending"}),
                RecoveredState::Committed(result) => {
                    json!({"operationSequence":sequence,"state":"committed","result":result})
                }
                RecoveredState::Retired => json!({"operationSequence":sequence,"state":"retired"}),
            }
        })
        .collect();
    json!({"session":report.session.to_string(),"allocatedThrough":report.allocated_through.to_string(),"operations":operations})
}

pub async fn serve(sdk: NumberedEventSdk<HttpClient>) -> Result<(), String> {
    let started = Instant::now();
    let report = sdk.recover().await.map_err(describe_error)?;
    let mut startup_seconds = Some(started.elapsed().as_secs_f64());
    let mut pending = outstanding(&report);
    // A dedicated OS reader, rather than blocking this current-thread runtime
    // or Tokio's blocking pool. The reactor stays live between IPC requests;
    // EOF closes the channel and process exit does not wait on a stdin task.
    let (send, mut receive) = tokio::sync::mpsc::channel(1);
    std::thread::spawn(move || {
        let mut input = io::stdin().lock();
        loop {
            let mut line = Vec::new();
            let read = input
                .by_ref()
                .take(MAX_LINE + 1)
                .read_until(b'\n', &mut line);
            let terminal =
                !matches!(read, Ok(n) if n > 0 && n as u64 <= MAX_LINE && line.ends_with(b"\n"));
            if matches!(read, Ok(0)) {
                break;
            }
            let request = if terminal {
                Err("worker request truncated or exceeds line bound".to_owned())
            } else {
                serde_json::from_slice::<Request>(&line)
                    .map_err(|_| "invalid worker request".to_owned())
            };
            if send.blocking_send(request).is_err() || terminal {
                break;
            }
        }
    });
    while let Some(request) = receive.recv().await {
        let mut timing = BTreeMap::new();
        let mut outcomes = BTreeMap::new();
        if let Some(seconds) = startup_seconds.take() {
            timing.insert("startup-recovery", seconds);
            outcomes.insert("startup-recovery", "success");
        }
        let result = match request {
            Ok(request) => execute(&sdk, &mut pending, request, &mut timing, &mut outcomes).await,
            Err(error) => Err(error),
        };
        let response = match result {
            Ok(result) => {
                json!({"result":result,"timing_seconds":timing,"phase_outcomes":outcomes})
            }
            Err(error) => json!({"error":error,"timing_seconds":timing,"phase_outcomes":outcomes}),
        };
        let mut output = io::stdout().lock();
        writeln!(output, "{response}")
            .and_then(|()| output.flush())
            .map_err(|_| "worker output closed; journal retained".to_owned())?;
    }
    Ok(())
}

async fn execute(
    sdk: &NumberedEventSdk<HttpClient>,
    pending: &mut BTreeSet<u64>,
    request: Request,
    timing: &mut BTreeMap<&'static str, f64>,
    outcomes: &mut BTreeMap<&'static str, &'static str>,
) -> Result<Value, String> {
    // Wall time at SDK boundaries, including scheduling. SDK methods include
    // local journal work as well as RPC; these are not server-only timings.
    macro_rules! measured {
        ($name:literal, $operation:expr) => {{
            let started = Instant::now();
            let result = $operation;
            timing.insert($name, started.elapsed().as_secs_f64());
            outcomes.insert($name, if result.is_err() { "error" } else { "success" });
            result
        }};
    }
    match request {
        Request::Publish { intent } => {
            if !pending.is_empty() {
                return Err(
                    "journal has unapplied work; recover and acknowledge original intent first"
                        .to_owned(),
                );
            }
            let sequence =
                measured!("journal", sdk.journal_publication(*intent)).map_err(describe_error)?;
            pending.insert(sequence);
            let result = measured!("sdk-publish", sdk.publish_journaled_outcome(sequence).await)
                .map_err(describe_error)?;
            Ok(json!(result))
        }
        Request::Recover => {
            let report = measured!("sdk-recover", sdk.recover().await).map_err(describe_error)?;
            *pending = outstanding(&report);
            Ok(report_json(report))
        }
        Request::Show { sequence } => {
            let intent = measured!("journal-show", sdk.journaled_intent(sequence.get()))
                .map_err(describe_error)?
                .ok_or("sequence has no retained journaled intent")?;
            Ok(json!(intent))
        }
        Request::Retry { sequence } => {
            let result = measured!("sdk-retry", sdk.publish_journaled(sequence.get()).await)
                .map_err(describe_error)?;
            Ok(json!(result))
        }
        Request::Ack { sequence } => {
            measured!("sdk-ack", sdk.acknowledge(sequence.get()).await).map_err(describe_error)?;
            pending.remove(&sequence.get());
            Ok(Value::Null)
        }
    }
}
