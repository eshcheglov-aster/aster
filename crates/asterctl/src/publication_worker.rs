//! Line IPC for workload generators retaining one durable SDK owner.
use crate::{api, journal::describe_error};
use aster_agent::sdk::{
    MAX_PUBLICATION_JOURNAL_ENTRIES, NumberedEventSdk, PublicationPacing, RecoveredState,
    RecoveryReport,
};
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
    #[serde(rename = "publish-batch")]
    PublishBatch {
        intents: Vec<api::PublishNumberedEventRequest>,
        interval_seconds: f64,
        first_delay_seconds: f64,
    },
    #[serde(rename = "stream-start")]
    StreamStart {
        interval_seconds: f64,
        first_delay_seconds: f64,
    },
    #[serde(rename = "stream-item")]
    StreamItem {
        intent: Box<api::PublishNumberedEventRequest>,
    },
    #[serde(rename = "stream-applied")]
    StreamApplied { sequence: NonZeroU64 },
    #[serde(rename = "stream-finish")]
    StreamFinish,
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
    let mut pacing = None;
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
            if send
                .blocking_send((tokio::time::Instant::now(), request))
                .is_err()
                || terminal
            {
                break;
            }
        }
    });
    while let Some((received_at, request)) = receive.recv().await {
        if let Ok(Request::StreamStart {
            interval_seconds,
            first_delay_seconds,
        }) = request
        {
            let result = serve_stream(
                &sdk,
                &pending,
                &mut receive,
                received_at,
                interval_seconds,
                first_delay_seconds,
            )
            .await;
            let failed = result.is_err();
            write_response(match result {
                Ok(lag) => json!({"result":{"finished":true,"max_schedule_lag_seconds":lag}}),
                Err(error) => json!({"error":error}),
            })
            .await?;
            // Discard queued commands after failure. A fresh owner must recover
            // the original journal before accepting any replacement input.
            if failed {
                return Ok(());
            }
            continue;
        }
        let mut timing = BTreeMap::new();
        let mut outcomes = BTreeMap::new();
        if let Some(seconds) = startup_seconds.take() {
            timing.insert("startup-recovery", seconds);
            outcomes.insert("startup-recovery", "success");
        }
        let result = match request {
            Ok(request) => {
                execute(
                    &sdk,
                    &mut pending,
                    &mut pacing,
                    received_at,
                    request,
                    &mut timing,
                    &mut outcomes,
                )
                .await
            }
            Err(error) => Err(error),
        };
        let response = match result {
            Ok(result) => {
                json!({"result":result,"timing_seconds":timing,"phase_outcomes":outcomes})
            }
            Err(error) => json!({"error":error,"timing_seconds":timing,"phase_outcomes":outcomes}),
        };
        write_response(response).await?;
    }
    Ok(())
}

async fn write_response_to<W: Write + Send + 'static>(
    mut output: W,
    response: Value,
) -> Result<(), String> {
    // Only one output is outstanding per worker. Never block the current-thread
    // reactor on a full stdout pipe; the controller drains concurrently and its
    // existing IPC deadline/terminate path bounds an unresponsive peer.
    tokio::task::spawn_blocking(move || {
        writeln!(output, "{response}")
            .and_then(|()| output.flush())
            .map_err(|_| "worker output closed; journal retained".to_owned())
    })
    .await
    .map_err(|_| "worker output task failed; journal retained".to_owned())?
}

async fn write_response(response: Value) -> Result<(), String> {
    write_response_to(io::stdout(), response).await
}

type WorkerInput = tokio::sync::mpsc::Receiver<(tokio::time::Instant, Result<Request, String>)>;

async fn serve_stream(
    sdk: &NumberedEventSdk<HttpClient>,
    pending: &BTreeSet<u64>,
    receive: &mut WorkerInput,
    received_at: tokio::time::Instant,
    interval: f64,
    delay: f64,
) -> Result<f64, String> {
    if !pending.is_empty()
        || !interval.is_finite()
        || !(0.000001..=3600.0).contains(&interval)
        || !delay.is_finite()
        || delay.abs() > 3600.0
    {
        return Err("invalid stream pace or unapplied journal work".into());
    }
    let offset = std::time::Duration::from_secs_f64(delay.abs());
    let due = if delay < 0.0 {
        received_at - offset
    } else {
        received_at + offset
    };
    let mut pacing = PublicationPacing::new(due, std::time::Duration::from_secs_f64(interval))
        .map_err(describe_error)?;
    let (input, source) = tokio::sync::mpsc::channel(8);
    let mut input = Some(input);
    let (output, mut results) =
        tokio::sync::mpsc::channel::<aster_agent::sdk::RollingPublication>(8);
    let mut applied = BTreeMap::new();
    write_response(json!({"result":{"ready":true}})).await?;
    let result = {
        let run = sdk.publish_rolling(source, output, &mut pacing, 1);
        tokio::pin!(run);
        loop {
            tokio::select! {
                result = &mut run => break result.map_err(describe_error),
                publication = results.recv() => {
                    if let Some(publication) = publication {
                        let sequence = publication.result.operation_sequence;
                        applied.insert(sequence, publication.applied);
                        write_response(json!({"result":{"intent":publication.intent,"publication":publication.result}})).await?;
                    }
                }
                request = receive.recv() => {
                    let (_, request) = request.ok_or("stream input closed; journal retained")?;
                    match request? {
                        Request::StreamItem { intent } => input.as_ref().ok_or("stream input already finished")?
                            .try_send(*intent).map_err(|_| "stream input window exceeded")?,
                        Request::StreamApplied { sequence } => applied.remove(&sequence.get())
                            .ok_or("application acknowledged an unknown result")?.send(())
                            .map_err(|_| "publication stream stopped; journal retained")?,
                        Request::StreamFinish => { input.take(); }
                        _ => return Err("invalid command during stream".into()),
                    }
                }
            }
        }
    };
    write_response(
        json!({"result":{"telemetry":true,"publication_trace":pacing.trace()},"timing_seconds":{"schedule-lag":pacing.max_schedule_lag().as_secs_f64()}}),
    ).await?;
    result?;
    Ok(pacing.max_schedule_lag().as_secs_f64())
}

async fn execute(
    sdk: &NumberedEventSdk<HttpClient>,
    pending: &mut BTreeSet<u64>,
    pacing: &mut Option<(f64, PublicationPacing)>,
    received_at: tokio::time::Instant,
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
        Request::PublishBatch {
            intents,
            interval_seconds,
            first_delay_seconds,
        } => {
            if !pending.is_empty() {
                return Err(
                    "journal has unapplied work; recover and acknowledge original intent first"
                        .to_owned(),
                );
            }
            if intents.is_empty()
                || intents.len() > MAX_PUBLICATION_JOURNAL_ENTRIES
                || !interval_seconds.is_finite()
                || !(0.000001..=3600.0).contains(&interval_seconds)
                || !first_delay_seconds.is_finite()
                || first_delay_seconds.abs() > 3600.0
            {
                return Err("invalid bounded publication batch or pace".to_owned());
            }
            if pacing
                .as_ref()
                .is_some_and(|(interval, _)| *interval != interval_seconds)
            {
                return Err("publication pace cannot change within a worker".to_owned());
            }
            if pacing.is_none() {
                let offset = std::time::Duration::from_secs_f64(first_delay_seconds.abs());
                let due = if first_delay_seconds < 0.0 {
                    received_at - offset
                } else {
                    received_at + offset
                };
                *pacing = Some((
                    interval_seconds,
                    PublicationPacing::new(
                        due,
                        std::time::Duration::from_secs_f64(interval_seconds),
                    )
                    .map_err(describe_error)?,
                ));
            }
            let mut sequences = Vec::with_capacity(intents.len());
            measured!(
                "journal-batch",
                (|| {
                    for intent in intents {
                        let sequence = sdk.journal_publication(intent)?;
                        pending.insert(sequence);
                        sequences.push(sequence);
                    }
                    Ok::<_, aster_agent::sdk::NumberedEventSdkError>(())
                })()
            )
            .map_err(describe_error)?;
            let schedule = &mut pacing.as_mut().expect("initialized pace").1;
            let results = measured!(
                "sdk-stream",
                sdk.publish_journaled_pipeline_paced(&sequences, 1, schedule)
                    .await
            );
            timing.insert("schedule-lag", schedule.max_schedule_lag().as_secs_f64());
            let results = results.map_err(describe_error)?;
            Ok(
                json!({"results": results, "max_schedule_lag_seconds": schedule.max_schedule_lag().as_secs_f64()}),
            )
        }
        Request::StreamStart { .. }
        | Request::StreamItem { .. }
        | Request::StreamApplied { .. }
        | Request::StreamFinish => Err("stream command outside active stream".into()),
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

#[cfg(test)]
mod output_tests {
    use super::*;

    struct SlowOutput;
    impl Write for SlowOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            std::thread::sleep(std::time::Duration::from_millis(100));
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn blocked_output_keeps_current_thread_reactor_running() {
        let heartbeat = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        });
        tokio::task::yield_now().await;
        write_response_to(SlowOutput, json!({"result":true}))
            .await
            .unwrap();
        assert!(
            heartbeat.is_finished(),
            "stdout must not block the async reactor"
        );
        heartbeat.await.unwrap();
    }
}
