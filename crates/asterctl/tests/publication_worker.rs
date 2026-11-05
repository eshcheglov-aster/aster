use buffa::Message;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

mod support;
mod proto {
    connectrpc::include_generated!();
}
use proto::aster::application::v1alpha1 as api;

fn exchange(child: &mut std::process::Child, request: Value) -> Value {
    writeln!(child.stdin.as_mut().unwrap(), "{request}").unwrap();
    // Read exactly one line, without reading ahead across responses.
    let mut line = Vec::new();
    loop {
        let mut byte = [0];
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut byte)
            .unwrap();
        if byte == *b"\n" {
            break;
        }
        line.push(byte[0]);
    }
    serde_json::from_slice(&line).unwrap()
}

#[test]
fn lost_response_reopens_original_sequence_and_retries_only_original_intent() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let mut session = 0;
        let mut intents = Vec::new();
        for method in [
            "BeginEventPublicationSession",
            "CompleteEventPublicationRecovery",
            "PublishNumberedEvent",
            "BeginEventPublicationSession",
            "CompleteEventPublicationRecovery",
            "BeginEventPublicationSession",
            "CompleteEventPublicationRecovery",
            "BeginEventPublicationSession",
            "CompleteEventPublicationRecovery",
            "PublishNumberedEvent",
            "AcknowledgeEventPublicationResult",
        ] {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.contains(method), "{line} expected {method}");
            let mut length = 0;
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length: ") {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let response = match method {
                "BeginEventPublicationSession" => {
                    let request =
                        api::BeginEventPublicationSessionRequest::decode_from_slice(&body).unwrap();
                    assert_eq!(request.expected_session, session);
                    session += 1;
                    api::BeginEventPublicationSessionResponse {
                        session,
                        snapshot_revision: 1,
                        ..Default::default()
                    }
                    .encode_to_vec()
                }
                "CompleteEventPublicationRecovery" => {
                    if session == 2 {
                        continue; // Lose an explicit recovery response too.
                    }
                    api::CompleteEventPublicationRecoveryResponse::default().encode_to_vec()
                }
                "PublishNumberedEvent" => {
                    let mut request =
                        api::PublishNumberedEventRequest::decode_from_slice(&body).unwrap();
                    assert_eq!(request.operation_sequence, 1);
                    assert_eq!(request.session, session);
                    request.session = 0;
                    intents.push(request);
                    if intents.len() == 1 {
                        continue;
                    } // Drop an uncertain response.
                    assert_eq!(intents[0], intents[1]);
                    api::PublishNumberedEventResponse {
                        result: api::CommittedPublicationResult {
                            operation_sequence: 1,
                            receipt: api::CommittedEventReceipt {
                                event_id: vec![7; 32],
                                transfer_id: vec![8; 32],
                                acceptance_marker: 1,
                                ..Default::default()
                            }
                            .into(),
                            content: api::CommittedContentStatus::Available.into(),
                            ..Default::default()
                        }
                        .into(),
                        inserted: true,
                        ..Default::default()
                    }
                    .encode_to_vec()
                }
                _ => api::AcknowledgeEventPublicationResultResponse::default().encode_to_vec(),
            };
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/proto\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
            socket.write_all(&response).unwrap();
        }
        assert_eq!(intents.len(), 2);
    });
    let journal = support::Journal::new();
    let spawn = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_asterctl"));
        command.args([
            "--token",
            "asterctl-test-token-00000000000000",
            "--port",
            &port.to_string(),
            "publication-worker",
        ]);
        journal.configure(&mut command);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let mut child = spawn();
    let publish = json!({"action":"publish", "intent":{"topic":"mesh.messages", "scope":"demo/playground", "priority":"PRIORITY_ROUTINE", "logicalKey":"aw==", "payload":"cGF5bG9hZA=="}});
    let failed = exchange(&mut child, publish.clone());
    assert!(failed.get("error").is_some());
    for phase in ["startup-recovery", "journal", "sdk-publish"] {
        assert!(failed["timing_seconds"][phase].as_f64().unwrap() >= 0.0);
    }
    assert_eq!(
        failed["phase_outcomes"],
        json!({"startup-recovery":"success", "journal":"success", "sdk-publish":"error"})
    );
    let blocked = exchange(&mut child, publish);
    assert!(blocked.get("error").is_some());
    assert_eq!(blocked["phase_outcomes"], json!({}));
    let failed_recovery = exchange(&mut child, json!({"action":"publication-recover"}));
    assert!(failed_recovery.get("error").is_some());
    assert_eq!(
        failed_recovery["phase_outcomes"],
        json!({"sdk-recover":"error"})
    );
    child.kill().unwrap();
    child.wait().unwrap();
    let mut child = spawn();
    let recovered = exchange(&mut child, json!({"action":"publication-recover"}));
    assert_eq!(
        recovered["phase_outcomes"],
        json!({"startup-recovery":"success", "sdk-recover":"success"})
    );
    assert_eq!(
        recovered["result"]["operations"],
        json!([{"operationSequence":"1", "state":"pending"}])
    );
    let intent = exchange(
        &mut child,
        json!({"action":"publication-show", "sequence":1}),
    );
    assert_eq!(intent["result"]["payload"], "cGF5bG9hZA==");
    assert_eq!(intent["result"]["logicalKey"], "aw==");
    let result = exchange(
        &mut child,
        json!({"action":"publication-retry", "sequence":1}),
    );
    assert_eq!(result["result"]["operationSequence"], "1");
    assert!(
        exchange(
            &mut child,
            json!({"action":"publication-ack", "sequence":1})
        )
        .get("error")
        .is_none()
    );
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
    server.join().unwrap();
}

#[test]
fn repeated_publications_keep_one_session_across_idle_and_http_disconnect() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        for method in [
            "BeginEventPublicationSession",
            "CompleteEventPublicationRecovery",
            "PublishNumberedEvent",
            "AcknowledgeEventPublication",
            "PublishNumberedEvent",
            "AcknowledgeEventPublication",
        ] {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.contains(method), "{line} expected {method}");
            let mut length = 0;
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length: ") {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let response = match method {
                "BeginEventPublicationSession" => api::BeginEventPublicationSessionResponse {
                    session: 1,
                    snapshot_revision: 1,
                    ..Default::default()
                }
                .encode_to_vec(),
                "CompleteEventPublicationRecovery" => {
                    api::CompleteEventPublicationRecoveryResponse::default().encode_to_vec()
                }
                "PublishNumberedEvent" => {
                    let request =
                        api::PublishNumberedEventRequest::decode_from_slice(&body).unwrap();
                    assert_eq!(request.session, 1);
                    assert_eq!(request.payload, b"payload");
                    api::PublishNumberedEventResponse {
                        result: Some(api::CommittedPublicationResult {
                            operation_sequence: request.operation_sequence,
                            receipt: Some(api::CommittedEventReceipt {
                                event_id: vec![7; 32],
                                transfer_id: vec![8; 32],
                                acceptance_marker: request.operation_sequence,
                                ..Default::default()
                            })
                            .into(),
                            content: api::CommittedContentStatus::Available.into(),
                            ..Default::default()
                        })
                        .into(),
                        inserted: true,
                        ..Default::default()
                    }
                    .encode_to_vec()
                }
                _ => api::AcknowledgeEventPublicationResultResponse::default().encode_to_vec(),
            };
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/proto\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
            socket.write_all(&response).unwrap();
        }
    });
    let journal = support::Journal::new();
    let mut command = Command::new(env!("CARGO_BIN_EXE_asterctl"));
    command.args([
        "--token",
        "asterctl-test-token-00000000000000",
        "--port",
        &port.to_string(),
        "publication-worker",
    ]);
    journal.configure(&mut command);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    for sequence in 1..=2 {
        let request = json!({"action":"publish", "intent":{"topic":"mesh.messages", "scope":"demo/playground", "priority":"PRIORITY_ROUTINE", "logicalKey":"aw==", "payload":"cGF5bG9hZA=="}});
        writeln!(input, "{request}").unwrap();
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        let response: Value = serde_json::from_str(&line).expect("worker must reply with JSON");
        for phase in ["journal", "sdk-publish"] {
            assert!(response["timing_seconds"][phase].as_f64().unwrap() >= 0.0);
            assert_eq!(response["phase_outcomes"][phase], "success");
        }
        assert_eq!(
            response["result"]["result"]["operationSequence"],
            sequence.to_string()
        );
        writeln!(input, "{request}").unwrap();
        line.clear();
        output.read_line(&mut line).unwrap();
        assert!(
            serde_json::from_str::<Value>(&line)
                .unwrap()
                .get("error")
                .is_some(),
            "one lane must apply and acknowledge its result before assigning another intent"
        );
        writeln!(
            input,
            "{}",
            json!({"action":"publication-ack", "sequence":sequence})
        )
        .unwrap();
        line.clear();
        output.read_line(&mut line).unwrap();
        let acknowledgement: Value = serde_json::from_str(&line).unwrap();
        assert!(acknowledgement.get("error").is_none());
        assert_eq!(
            acknowledgement["phase_outcomes"],
            json!({"sdk-ack":"success"})
        );
        assert!(
            acknowledgement["timing_seconds"]["sdk-ack"]
                .as_f64()
                .unwrap()
                >= 0.0
        );
        thread::sleep(Duration::from_millis(150));
    }
    drop(input);
    assert!(child.wait().unwrap().success());
    server.join().unwrap();
}
