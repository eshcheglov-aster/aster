#![cfg(feature = "client")]

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use aster_agent::{
    BoundAgent, ClientToken,
    proto::aster::application::v1alpha1 as api,
    sdk::{NumberedEventSdk, PipelinedEventPublisher, PublicationJournal, RecoveredState},
};
use aster_mesh::{ProvisioningAccess, ReferenceProvisioner, Scope, Topic};
use aster_node::mission::UnprotectedReferenceMission;
use aster_node::{MutableSourceInterests, NodeApplication, NodeConfig, start_node};
use buffa::{Message as _, MessageName as _};
use connectrpc::{
    ConnectError, ErrorCode, Protocol,
    client::{ClientConfig, Http2Connection, HttpClient},
};

const TEST_TOKEN: &[u8] = b"real-node-connect-test-token-0001";

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

struct TestState(PathBuf);

impl TestState {
    fn new() -> Self {
        let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-agent-real-node-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create isolated state root");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("protect isolated state root");
        Self(path)
    }
}

impl Drop for TestState {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn decode_base64(value: &str) -> Vec<u8> {
    fn sextet(byte: u8) -> u8 {
        match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("invalid base64 fixture"),
        }
    }

    let mut decoded = Vec::new();
    for chunk in value.as_bytes().chunks(4) {
        let a = sextet(chunk[0]);
        let b = sextet(chunk[1]);
        decoded.push((a << 2) | (b >> 4));
        if chunk.len() > 2 && chunk[2] != b'=' {
            let c = sextet(chunk[2]);
            decoded.push((b << 4) | (c >> 2));
            if chunk.len() > 3 && chunk[3] != b'=' {
                decoded.push((c << 6) | sextet(chunk[3]));
            }
        }
    }
    decoded
}

fn assert_authentication_error(error: &ConnectError, expected_type_url: &str) {
    assert_eq!(error.code, ErrorCode::Unauthenticated);
    assert_eq!(error.message.as_deref(), Some("authentication failed"));
    assert_eq!(error.details.len(), 1);
    let wire_detail = &error.details[0];
    assert_eq!(wire_detail.type_url, expected_type_url);
    assert!(wire_detail.debug.is_none());
    let detail = api::PublicErrorDetail::decode_from_slice(&decode_base64(
        wire_detail.value.as_deref().expect("encoded public detail"),
    ))
    .expect("decodable public authentication detail");
    assert_eq!(detail.reason, api::PublicErrorReason::AuthenticationFailed);
    assert_eq!(detail.operation, "unspecified");
    assert!(!detail.retryable);
    assert_eq!(detail.retry_delay_ms, None);
}

fn assert_public_reason(
    error: &ConnectError,
    code: ErrorCode,
    reason: api::PublicErrorReason,
    operation: &str,
) {
    assert_public_reason_with_retryability(error, code, reason, operation, false);
}

fn assert_public_reason_with_retryability(
    error: &ConnectError,
    code: ErrorCode,
    reason: api::PublicErrorReason,
    operation: &str,
    retryable: bool,
) {
    assert_eq!(error.code, code);
    assert_eq!(error.details.len(), 1, "{operation}: {error:?}");
    let wire_detail = &error.details[0];
    assert!(wire_detail.debug.is_none());
    let detail = api::PublicErrorDetail::decode_from_slice(&decode_base64(
        wire_detail.value.as_deref().expect("encoded public detail"),
    ))
    .expect("decodable public detail");
    assert_eq!(detail.reason, reason);
    assert_eq!(detail.operation, operation);
    assert_eq!(detail.retryable, retryable);
    assert_eq!(detail.retry_delay_ms, None);
}

fn blob_mission() -> UnprotectedReferenceMission {
    let access = ProvisioningAccess::member(
        Scope::new("mission/team/alpha").expect("Blob scope"),
        vec![1],
        vec![Topic::new("imagery.maps").expect("Blob topic")],
    )
    .expect("Blob access");
    let mut provisioner =
        ReferenceProvisioner::from_seed([0xb7; 32]).expect("reference provisioner");
    UnprotectedReferenceMission::from_bytes(
        provisioner
            .issue_node(1, &[access])
            .expect("issue Blob mission")
            .to_bytes()
            .expect("encode Blob mission"),
    )
    .expect("load disposable Blob test mission")
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "release-only local end-to-end Blob streaming benchmark"]
fn real_node_blob_bidi_stream_benchmark() {
    const TOTAL_LEN: u64 = 64 * 1024 * 1024;
    const FRAME_LEN: usize = 64 * 1024;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let state = TestState::new();
        let node = start_node(NodeConfig {
            state: state.0.clone(),
            bind: "127.0.0.1:0".parse().expect("mesh bind"),
            mission: blob_mission(),
            peers: Vec::new(),
            mutable_interests: MutableSourceInterests::default(),
            sync_interval: Duration::from_millis(50),
            run_for: None,
            application: NodeApplication::Relay,
        })
        .await
        .expect("start selected node");
        let agent = BoundAgent::bind("127.0.0.1:0".parse().expect("agent bind"))
            .await
            .expect("bind agent");
        let address = agent.local_addr().expect("agent address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(
            agent
                .serve_with_blobs(
                    node.selected_events(),
                    node.selected_blobs(),
                    node.state_root().to_path_buf(),
                    ClientToken::from_bytes(TEST_TOKEN.to_vec()).expect("valid token"),
                    shutdown_rx,
                )
                .expect("combined service"),
        );
        let client = api::AsterApplicationServiceClient::new(
            Http2Connection::connect_plaintext(
                format!("http://{address}").parse().expect("transport URI"),
            )
            .await
            .expect("connect HTTP/2")
            .shared(8),
            ClientConfig::new(format!("http://{address}").parse().expect("client URI"))
                .with_protocol(Protocol::Grpc)
                .with_default_header(
                    "authorization",
                    format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
                ),
        );

        let started = std::time::Instant::now();
        let mut call = client.publish_blob().await.expect("open publish RPC");
        call.send(api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                api::PublishBlobMetadata {
                    operation_key: b"local-rpc-release-benchmark".to_vec(),
                    topic: "imagery.maps".to_owned(),
                    scope: "mission/team/alpha".to_owned(),
                    priority: api::Priority::Routine.into(),
                    total_len: TOTAL_LEN,
                    ..Default::default()
                },
            ))),
            ..Default::default()
        })
        .await
        .expect("send metadata");
        let accepted = call
            .message::<api::PublishBlobResponse>()
            .await
            .expect("receive acceptance")
            .expect("acceptance response")
            .to_owned_message();
        assert!(matches!(
            accepted.frame,
            Some(api::publish_blob_response::Frame::Accepted(ref accepted))
                if accepted.durable_offset == 0 && accepted.accepted_offset == 0
        ));
        let (mut send, mut receive) = call.into_split();
        let sender = async move {
            let bytes = vec![0x5a; FRAME_LEN];
            let mut offset = 0_u64;
            while offset < TOTAL_LEN {
                send.send(api::PublishBlobRequest {
                    frame: Some(api::publish_blob_request::Frame::Data(Box::new(
                        api::PublishBlobData {
                            offset,
                            bytes: bytes.clone(),
                            ..Default::default()
                        },
                    ))),
                    ..Default::default()
                })
                .await
                .expect("send payload frame");
                offset += FRAME_LEN as u64;
            }
            send.send(api::PublishBlobRequest {
                frame: Some(api::publish_blob_request::Frame::Finish(Box::default())),
                ..Default::default()
            })
            .await
            .expect("send finish");
            send.close_send();
        };
        let receiver = async move {
            let mut checkpoints = 0_u64;
            let mut receipt = None;
            while let Some(response) = receive
                .message::<api::PublishBlobResponse>()
                .await
                .expect("receive progress")
            {
                match response.to_owned_message().frame {
                    Some(api::publish_blob_response::Frame::Checkpoint(_)) => checkpoints += 1,
                    Some(api::publish_blob_response::Frame::Complete(complete)) => {
                        receipt = Some(*complete)
                    }
                    _ => panic!("unexpected Blob progress frame"),
                }
            }
            (checkpoints, receipt.expect("completion receipt"))
        };
        let ((), (checkpoints, receipt)) = tokio::join!(sender, receiver);
        let elapsed = started.elapsed();
        assert_eq!(receipt.total_len, TOTAL_LEN);
        assert!(receipt.inserted);
        assert!(checkpoints > 0);
        eprintln!(
            "blob_rpc_publish bytes={TOTAL_LEN} seconds={:.6} bytes_per_second={:.0} mebibytes_per_second={:.2} checkpoints={checkpoints}",
            elapsed.as_secs_f64(),
            TOTAL_LEN as f64 / elapsed.as_secs_f64(),
            TOTAL_LEN as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0),
        );

        const RESUME_TOTAL: u64 = 20 * 1024 * 1024;
        const FIRST_CHECKPOINT: u64 = 16 * 1024 * 1024;
        let resume_metadata = || api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                api::PublishBlobMetadata {
                    operation_key: b"local-rpc-resume-benchmark".to_vec(),
                    topic: "imagery.maps".to_owned(),
                    scope: "mission/team/alpha".to_owned(),
                    priority: api::Priority::Routine.into(),
                    total_len: RESUME_TOTAL,
                    ..Default::default()
                },
            ))),
            ..Default::default()
        };
        let mut interrupted = client.publish_blob().await.expect("open interrupted RPC");
        interrupted
            .send(resume_metadata())
            .await
            .expect("send interrupted metadata");
        let accepted = interrupted
            .message::<api::PublishBlobResponse>()
            .await
            .expect("receive initial acceptance")
            .expect("initial acceptance")
            .to_owned_message();
        assert!(matches!(
            accepted.frame,
            Some(api::publish_blob_response::Frame::Accepted(ref accepted))
                if accepted.durable_offset == 0
        ));
        let resume_bytes = vec![0x39; FRAME_LEN];
        let mut offset = 0_u64;
        while offset < FIRST_CHECKPOINT {
            interrupted
                .send(api::PublishBlobRequest {
                    frame: Some(api::publish_blob_request::Frame::Data(Box::new(
                        api::PublishBlobData {
                            offset,
                            bytes: resume_bytes.clone(),
                            ..Default::default()
                        },
                    ))),
                    ..Default::default()
                })
                .await
                .expect("send pre-interruption frame");
            offset += FRAME_LEN as u64;
        }
        let durable_offset = loop {
            let response = interrupted
                .message::<api::PublishBlobResponse>()
                .await
                .expect("receive pre-interruption checkpoint")
                .expect("checkpoint response")
                .to_owned_message();
            if let Some(api::publish_blob_response::Frame::Checkpoint(checkpoint)) = response.frame
            {
                break checkpoint.durable_offset;
            }
        };
        assert!(durable_offset > 0);
        assert!(durable_offset <= FIRST_CHECKPOINT);
        assert_eq!(durable_offset % (1024 * 1024), 0);
        interrupted
            .send(api::PublishBlobRequest {
                frame: Some(api::publish_blob_request::Frame::Data(Box::new(
                    api::PublishBlobData {
                        offset,
                        bytes: resume_bytes.clone(),
                        ..Default::default()
                    },
                ))),
                ..Default::default()
            })
            .await
            .expect("send uncheckpointed tail");
        drop(interrupted);

        let mut resumed = loop {
            let mut candidate = client.publish_blob().await.expect("reopen publish RPC");
            candidate
                .send(resume_metadata())
                .await
                .expect("send resume metadata");
            match candidate.message::<api::PublishBlobResponse>().await {
                Ok(Some(response)) => break (candidate, response.to_owned_message()),
                Err(error) if error.code == ErrorCode::ResourceExhausted => {
                    tokio::task::yield_now().await;
                }
                other => panic!("resume negotiation failed: {other:?}"),
            }
        };
        let accepted = resumed.1.frame.expect("resumed acceptance frame");
        let api::publish_blob_response::Frame::Accepted(accepted) = accepted else {
            panic!("expected resumed acceptance")
        };
        assert!(accepted.durable_offset >= durable_offset);
        assert!(accepted.durable_offset <= FIRST_CHECKPOINT);
        assert_eq!(accepted.durable_offset % (1024 * 1024), 0);
        assert_eq!(accepted.accepted_offset, accepted.durable_offset);
        let resumed_offset = accepted.durable_offset;
        offset = resumed_offset;
        while offset < RESUME_TOTAL {
            let send_result = resumed
                .0
                .send(api::PublishBlobRequest {
                    frame: Some(api::publish_blob_request::Frame::Data(Box::new(
                        api::PublishBlobData {
                            offset,
                            bytes: resume_bytes.clone(),
                            ..Default::default()
                        },
                    ))),
                    ..Default::default()
                })
                .await;
            if let Err(send_error) = send_result {
                let server_error = resumed.0.message::<api::PublishBlobResponse>().await;
                panic!(
                    "send resumed frame failed at offset {offset}: send={send_error:?} server={server_error:?}"
                );
            }
            offset += FRAME_LEN as u64;
        }
        resumed
            .0
            .send(api::PublishBlobRequest {
                frame: Some(api::publish_blob_request::Frame::Finish(Box::default())),
                ..Default::default()
            })
            .await
            .expect("finish resumed publication");
        resumed.0.close_send();
        let mut resumed_complete = None;
        while let Some(response) = resumed
            .0
            .message::<api::PublishBlobResponse>()
            .await
            .expect("receive resumed progress")
        {
            if let Some(api::publish_blob_response::Frame::Complete(complete)) =
                response.to_owned_message().frame
            {
                resumed_complete = Some(*complete);
            }
        }
        assert_eq!(
            resumed_complete.expect("resumed completion").total_len,
            RESUME_TOTAL
        );
        eprintln!(
            "blob_rpc_resume durable_offset={resumed_offset} replayed_tail_bytes={} total_bytes={RESUME_TOTAL}",
            FIRST_CHECKPOINT + FRAME_LEN as u64 - resumed_offset
        );

        shutdown_tx.send(true).expect("request agent shutdown");
        server.await.expect("agent task").expect("agent shutdown");
        node.shutdown().await.expect("node shutdown");
    });
}

async fn assert_exact_blob_rpc_resume(
    client: &api::AsterApplicationServiceClient<connectrpc::client::SharedHttp2Connection>,
) {
    const RESUME_FRAME: usize = 64 * 1024;
    const RESUME_SEGMENT: u64 = 1024 * 1024;
    const RESUME_TOTAL: u64 = 2 * RESUME_SEGMENT;
    let resume_metadata = || api::PublishBlobRequest {
        frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
            api::PublishBlobMetadata {
                operation_key: b"real-node-blob-exact-resume".to_vec(),
                topic: "imagery.maps".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                priority: api::Priority::Routine.into(),
                media_type: Some("application/x-aster-test".to_owned()),
                schema_id: b"schema/blob-v1".to_vec(),
                total_len: RESUME_TOTAL,
                ..Default::default()
            },
        ))),
        ..Default::default()
    };
    let mut interrupted = client.publish_blob().await.expect("open exact-resume RPC");
    interrupted
        .send(resume_metadata())
        .await
        .expect("send exact-resume metadata");
    let accepted = interrupted
        .message::<api::PublishBlobResponse>()
        .await
        .expect("receive exact-resume acceptance")
        .expect("exact-resume acceptance")
        .to_owned_message();
    assert!(matches!(
        accepted.frame,
        Some(api::publish_blob_response::Frame::Accepted(ref accepted))
            if accepted.accepted_offset == 0
                && accepted.durable_offset == 0
                && accepted.canonical_frame_bytes == RESUME_FRAME as u32
    ));
    let first = vec![0x61; RESUME_FRAME];
    let mut resume_offset = 0_u64;
    while resume_offset < RESUME_SEGMENT {
        if resume_offset + RESUME_FRAME as u64 == RESUME_SEGMENT {
            // Expire the interval immediately before completing a pack segment.
            // Sleeping before the first frame instead permits a checkpoint of
            // zero complete segments and resets the interval too early.
            tokio::time::sleep(Duration::from_millis(275)).await;
        }
        interrupted
            .send(api::PublishBlobRequest {
                frame: Some(api::publish_blob_request::Frame::Data(Box::new(
                    api::PublishBlobData {
                        offset: resume_offset,
                        bytes: first.clone(),
                        ..Default::default()
                    },
                ))),
                ..Default::default()
            })
            .await
            .expect("send checkpointed exact-resume frame");
        resume_offset += RESUME_FRAME as u64;
    }
    let checkpoint = loop {
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            interrupted.message::<api::PublishBlobResponse>(),
        )
        .await
        .expect("exact-resume checkpoint deadline")
        .expect("receive exact-resume checkpoint")
        .expect("exact-resume checkpoint response")
        .to_owned_message();
        if let Some(api::publish_blob_response::Frame::Checkpoint(checkpoint)) = response.frame {
            break checkpoint;
        }
    };
    assert_eq!(checkpoint.accepted_offset, RESUME_SEGMENT);
    assert_eq!(checkpoint.durable_offset, RESUME_SEGMENT);
    interrupted
        .send(api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Data(Box::new(
                api::PublishBlobData {
                    offset: RESUME_SEGMENT,
                    bytes: vec![0x62; RESUME_FRAME],
                    ..Default::default()
                },
            ))),
            ..Default::default()
        })
        .await
        .expect("send non-durable exact-resume tail");
    drop(interrupted);

    let (resumed, accepted) = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut candidate = client
                .publish_blob()
                .await
                .expect("reopen exact-resume RPC");
            candidate
                .send(resume_metadata())
                .await
                .expect("resend exact-resume metadata");
            match candidate.message::<api::PublishBlobResponse>().await {
                Ok(Some(response)) => break (candidate, response.to_owned_message()),
                Err(error) if error.code == ErrorCode::ResourceExhausted => {
                    tokio::task::yield_now().await;
                }
                other => panic!("exact-resume negotiation failed: {other:?}"),
            }
        }
    })
    .await
    .expect("exact-resume cleanup deadline");
    let Some(api::publish_blob_response::Frame::Accepted(accepted)) = accepted.frame else {
        panic!("expected exact resumed acceptance")
    };
    assert_eq!(accepted.accepted_offset, RESUME_SEGMENT);
    assert_eq!(accepted.durable_offset, RESUME_SEGMENT);
    let (mut resumed_send, mut resumed_receive) = resumed.into_split();
    let resumed_sender = async move {
        let mut offset = RESUME_SEGMENT;
        let second = vec![0x62; RESUME_FRAME];
        while offset < RESUME_TOTAL {
            resumed_send
                .send(api::PublishBlobRequest {
                    frame: Some(api::publish_blob_request::Frame::Data(Box::new(
                        api::PublishBlobData {
                            offset,
                            bytes: second.clone(),
                            ..Default::default()
                        },
                    ))),
                    ..Default::default()
                })
                .await
                .expect("send resumed exact-resume frame");
            offset += RESUME_FRAME as u64;
        }
        resumed_send
            .send(api::PublishBlobRequest {
                frame: Some(api::publish_blob_request::Frame::Finish(Box::default())),
                ..Default::default()
            })
            .await
            .expect("finish exact-resume publication");
        resumed_send.close_send();
    };
    let resumed_receiver = async move {
        let mut receipt = None;
        while let Some(response) = resumed_receive
            .message::<api::PublishBlobResponse>()
            .await
            .expect("receive exact-resume completion")
        {
            if let Some(api::publish_blob_response::Frame::Complete(complete)) =
                response.to_owned_message().frame
            {
                receipt = Some(*complete);
            }
        }
        receipt.expect("exact-resume receipt")
    };
    let ((), resumed_receipt) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(resumed_sender, resumed_receiver)
    })
    .await
    .expect("exact-resume completion deadline");
    assert_eq!(
        resumed_receipt.id,
        [
            0x66, 0x76, 0xb9, 0xb5, 0xce, 0x4f, 0x1f, 0x3a, 0xc7, 0xbc, 0xd7, 0x82, 0x31, 0xbe,
            0x44, 0x4d, 0xd8, 0x07, 0x3d, 0x8a, 0xf9, 0x95, 0x21, 0x82, 0x4e, 0x99, 0xf1, 0x79,
            0xaa, 0xb6, 0x5b, 0x07,
        ]
    );
    let mut resumed_read = client
        .read_blob(api::ReadBlobRequest {
            id: resumed_receipt.id.clone(),
            topic: "imagery.maps".to_owned(),
            scope: "mission/team/alpha".to_owned(),
            ..Default::default()
        })
        .await
        .expect("open exact-resume read");
    let mut resumed_bytes = Vec::new();
    loop {
        let page = tokio::time::timeout(Duration::from_secs(5), resumed_read.message())
            .await
            .expect("exact-resume read deadline")
            .expect("read exact-resume page");
        let Some(page) = page else { break };
        resumed_bytes.extend_from_slice(&page.to_owned_message().chunk);
    }
    let mut expected_resumed = vec![0x61; RESUME_SEGMENT as usize];
    expected_resumed.extend(vec![0x62; RESUME_SEGMENT as usize]);
    assert_eq!(resumed_bytes, expected_resumed);
}

#[cfg(target_os = "linux")]
#[test]
fn real_node_blob_bidi_disconnect_resumes_exact_bytes() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let state = TestState::new();
        let node = start_node(NodeConfig {
            state: state.0.clone(),
            bind: "127.0.0.1:0".parse().expect("mesh bind"),
            mission: blob_mission(),
            peers: Vec::new(),
            mutable_interests: MutableSourceInterests::default(),
            sync_interval: Duration::from_millis(50),
            run_for: None,
            application: NodeApplication::Relay,
        })
        .await
        .expect("start exact-resume node");
        let agent = BoundAgent::bind("127.0.0.1:0".parse().expect("agent bind"))
            .await
            .expect("bind exact-resume agent");
        let address = agent.local_addr().expect("agent address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(
            agent
                .serve_with_blobs(
                    node.selected_events(),
                    node.selected_blobs(),
                    node.state_root().to_path_buf(),
                    ClientToken::from_bytes(TEST_TOKEN.to_vec()).expect("valid token"),
                    shutdown_rx,
                )
                .expect("construct exact-resume service"),
        );
        let client = api::AsterApplicationServiceClient::new(
            Http2Connection::connect_plaintext(
                format!("http://{address}")
                    .parse()
                    .expect("exact-resume transport URI"),
            )
            .await
            .expect("connect exact-resume HTTP/2")
            .shared(8),
            ClientConfig::new(
                format!("http://{address}")
                    .parse()
                    .expect("exact-resume client URI"),
            )
            .with_protocol(Protocol::Grpc)
            .with_default_header(
                "authorization",
                format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
            ),
        );

        assert_exact_blob_rpc_resume(&client).await;

        shutdown_tx
            .send(true)
            .expect("request exact-resume shutdown");
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("exact-resume agent shutdown timeout")
            .expect("exact-resume agent task")
            .expect("exact-resume agent serve");
        node.shutdown().await.expect("exact-resume node shutdown");
    });
}

#[cfg(target_os = "linux")]
#[test]
fn real_node_finite_blob_upload_progress_survives_idle_bound_and_retries_from_zero() {
    const FRAME_LEN: usize = 64 * 1024;
    const TOTAL_LEN: u64 = 3 * FRAME_LEN as u64;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let state = TestState::new();
        let node = start_node(NodeConfig {
            state: state.0.clone(),
            bind: "127.0.0.1:0".parse().expect("mesh bind"),
            mission: blob_mission(),
            peers: Vec::new(),
            mutable_interests: MutableSourceInterests::default(),
            sync_interval: Duration::from_millis(50),
            run_for: None,
            application: NodeApplication::Relay,
        })
        .await
        .expect("start finite progress node");
        let agent = BoundAgent::bind("127.0.0.1:0".parse().expect("agent bind"))
            .await
            .expect("bind finite progress agent");
        let uri = format!("http://{}", agent.local_addr().expect("agent address"));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(
            agent
                .serve_with_blobs(
                    node.selected_events(),
                    node.selected_blobs(),
                    node.state_root().to_path_buf(),
                    ClientToken::from_bytes(TEST_TOKEN.to_vec()).expect("valid token"),
                    shutdown_rx,
                )
                .expect("construct finite progress service"),
        );
        let client = api::AsterApplicationServiceClient::new(
            Http2Connection::connect_plaintext(uri.parse().expect("transport URI"))
                .await
                .expect("connect finite progress HTTP/2")
                .shared(8),
            ClientConfig::new(uri.parse().expect("client URI"))
                .with_protocol(Protocol::Grpc)
                .with_default_timeout(Duration::from_secs(120))
                .with_default_header(
                    "authorization",
                    format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
                ),
        );
        let metadata = || api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                api::PublishBlobMetadata {
                    operation_key: b"finite-progress-retry".to_vec(),
                    topic: "imagery.maps".to_owned(),
                    scope: "mission/team/alpha".to_owned(),
                    priority: api::Priority::Routine.into(),
                    total_len: TOTAL_LEN,
                    ttl_ms: Some(600_000),
                    ..Default::default()
                },
            ))),
            ..Default::default()
        };
        let data = |index: u64| api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Data(Box::new(
                api::PublishBlobData {
                    offset: index * FRAME_LEN as u64,
                    bytes: vec![0x51 + index as u8; FRAME_LEN],
                    ..Default::default()
                },
            ))),
            ..Default::default()
        };
        let mut interrupted = client.publish_blob().await.expect("open finite upload");
        interrupted.send(metadata()).await.expect("send metadata");
        let accepted = interrupted
            .message::<api::PublishBlobResponse>()
            .await
            .expect("finite acceptance")
            .expect("acceptance frame")
            .to_owned_message();
        assert!(matches!(
            accepted.frame,
            Some(api::publish_blob_response::Frame::Accepted(ref accepted))
                if accepted.accepted_offset == 0 && accepted.durable_offset == 0
        ));
        let started = tokio::time::Instant::now();
        for index in 0..2 {
            // Break caught: inbound progress alone does not reset the response
            // idle timer. Advance only between completed I/O operations, then
            // resume real time so filesystem/network waits cannot auto-advance.
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(20)).await;
            tokio::time::resume();
            interrupted
                .send(data(index))
                .await
                .expect("send finite data");
            let progress = tokio::time::timeout(
                Duration::from_secs(5),
                interrupted.message::<api::PublishBlobResponse>(),
            )
            .await
            .expect("active finite upload must report progress")
            .expect("active finite upload must not time out")
            .expect("finite progress frame")
            .to_owned_message();
            let Some(api::publish_blob_response::Frame::Checkpoint(progress)) = progress.frame
            else {
                panic!("finite data must yield a checkpoint");
            };
            assert_eq!(progress.accepted_offset, (index + 1) * FRAME_LEN as u64);
            assert_eq!(
                progress.durable_offset, 0,
                "private staging is not resumable"
            );
        }
        assert!(started.elapsed() >= Duration::from_secs(40));
        drop(interrupted);

        let mut retry = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let mut call = client.publish_blob().await.expect("open finite retry");
                call.send(metadata()).await.expect("send retry metadata");
                match call.message::<api::PublishBlobResponse>().await {
                    Ok(Some(response)) => {
                        let response = response.to_owned_message();
                        assert!(matches!(
                            response.frame,
                            Some(api::publish_blob_response::Frame::Accepted(ref accepted))
                                if accepted.accepted_offset == 0 && accepted.durable_offset == 0
                        ));
                        break call;
                    }
                    Err(error) if error.code == ErrorCode::ResourceExhausted => {
                        tokio::task::yield_now().await;
                    }
                    other => panic!("unexpected finite retry acceptance: {other:?}"),
                }
            }
        })
        .await
        .expect("cancelled finite upload must release its staging permit");
        for index in 0..3 {
            retry.send(data(index)).await.expect("replay finite data");
            let progress = retry
                .message::<api::PublishBlobResponse>()
                .await
                .expect("replay progress")
                .expect("replay progress frame")
                .to_owned_message();
            let Some(api::publish_blob_response::Frame::Checkpoint(progress)) = progress.frame
            else {
                panic!("finite replay must yield a checkpoint");
            };
            assert_eq!(progress.accepted_offset, (index + 1) * FRAME_LEN as u64);
            assert_eq!(progress.durable_offset, 0);
        }
        retry
            .send(api::PublishBlobRequest {
                frame: Some(api::publish_blob_request::Frame::Finish(Box::default())),
                ..Default::default()
            })
            .await
            .expect("finish finite retry");
        retry.close_send();
        let complete = retry
            .message::<api::PublishBlobResponse>()
            .await
            .expect("finite retry completion")
            .expect("completion frame")
            .to_owned_message();
        let Some(api::publish_blob_response::Frame::Complete(complete)) = complete.frame else {
            panic!("finite retry must complete");
        };
        assert_eq!(complete.total_len, TOTAL_LEN);
        assert_eq!(complete.ttl_ms, Some(600_000));
        assert!(complete.inserted);
        assert!(
            retry
                .message::<api::PublishBlobResponse>()
                .await
                .unwrap()
                .is_none()
        );
        let mut read = client
            .read_blob(api::ReadBlobRequest {
                id: complete.id.clone(),
                topic: "imagery.maps".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                ..Default::default()
            })
            .await
            .expect("read finite retry");
        let mut observed = Vec::new();
        while let Some(page) = read.message().await.expect("finite read page") {
            observed.extend_from_slice(&page.to_owned_message().chunk);
        }
        let expected: Vec<_> = (0..3)
            .flat_map(|index| std::iter::repeat_n(0x51 + index, FRAME_LEN))
            .collect();
        assert_eq!(observed, expected);

        shutdown_tx.send(true).expect("request agent shutdown");
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("agent shutdown deadline")
            .expect("agent task")
            .expect("agent shutdown");
        node.shutdown().await.expect("node shutdown");
    });
}

#[cfg(target_os = "linux")]
#[test]
fn real_node_blob_publish_read_preserves_ttl_and_status_distinctions() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let state = TestState::new();
        let node = start_node(NodeConfig {
            state: state.0.clone(),
            bind: "127.0.0.1:0".parse().expect("mesh bind"),
            mission: blob_mission(),
            peers: Vec::new(),
            mutable_interests: MutableSourceInterests::default(),
            sync_interval: Duration::from_millis(50),
            run_for: None,
            application: NodeApplication::Relay,
        })
        .await
        .expect("start real selected node");
        let agent = BoundAgent::bind("127.0.0.1:0".parse().expect("agent bind"))
            .await
            .expect("bind agent");
        let address = agent.local_addr().expect("agent address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(
            agent
                .serve_with_blobs(
                    node.selected_events(),
                    node.selected_blobs(),
                    node.state_root().to_path_buf(),
                    ClientToken::from_bytes(TEST_TOKEN.to_vec()).expect("valid token"),
                    shutdown_rx,
                )
                .expect("construct combined Event/Blob service"),
        );
        let grpc = Http2Connection::connect_plaintext(
            format!("http://{address}")
                .parse()
                .expect("gRPC transport URI"),
        )
        .await
        .expect("connect gRPC HTTP/2 transport")
        .shared(8);
        let client = api::AsterApplicationServiceClient::new(
            grpc.clone(),
            ClientConfig::new(
                format!("http://{address}")
                    .parse()
                    .expect("gRPC client URI"),
            )
            .with_protocol(Protocol::Grpc)
            .with_default_header(
                "authorization",
                format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
            ),
        );

        macro_rules! publish_frames {
            ($client:expr, $frames:expr) => {{
                async {
                    let mut call = $client.publish_blob().await?;
                    let mut durable_offset = 0_u64;
                    for (index, mut frame) in ($frames).into_iter().enumerate() {
                        let declared_len = match frame.frame.as_ref() {
                            Some(api::publish_blob_request::Frame::Metadata(metadata))
                                if index == 0 =>
                            {
                                Some(metadata.total_len)
                            }
                            _ => None,
                        };
                        if let Some(total_len) = declared_len {
                            call.send(frame).await?;
                            let response = call
                                .message::<api::PublishBlobResponse>()
                                .await?
                                .ok_or_else(|| {
                                    ConnectError::data_loss("missing Blob acceptance")
                                })?;
                            let Some(api::publish_blob_response::Frame::Accepted(accepted)) =
                                response.to_owned_message().frame
                            else {
                                return Err(ConnectError::data_loss("expected Blob acceptance"));
                            };
                            assert_eq!(accepted.accepted_offset, accepted.durable_offset);
                            assert!(accepted.durable_offset <= total_len);
                            durable_offset = accepted.durable_offset;
                            continue;
                        }
                        // Retry starts at Store-authoritative durable progress.
                        // A completed operation sends Finish without replaying
                        // payload; malformed fresh frames still reach the server.
                        if let Some(api::publish_blob_request::Frame::Data(data)) = &mut frame.frame
                            && data.offset < durable_offset
                        {
                            let skip =
                                usize::try_from(durable_offset - data.offset).unwrap_or(usize::MAX);
                            if skip >= data.bytes.len() {
                                continue;
                            }
                            drop(data.bytes.drain(..skip));
                            data.offset = durable_offset;
                        }
                        call.send(frame).await?;
                    }
                    call.send(api::PublishBlobRequest {
                        frame: Some(api::publish_blob_request::Frame::Finish(Box::default())),
                        ..Default::default()
                    })
                    .await?;
                    call.close_send();
                    let mut receipt = None;
                    while let Some(response) = call.message::<api::PublishBlobResponse>().await? {
                        if let Some(api::publish_blob_response::Frame::Complete(complete)) =
                            response.to_owned_message().frame
                        {
                            receipt = Some(*complete);
                        }
                    }
                    receipt.ok_or_else(|| ConnectError::data_loss("missing Blob completion"))
                }
                .await
            }};
        }

        let pending_upload_metadata = |key: &[u8]| api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                api::PublishBlobMetadata {
                    operation_key: key.to_vec(),
                    topic: "imagery.maps".to_owned(),
                    scope: "mission/team/alpha".to_owned(),
                    priority: api::Priority::Routine.into(),
                    total_len: 1,
                    ..Default::default()
                },
            ))),
            ..Default::default()
        };
        let one_byte_upload = |key: &[u8], declared_len: u64| {
            vec![
                api::PublishBlobRequest {
                    frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                        api::PublishBlobMetadata {
                            operation_key: key.to_vec(),
                            topic: "imagery.maps".to_owned(),
                            scope: "mission/team/alpha".to_owned(),
                            priority: api::Priority::Routine.into(),
                            total_len: declared_len,
                            ..Default::default()
                        },
                    ))),
                    ..Default::default()
                },
                api::PublishBlobRequest {
                    frame: Some(api::publish_blob_request::Frame::Data(Box::new(
                        api::PublishBlobData {
                            offset: 0,
                            bytes: vec![0x31],
                            ..Default::default()
                        },
                    ))),
                    ..Default::default()
                },
            ]
        };
        let cancelled_polled = Arc::new(tokio::sync::Notify::new());
        let cancelled_client = client.clone();
        let cancelled_metadata = pending_upload_metadata(b"real-node-blob-cancelled");
        let cancelled_ready = Arc::clone(&cancelled_polled);
        let cancelled = tokio::spawn(async move {
            let mut call = cancelled_client.publish_blob().await?;
            call.send(cancelled_metadata).await?;
            let _ = call.message::<api::PublishBlobResponse>().await?;
            cancelled_ready.notify_one();
            futures::future::pending::<()>().await;
            Ok::<(), ConnectError>(())
        });
        tokio::time::timeout(Duration::from_secs(2), cancelled_polled.notified())
            .await
            .expect("pending cancellation upload received acceptance");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let probe =
                    publish_frames!(client, one_byte_upload(b"real-node-capacity-probe", 2))
                        .expect_err("capacity probe is intentionally short");
                if probe.code == ErrorCode::ResourceExhausted {
                    break;
                }
                assert_eq!(probe.code, ErrorCode::InvalidArgument);
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pending upload acquired server staging and the singleton permit");
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        let recovered_cancelled = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match publish_frames!(client, one_byte_upload(b"real-node-blob-cancelled", 1)) {
                    Ok(response) => break response,
                    Err(error) if error.code == ErrorCode::ResourceExhausted => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("cancel recovery failed: {error:?}"),
                }
            }
        })
        .await
        .expect("cancellation releases staging and capacity after cleanup");
        assert!(recovered_cancelled.inserted);

        let deadline_client = api::AsterApplicationServiceClient::new(
            grpc,
            ClientConfig::new(
                format!("http://{address}")
                    .parse()
                    .expect("deadline client URI"),
            )
            .with_protocol(Protocol::Grpc)
            .with_default_timeout(Duration::from_millis(10))
            .with_default_header(
                "authorization",
                format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
            ),
        );
        let deadline_metadata = pending_upload_metadata(b"real-node-blob-deadline");
        let deadline_task = tokio::spawn(async move {
            let mut call = deadline_client.publish_blob().await?;
            call.send(deadline_metadata).await?;
            let _ = call.message::<api::PublishBlobResponse>().await?;
            call.message::<api::PublishBlobResponse>().await
        });
        // The 10ms deadline may expire before the first Accepted response.
        // Await the task directly so either response can report that deadline;
        // a notification sent only after Accepted could otherwise hang here.
        let deadline = tokio::time::timeout(Duration::from_secs(2), deadline_task)
            .await
            .expect("incomplete upload reached its client deadline")
            .expect("deadline request task")
            .expect_err("an incomplete upload must obey the client deadline");
        assert_eq!(deadline.code, ErrorCode::DeadlineExceeded);
        // The client observes its deadline before the server necessarily
        // drops the response stream and the actor processes ClosePublishStream.
        // Prove that cleanup releases both admission layers before testing an
        // unrelated transport rejection; a leak must still fail within 2s.
        let recovered_deadline = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match publish_frames!(client, one_byte_upload(b"real-node-blob-deadline", 1)) {
                    Ok(response) => break response,
                    Err(error) if error.code == ErrorCode::ResourceExhausted => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("deadline recovery failed: {error:?}"),
                }
            }
        })
        .await
        .expect("deadline releases staging and capacity after cleanup");
        assert!(recovered_deadline.inserted);

        let grpc_web_client = api::AsterApplicationServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(
                format!("http://{address}")
                    .parse()
                    .expect("gRPC-Web client URI"),
            )
            .with_protocol(Protocol::GrpcWeb)
            .with_default_header(
                "authorization",
                format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
            ),
        );
        let grpc_web_frames = vec![
            api::PublishBlobRequest {
                frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                    api::PublishBlobMetadata {
                        operation_key: b"grpc-web-rejected-blob".to_vec(),
                        topic: "imagery.maps".to_owned(),
                        scope: "mission/team/alpha".to_owned(),
                        priority: api::Priority::Routine.into(),
                        total_len: 1,
                        ..Default::default()
                    },
                ))),
                ..Default::default()
            },
            api::PublishBlobRequest {
                frame: Some(api::publish_blob_request::Frame::Data(Box::new(
                    api::PublishBlobData {
                        offset: 0,
                        bytes: vec![0x44],
                        ..Default::default()
                    },
                ))),
                ..Default::default()
            },
        ];
        let grpc_web_error = publish_frames!(grpc_web_client, grpc_web_frames.clone())
            .expect_err("gRPC-Web request streaming must be rejected");
        assert_public_reason(
            &grpc_web_error,
            ErrorCode::Unimplemented,
            api::PublicErrorReason::UnsupportedValue,
            "publish_blob",
        );
        let after_grpc_web = publish_frames!(client, grpc_web_frames)
            .expect("gRPC-Web rejection must not mutate Blob state");
        assert!(after_grpc_web.inserted);

        // Read frames are bounded at 1 MiB independently of the 64 KiB
        // upload grammar. Cross that boundary to retain a real two-page read.
        let payload = vec![0x5a; 1024 * 1024 + 3];
        let metadata = api::PublishBlobMetadata {
            operation_key: b"real-node-blob-durable".to_vec(),
            topic: "imagery.maps".to_owned(),
            scope: "mission/team/alpha".to_owned(),
            priority: api::Priority::Immediate.into(),
            media_type: Some("application/octet-stream".to_owned()),
            schema_id: b"schema/blob-v1".to_vec(),
            total_len: payload.len() as u64,
            ttl_ms: None,
            ..Default::default()
        };
        let mut frames = vec![api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                metadata.clone(),
            ))),
            ..Default::default()
        }];
        frames.extend(payload.chunks(65_536).enumerate().map(|(index, bytes)| {
            api::PublishBlobRequest {
                frame: Some(api::publish_blob_request::Frame::Data(Box::new(
                    api::PublishBlobData {
                        offset: (index * 65_536) as u64,
                        bytes: bytes.to_vec(),
                        ..Default::default()
                    },
                ))),
                ..Default::default()
            }
        }));
        let published = publish_frames!(client, frames.clone()).expect("publish durable Blob");
        assert!(published.inserted);
        assert_eq!(published.ttl_ms, None);
        assert_eq!(published.total_len, payload.len() as u64);
        let retried = publish_frames!(client, frames).expect("retry durable Blob");
        assert!(!retried.inserted);
        assert_eq!(retried.id, published.id);
        assert_eq!(retried.ttl_ms, None);

        let mut pages = client
            .read_blob(api::ReadBlobRequest {
                id: published.id.clone(),
                topic: "imagery.maps".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                ..Default::default()
            })
            .await
            .expect("start multi-page Blob read");
        let mut observed = Vec::new();
        let mut offsets = Vec::new();
        while let Some(page) = pages.message().await.expect("read Blob page") {
            let page = page.to_owned_message();
            assert_eq!(page.id, published.id);
            assert_eq!(page.publisher, published.publisher);
            assert_eq!(page.publisher_counter, published.publisher_counter);
            assert_eq!(page.topic, "imagery.maps");
            assert_eq!(page.scope, "mission/team/alpha");
            assert_eq!(page.priority, api::Priority::Immediate);
            assert_eq!(page.ttl_ms, None);
            assert_eq!(page.total_len, payload.len() as u64);
            assert_eq!(page.media_type.as_deref(), Some("application/octet-stream"));
            assert_eq!(page.schema_id, b"schema/blob-v1");
            assert_eq!(page.acceptance_marker, published.acceptance_marker);
            assert_eq!(page.offset, observed.len() as u64);
            assert!(!page.chunk.is_empty() && page.chunk.len() <= 1024 * 1024);
            offsets.push(page.offset);
            observed.extend_from_slice(&page.chunk);
            if page.complete {
                break;
            }
        }
        assert_eq!(offsets, [0, 1024 * 1024]);
        assert_eq!(observed, payload);

        let metadata_frame = |key: &[u8], total_len| api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                api::PublishBlobMetadata {
                    operation_key: key.to_vec(),
                    topic: "imagery.maps".to_owned(),
                    scope: "mission/team/alpha".to_owned(),
                    priority: api::Priority::Routine.into(),
                    total_len,
                    ..Default::default()
                },
            ))),
            ..Default::default()
        };
        let chunk_frame = |bytes| api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Data(Box::new(
                api::PublishBlobData {
                    offset: 0,
                    bytes,
                    ..Default::default()
                },
            ))),
            ..Default::default()
        };
        let malformed_cases = vec![
            (
                "missing-frame",
                vec![api::PublishBlobRequest::default()],
                ErrorCode::InvalidArgument,
                api::PublicErrorReason::MalformedInput,
                None,
            ),
            (
                "over-policy",
                vec![metadata_frame(
                    b"real-node-blob-over-policy",
                    node.selected_blobs()
                        .max_publish_bytes()
                        .checked_add(1)
                        .expect("bounded publication policy"),
                )],
                ErrorCode::ResourceExhausted,
                api::PublicErrorReason::ResourceExhaustion,
                Some(b"real-node-blob-over-policy".as_slice()),
            ),
            (
                "short",
                vec![
                    metadata_frame(b"real-node-blob-short", 2),
                    chunk_frame(vec![1]),
                ],
                ErrorCode::InvalidArgument,
                api::PublicErrorReason::MalformedInput,
                Some(b"real-node-blob-short".as_slice()),
            ),
            (
                "long",
                vec![
                    metadata_frame(b"real-node-blob-long", 1),
                    chunk_frame(vec![1, 2]),
                ],
                ErrorCode::InvalidArgument,
                api::PublicErrorReason::MalformedInput,
                Some(b"real-node-blob-long".as_slice()),
            ),
            (
                "reordered",
                vec![chunk_frame(vec![1])],
                ErrorCode::InvalidArgument,
                api::PublicErrorReason::MalformedInput,
                None,
            ),
        ];
        for (label, frames, code, reason, rejected_key) in malformed_cases {
            let error = publish_frames!(client, frames).expect_err(label);
            assert_public_reason_with_retryability(
                &error,
                code,
                reason,
                "publish_blob",
                reason == api::PublicErrorReason::ResourceExhaustion,
            );

            let recovery_key = rejected_key
                .map(<[u8]>::to_vec)
                .unwrap_or_else(|| format!("real-node-recovery-{label}").into_bytes());
            // The short upload already accepted metadata for two bytes. Its
            // resumable operation retains that exact declaration after failure.
            // Over-policy metadata was rejected before admission; long declared
            // one byte, and missing/reordered metadata creates no operation.
            let recovery_len = if label == "short" { 2 } else { 1 };
            let recovery_payload = vec![0x41; recovery_len as usize];
            // A grammar error drops the stream and queues actor cleanup. Its
            // error trailer can arrive before that cleanup releases admission.
            let recovered = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match publish_frames!(
                        client,
                        [
                            metadata_frame(&recovery_key, recovery_len),
                            chunk_frame(recovery_payload.clone())
                        ]
                    ) {
                        Ok(receipt) => break receipt,
                        Err(error) if error.code == ErrorCode::ResourceExhausted => {
                            tokio::task::yield_now().await;
                        }
                        Err(error) => panic!("{label} recovery failed: {error:?}"),
                    }
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{label} rejection must release capacity within 2s"));
            assert!(recovered.inserted);
            assert_eq!(recovered.total_len, recovery_len);
            let retry = publish_frames!(
                client,
                [
                    metadata_frame(&recovery_key, recovery_len),
                    chunk_frame(recovery_payload)
                ]
            )
            .expect("exact-key recovery must remain idempotent");
            assert!(!retry.inserted);
            assert_eq!(retry.id, recovered.id);
            assert_eq!(retry.acceptance_marker, recovered.acceptance_marker);
        }
        assert!(
            fs::read_dir(&state.0)
                .expect("inspect state root")
                .all(|entry| !entry
                    .expect("state entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".aster-agent-blob-upload-")),
            "Blob staging names must be unlinked before payload custody"
        );

        let finite_payload = b"finite-blob".to_vec();
        let finite = publish_frames!(
            client,
            [
                api::PublishBlobRequest {
                    frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                        api::PublishBlobMetadata {
                            operation_key: b"real-node-blob-finite".to_vec(),
                            topic: "imagery.maps".to_owned(),
                            scope: "mission/team/alpha".to_owned(),
                            priority: api::Priority::Priority.into(),
                            media_type: Some("application/octet-stream".to_owned()),
                            schema_id: b"schema/blob-v1".to_vec(),
                            total_len: finite_payload.len() as u64,
                            ttl_ms: Some(1_000),
                            ..Default::default()
                        },
                    ))),
                    ..Default::default()
                },
                api::PublishBlobRequest {
                    frame: Some(api::publish_blob_request::Frame::Data(Box::new(
                        api::PublishBlobData {
                            offset: 0,
                            bytes: finite_payload,
                            ..Default::default()
                        },
                    ))),
                    ..Default::default()
                },
            ]
        )
        .expect("publish finite Blob");
        assert_eq!(finite.ttl_ms, Some(1_000));
        tokio::time::sleep(Duration::from_millis(1_100)).await;

        let mut expired = client
            .read_blob(api::ReadBlobRequest {
                id: finite.id,
                topic: "imagery.maps".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                ..Default::default()
            })
            .await
            .expect("start expired read stream");
        let expired = expired
            .message()
            .await
            .expect_err("recently expired Blob must fail");
        assert_public_reason(
            &expired,
            ErrorCode::NotFound,
            api::PublicErrorReason::ExpiredOrRetired,
            "read_blob",
        );

        let mut missing = client
            .read_blob(api::ReadBlobRequest {
                id: vec![0xee; 32],
                topic: "imagery.maps".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                ..Default::default()
            })
            .await
            .expect("start never-observed read stream");
        let missing = missing
            .message()
            .await
            .expect_err("never-observed Blob must fail");
        assert_public_reason(
            &missing,
            ErrorCode::NotFound,
            api::PublicErrorReason::MissingDurableObject,
            "read_blob",
        );

        shutdown_tx.send(true).expect("request shutdown");
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("agent shutdown timeout")
            .expect("agent task")
            .expect("agent serve");
        node.shutdown().await.expect("node shutdown");
    });
}

#[test]
fn connect_client_uses_the_real_live_event_authority() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let state = TestState::new();
        let mission = UnprotectedReferenceMission::from_bytes(
            include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle")
                .to_vec(),
        )
        .expect("load disposable public test mission");
        let node = start_node(NodeConfig {
            state: state.0.clone(),
            bind: "127.0.0.1:0".parse().expect("mesh bind"),
            mission,
            peers: Vec::new(),
            mutable_interests: MutableSourceInterests::default(),
            sync_interval: Duration::from_millis(50),
            run_for: None,
            application: NodeApplication::Relay,
        })
        .await
        .expect("start real selected node");

        let agent = BoundAgent::bind("127.0.0.1:0".parse().expect("agent bind"))
            .await
            .expect("bind agent");
        let address = agent.local_addr().expect("agent address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let token = ClientToken::from_bytes(TEST_TOKEN.to_vec()).expect("valid test token");
        let server = tokio::spawn(agent.serve(node.selected_events(), token, shutdown_rx));

        let unauthenticated_client = api::AsterApplicationServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(format!("http://{address}").parse().expect("agent base URI")),
        );
        let error = unauthenticated_client
            .get_status(api::GetStatusRequest::default())
            .await
            .expect_err("missing credentials must fail");
        assert_authentication_error(&error, api::PublicErrorDetail::FULL_NAME);
        let mut unauthenticated_stream = unauthenticated_client
            .stream_events(api::StreamEventsRequest {
                subscription_id: vec![0; 32],
                delivery_limit: 1,
                scan_limit: 1,
                poll_backoff_ms: 250,
                ..Default::default()
            })
            .await
            .expect("stream response carries protocol error");
        let stream_error = unauthenticated_stream
            .message()
            .await
            .expect_err("missing streaming credentials must fail");
        assert_authentication_error(&stream_error, api::PublicErrorDetail::FULL_NAME);

        let base_uri = format!("http://{address}");
        let unauthenticated_grpc_web = api::AsterApplicationServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(base_uri.parse().expect("gRPC-Web client URI"))
                .with_protocol(Protocol::GrpcWeb),
        );
        let error = unauthenticated_grpc_web
            .get_status(api::GetStatusRequest::default())
            .await
            .expect_err("missing gRPC-Web credentials must fail");
        assert_authentication_error(&error, api::PublicErrorDetail::TYPE_URL);

        let grpc =
            Http2Connection::connect_plaintext(base_uri.parse().expect("gRPC transport URI"))
                .await
                .expect("connect gRPC HTTP/2 transport")
                .shared(32);
        let unauthenticated_grpc = api::AsterApplicationServiceClient::new(
            grpc.clone(),
            ClientConfig::new(base_uri.parse().expect("unauthenticated gRPC client URI"))
                .with_protocol(Protocol::Grpc),
        );
        let error = unauthenticated_grpc
            .get_status(api::GetStatusRequest::default())
            .await
            .expect_err("missing gRPC credentials must fail");
        assert_authentication_error(&error, api::PublicErrorDetail::TYPE_URL);

        let client = api::AsterApplicationServiceClient::new(
            grpc,
            ClientConfig::new(base_uri.parse().expect("gRPC client URI"))
                .with_protocol(Protocol::Grpc)
                .with_default_header(
                    "authorization",
                    format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
                ),
        );
        let status = client
            .get_status(api::GetStatusRequest::default())
            .await
            .expect("read real status")
            .into_owned();
        assert_eq!(status.identity.len(), 32);
        assert_eq!(status.mission_authority.len(), 32);
        assert!(status.credential_generation.is_empty());

        // Exercise the generated Connect client with authentication as well as
        // the gRPC client above. Borrow actual Aster fields before consuming
        // the response into an independently owned message.
        let connect_client = api::AsterApplicationServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(base_uri.parse().expect("Connect client URI"))
                .with_protocol(Protocol::Connect)
                .with_default_header(
                    "authorization",
                    format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
                ),
        );
        let response = connect_client
            .get_status(api::GetStatusRequest::default())
            .await
            .expect("read status over authenticated Connect");
        {
            let view = response.view();
            let identity: &[u8] = view.identity;
            let authority: &[u8] = view.mission_authority;
            assert_eq!(identity, status.identity);
            assert_eq!(authority, status.mission_authority);
            assert!(view.credential_generation.is_empty());
        }
        let owned: api::GetStatusResponse = response.into_owned();
        drop(connect_client);
        assert_eq!(owned.identity, status.identity);
        assert_eq!(owned.mission_authority, status.mission_authority);
        assert!(owned.credential_generation.is_empty());

        // Tracer exercises the real route independently of generated types.
        {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let mut stream = tokio::net::TcpStream::connect(address).await.expect("connect");
            let request = format!("POST /aster.application.v1alpha1.AsterApplicationService/ListEventSubscriptions HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nConnect-Protocol-Version: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}", String::from_utf8_lossy(TEST_TOKEN));
            stream.write_all(request.as_bytes()).await.expect("write request");
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.expect("read response");
            let response = String::from_utf8(bytes).expect("HTTP JSON");
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        }

        let subscription = client
            .create_event_subscription(api::CreateEventSubscriptionRequest {
                operation_key: b"connect-real-subscription".to_vec(),
                topic: "chat.events".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                include_descendant_scopes: false,
                ..Default::default()
            })
            .await
            .expect("create durable subscription")
            .into_owned();
        assert!(subscription.inserted);
        let listed = client.list_event_subscriptions(api::ListEventSubscriptionsRequest::default()).await.expect("list subscriptions").into_owned();
        assert_eq!(listed.subscriptions.len(), 1);
        let row = &listed.subscriptions[0];
        assert_eq!(row.subscription_id, subscription.subscription_id);
        assert_eq!(row.operation_key, b"connect-real-subscription");
        assert_eq!(row.topic, "chat.events");
        assert_eq!(row.scope, "mission/team/alpha");
        assert!(!row.include_descendant_scopes);

        let published = client
            .publish_event(api::PublishEventRequest {
                operation_key: b"connect-real-publication".to_vec(),
                topic: "chat.events".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                priority: api::Priority::Immediate.into(),
                logical_key: b"message-1".to_vec(),
                payload: b"offline-first through ConnectRPC".to_vec(),
                ..Default::default()
            })
            .await
            .expect("publish through ConnectRPC")
            .into_owned();
        assert!(published.inserted);
        assert_eq!(published.id.len(), 32);

        let page = client
            .poll_events(api::PollEventsRequest {
                subscription_id: subscription.subscription_id.clone(),
                delivery_limit: 8,
                scan_limit: 32,
                ..Default::default()
            })
            .await
            .expect("poll through ConnectRPC")
            .into_owned();
        assert_eq!(page.deliveries.len(), 1);
        let event = page.deliveries[0]
            .event
            .as_option()
            .expect("delivery event");
        assert_eq!(event.id, published.id);
        assert_eq!(event.payload, b"offline-first through ConnectRPC");
        assert_eq!(page.deliveries[0].attempt, 1);

        let acknowledgement = client
            .acknowledge_event(api::AcknowledgeEventRequest {
                subscription_id: subscription.subscription_id.clone(),
                event_id: published.id,
                ..Default::default()
            })
            .await
            .expect("acknowledge through ConnectRPC")
            .into_owned();
        assert!(!acknowledgement.already_acknowledged);

        let mut stream = client
            .stream_events(api::StreamEventsRequest {
                subscription_id: subscription.subscription_id.clone(),
                delivery_limit: 8,
                scan_limit: 32,
                poll_backoff_ms: 250,
                ..Default::default()
            })
            .await
            .expect("start durable delivery stream");
        let streamed_publication = client
            .publish_event(api::PublishEventRequest {
                operation_key: b"connect-stream-publication".to_vec(),
                topic: "chat.events".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                priority: api::Priority::Routine.into(),
                logical_key: b"message-2".to_vec(),
                payload: b"streamed without implicit acknowledgement".to_vec(),
                ..Default::default()
            })
            .await
            .expect("publish for stream")
            .into_owned();
        let streamed = tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .expect("stream delivery timeout")
            .expect("stream protocol")
            .expect("stream delivery")
            .to_owned_message();
        assert_eq!(streamed.attempt, 1);
        assert_eq!(
            streamed.event.as_option().expect("streamed event").id,
            streamed_publication.id
        );
        drop(stream);

        let redelivery = client
            .poll_events(api::PollEventsRequest {
                subscription_id: subscription.subscription_id.clone(),
                delivery_limit: 8,
                scan_limit: 32,
                ..Default::default()
            })
            .await
            .expect("poll unacknowledged streamed delivery")
            .into_owned();
        assert_eq!(redelivery.deliveries.len(), 1);
        assert_eq!(redelivery.deliveries[0].attempt, 2);
        assert_eq!(
            redelivery.deliveries[0]
                .event
                .as_option()
                .expect("redelivered event")
                .id,
            streamed_publication.id
        );
        client
            .acknowledge_event(api::AcknowledgeEventRequest {
                subscription_id: subscription.subscription_id,
                event_id: streamed_publication.id,
                ..Default::default()
            })
            .await
            .expect("acknowledge redelivery");

        let pipelined = PipelinedEventPublisher::new(client.clone(), 1)
            .publish_all(
                (0_u8..2)
                    .map(|suffix| api::PublishEventRequest {
                        operation_key: format!("real-node-pipelined/{suffix}").into_bytes(),
                        topic: "chat.events".to_owned(),
                        scope: "mission/team/alpha".to_owned(),
                        priority: api::Priority::Routine.into(),
                        logical_key: vec![suffix],
                        payload: vec![suffix],
                        ..Default::default()
                    })
                    .collect(),
            )
            .await
            .expect("publish pipelined Events through the real agent");
        assert_eq!(pipelined.len(), 2);
        assert!(pipelined.into_iter().all(|response| matches!(
            response.outcome,
            Some(api::publish_events_response::Outcome::Published(_))
        )));

        shutdown_tx.send(true).expect("request agent shutdown");
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("agent shutdown timeout")
            .expect("agent task")
            .expect("agent serve");
        node.shutdown().await.expect("node shutdown");
    });
}

#[tokio::test]
async fn query_filters_preserve_scan_cursors_across_empty_rpc_pages() {
    let state = TestState::new();
    let mission = UnprotectedReferenceMission::from_bytes(
        include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle").to_vec(),
    )
    .unwrap();
    let node = start_node(NodeConfig {
        state: state.0.clone(),
        bind: "127.0.0.1:0".parse().unwrap(),
        mission,
        peers: Vec::new(),
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: Duration::from_millis(50),
        run_for: None,
        application: NodeApplication::Relay,
    })
    .await
    .unwrap();
    let agent = BoundAgent::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = agent.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(agent.serve(
        node.selected_events(),
        ClientToken::from_bytes(TEST_TOKEN.to_vec()).unwrap(),
        shutdown_rx,
    ));
    let client = api::AsterApplicationServiceClient::new(
        HttpClient::plaintext(),
        ClientConfig::new(format!("http://{address}").parse().unwrap()).with_default_header(
            "authorization",
            format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
        ),
    );
    let publisher = client
        .get_status(api::GetStatusRequest::default())
        .await
        .unwrap()
        .into_owned()
        .identity;
    let empty = client
        .query_events(api::QueryEventsRequest {
            limit: 2,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned();
    assert!(empty.events.is_empty());
    assert_eq!(empty.scanned_through, 0);
    assert!(!empty.has_more);
    let mut published = Vec::new();
    for index in 1..=7 {
        published.push(
            client
                .publish_event(api::PublishEventRequest {
                    operation_key: format!("query/{index}").into_bytes(),
                    topic: "chat.events".to_owned(),
                    scope: "mission/team/alpha".to_owned(),
                    priority: api::Priority::Routine.into(),
                    logical_key: if index == 3 || index == 6 {
                        b"target".to_vec()
                    } else {
                        b"other".to_vec()
                    },
                    payload: format!("payload {index}").into_bytes(),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_owned()
                .id,
        );
    }
    // Decode field 8 directly to pin its wire number and exercise forwarding
    // through the client's protobuf encoder and the real HTTP service.
    let mut bounded = api::QueryEventsRequest::decode_from_slice(&[0x40, 4]).unwrap();
    bounded.limit = 8;
    let page = client.query_events(bounded).await.unwrap().into_owned();
    assert_eq!(
        page.events
            .iter()
            .map(|event| event.acceptance_marker)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(page.scanned_through, 3);
    assert!(!page.has_more);

    for (after, before) in [(0, 0), (0, 1), (3, 3), (4, 2), (u64::MAX, u64::MAX)] {
        let page = client
            .query_events(api::QueryEventsRequest {
                after_acceptance_marker: after,
                before_acceptance_marker: Some(before),
                limit: 2,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert!(page.events.is_empty(), "after={after}, before={before}");
        assert_eq!(page.scanned_through, after);
        assert!(!page.has_more);
    }

    // Combined exclusive bounds, a full final page, and filters that return
    // empty pages must all stop at the upper bound, not the store high-water.
    for (after, before, key, expected, scanned, more) in [
        (1, 4, None, vec![2, 3], 3, false),
        (1, 5, None, vec![2, 3], 3, true),
        (3, 5, None, vec![4], 4, false),
        (1, 5, Some(b"absent".to_vec()), vec![], 3, true),
        (3, 5, Some(b"absent".to_vec()), vec![], 4, false),
        (1, 4, Some(b"target".to_vec()), vec![3], 3, false),
        (6, 8, None, vec![7], 7, false),
        (6, u64::MAX, None, vec![7], 7, false),
        (u64::MAX, u64::MAX, None, vec![], u64::MAX, false),
    ] {
        let page = client
            .query_events(api::QueryEventsRequest {
                publisher: Some(publisher.clone()),
                topic: Some("chat.events".to_owned()),
                scope: Some("mission/team".to_owned()),
                include_descendant_scopes: true,
                logical_key: key,
                after_acceptance_marker: after,
                before_acceptance_marker: Some(before),
                limit: 2,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(
            page.events
                .iter()
                .map(|event| event.acceptance_marker)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(page.scanned_through, scanned);
        assert_eq!(page.has_more, more);
    }

    for (key, expected_pages) in [
        (None, vec![vec![1, 2], vec![3, 4], vec![5, 6], vec![7]]),
        (
            Some(b"absent".to_vec()),
            vec![vec![], vec![], vec![], vec![]],
        ),
        (
            Some(b"target".to_vec()),
            vec![vec![], vec![3], vec![6], vec![]],
        ),
    ] {
        let mut cursor = 0;
        for (page_index, expected) in expected_pages.into_iter().enumerate() {
            let page = client
                .query_events(api::QueryEventsRequest {
                    // Test the completely unfiltered path too. On selective paths,
                    // combine every RPC field and an ancestor scope.
                    publisher: key.as_ref().map(|_| publisher.clone()),
                    topic: key.as_ref().map(|_| "chat.events".to_owned()),
                    scope: key.as_ref().map(|_| "mission/team".to_owned()),
                    include_descendant_scopes: key.is_some(),
                    logical_key: key.clone(),
                    after_acceptance_marker: cursor,
                    limit: 2,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_owned();
            assert_eq!(
                page.events
                    .iter()
                    .map(|event| event.acceptance_marker)
                    .collect::<Vec<_>>(),
                expected
            );
            for event in &page.events {
                assert_eq!(event.id, published[event.acceptance_marker as usize - 1]);
                assert_eq!(
                    event.payload,
                    format!("payload {}", event.acceptance_marker).as_bytes()
                );
            }
            assert_eq!(page.scanned_through, [2, 4, 6, 7][page_index]);
            assert_eq!(page.has_more, page_index < 3);
            cursor = page.scanned_through;
        }
        let terminal = client
            .query_events(api::QueryEventsRequest {
                logical_key: key,
                after_acceptance_marker: cursor,
                limit: 2,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert!(terminal.events.is_empty());
        assert_eq!(terminal.scanned_through, 7);
        assert!(!terminal.has_more);
    }
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn subscription_listing_survives_restart_with_binary_keys_and_distinct_selectors() {
    let state = TestState::new();
    let mut expected = Vec::new();
    for generation in 0..2 {
        let mission = UnprotectedReferenceMission::from_bytes(
            include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle")
                .to_vec(),
        )
        .unwrap();
        let node = start_node(NodeConfig {
            state: state.0.clone(),
            bind: "127.0.0.1:0".parse().unwrap(),
            mission,
            peers: Vec::new(),
            mutable_interests: MutableSourceInterests::default(),
            sync_interval: Duration::from_millis(50),
            run_for: None,
            application: NodeApplication::Relay,
        })
        .await
        .unwrap();
        let agent = BoundAgent::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = agent.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(agent.serve(
            node.selected_events(),
            ClientToken::from_bytes(TEST_TOKEN.to_vec()).unwrap(),
            shutdown_rx,
        ));
        let client = api::AsterApplicationServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(format!("http://{address}").parse().unwrap()).with_default_header(
                "authorization",
                format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
            ),
        );
        let unauthenticated = api::AsterApplicationServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(format!("http://{address}").parse().unwrap()),
        );
        let error = unauthenticated
            .list_event_subscriptions(api::ListEventSubscriptionsRequest::default())
            .await
            .unwrap_err();
        assert_authentication_error(&error, api::PublicErrorDetail::FULL_NAME);
        let before = client
            .list_event_subscriptions(api::ListEventSubscriptionsRequest::default())
            .await
            .unwrap()
            .into_owned();
        assert_eq!(before.subscriptions, expected);
        if generation == 0 {
            for key in [
                vec![0xff, 0, 0x80],
                vec![0xfe; aster_redb_store::MAX_EVENT_SUBSCRIPTION_KEY_BYTES],
                vec![0xfd, 0],
            ] {
                let request = api::CreateEventSubscriptionRequest {
                    operation_key: key.clone(),
                    topic: "chat.events".to_owned(),
                    scope: "mission/team/alpha".to_owned(),
                    include_descendant_scopes: true,
                    ..Default::default()
                };
                let created = client
                    .create_event_subscription(request.clone())
                    .await
                    .unwrap()
                    .into_owned();
                let replay = client
                    .create_event_subscription(request)
                    .await
                    .unwrap()
                    .into_owned();
                assert!(!replay.inserted);
                assert_eq!(replay.subscription_id, created.subscription_id);
                expected.push(api::EventSubscription {
                    subscription_id: created.subscription_id,
                    topic: "chat.events".to_owned(),
                    scope: "mission/team/alpha".to_owned(),
                    include_descendant_scopes: true,
                    operation_key: key,
                    ..Default::default()
                });
            }
            expected.sort_by(|a, b| a.subscription_id.cmp(&b.subscription_id));
        } else {
            let removed = expected.remove(1);
            client
                .delete_event_subscription(api::DeleteEventSubscriptionRequest {
                    subscription_id: removed.subscription_id,
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        for _ in 0..2 {
            assert_eq!(
                client
                    .list_event_subscriptions(api::ListEventSubscriptionsRequest::default())
                    .await
                    .unwrap()
                    .into_owned()
                    .subscriptions,
                expected
            );
        }
        let json_client = api::AsterApplicationServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(format!("http://{address}").parse().unwrap())
                .with_protocol(Protocol::Connect)
                .with_codec_format(connectrpc::CodecFormat::Json)
                .with_default_header(
                    "authorization",
                    format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
                ),
        );
        assert_eq!(
            json_client
                .list_event_subscriptions(api::ListEventSubscriptionsRequest::default())
                .await
                .unwrap()
                .into_owned()
                .subscriptions,
            expected,
            "populated JSON response must preserve arbitrary binary operation keys"
        );
        let handle = node.selected_events();
        node.shutdown().await.unwrap();
        let error = json_client
            .list_event_subscriptions(api::ListEventSubscriptionsRequest::default())
            .await
            .expect_err("closed actor must reject this RPC, not return an empty list");
        assert_eq!(error.code, ErrorCode::Unavailable);
        shutdown_tx.send(true).unwrap();
        server.await.unwrap().unwrap();
        assert!(
            handle.list_subscriptions().await.is_err(),
            "closed actor must not return an empty success"
        );
    }
}

#[tokio::test]
async fn optional_event_ttl_is_enforced_by_the_live_agent() {
    const TEST_TTL_MS: u64 = 10_000;

    let state = TestState::new();
    let mission = UnprotectedReferenceMission::from_bytes(
        include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle").to_vec(),
    )
    .unwrap();
    let node = start_node(NodeConfig {
        state: state.0.clone(),
        bind: "127.0.0.1:0".parse().unwrap(),
        mission,
        peers: Vec::new(),
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: Duration::from_millis(50),
        run_for: None,
        application: NodeApplication::Relay,
    })
    .await
    .unwrap();
    let agent = BoundAgent::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = agent.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(agent.serve(
        node.selected_events(),
        ClientToken::from_bytes(TEST_TOKEN.to_vec()).unwrap(),
        shutdown_rx,
    ));
    let client = api::AsterApplicationServiceClient::new(
        HttpClient::plaintext(),
        ClientConfig::new(format!("http://{address}").parse().unwrap()).with_default_header(
            "authorization",
            format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
        ),
    );
    let mut request = api::PublishEventRequest {
        operation_key: b"ttl-publication".to_vec(),
        topic: "chat.events".to_owned(),
        scope: "mission/team/alpha".to_owned(),
        priority: api::Priority::Routine.into(),
        logical_key: b"finite".to_vec(),
        payload: b"short-lived".to_vec(),
        ttl_ms: Some(0),
        ..Default::default()
    };
    assert_eq!(
        client
            .publish_event(request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    request.ttl_ms = Some(TEST_TTL_MS);
    request.tombstone = true;
    assert_eq!(
        client
            .publish_event(request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    request.tombstone = false;
    #[cfg(not(target_os = "linux"))]
    assert_eq!(
        client
            .publish_event(request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::PermissionDenied
    );
    #[cfg(target_os = "linux")]
    {
        let subscription = client
            .create_event_subscription(api::CreateEventSubscriptionRequest {
                operation_key: b"ttl-subscription".to_vec(),
                topic: request.topic.clone(),
                scope: request.scope.clone(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        let published = client
            .publish_event(request.clone())
            .await
            .unwrap()
            .into_owned();
        assert_eq!(published.ttl_ms, request.ttl_ms);
        let retry = client
            .publish_event(request.clone())
            .await
            .unwrap()
            .into_owned();
        assert_eq!(retry.id, published.id);
        assert!(!retry.inserted);
        let mut changed = request.clone();
        changed.ttl_ms = Some(TEST_TTL_MS + 1_000);
        assert_eq!(
            client.publish_event(changed).await.unwrap_err().code,
            ErrorCode::Aborted
        );
        let query = api::QueryEventsRequest {
            logical_key: Some(b"finite".to_vec()),
            limit: 16,
            ..Default::default()
        };
        let page = client
            .query_events(query.clone())
            .await
            .unwrap()
            .into_owned();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].ttl_ms, request.ttl_ms);
        let poll = api::PollEventsRequest {
            subscription_id: subscription.subscription_id,
            delivery_limit: 16,
            scan_limit: 16,
            ..Default::default()
        };
        let deliveries = client.poll_events(poll.clone()).await.unwrap().into_owned();
        assert_eq!(deliveries.deliveries.len(), 1);
        assert_eq!(
            deliveries.deliveries[0].event.as_option().unwrap().ttl_ms,
            request.ttl_ms
        );
        let full = client
            .get_status(api::GetStatusRequest::default())
            .await
            .unwrap()
            .into_owned();
        // Keep a generous pre-expiry window for loaded CI runners while still
        // crossing the real live-agent wall-clock boundary in this test.
        tokio::time::sleep(Duration::from_millis(TEST_TTL_MS + 50)).await;
        assert!(
            client
                .query_events(query)
                .await
                .unwrap()
                .into_owned()
                .events
                .is_empty()
        );
        assert!(
            client
                .poll_events(poll)
                .await
                .unwrap()
                .into_owned()
                .deliveries
                .is_empty()
        );
        assert_eq!(
            client
                .publish_event(request.clone())
                .await
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
        let empty = client
            .get_status(api::GetStatusRequest::default())
            .await
            .unwrap()
            .into_owned();
        assert!(
            empty.store_capacity.as_option().unwrap().items
                < full.store_capacity.as_option().unwrap().items
        );
        assert!(
            empty.store_capacity.as_option().unwrap().payload_bytes
                < full.store_capacity.as_option().unwrap().payload_bytes
        );
        assert_eq!(
            empty
                .publish_operation_capacity
                .as_option()
                .unwrap()
                .retired_rows,
            1
        );
    }
    request.operation_key = b"durable-publication".to_vec();
    request.ttl_ms = None;
    let durable = client.publish_event(request).await.unwrap().into_owned();
    assert!(durable.inserted);
    assert_eq!(durable.ttl_ms, None);
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn numbered_sdk_recovers_its_committed_result_across_restart() {
    let state = TestState::new();
    let mission = UnprotectedReferenceMission::from_bytes(
        include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle").to_vec(),
    )
    .expect("mission");
    let node = start_node(NodeConfig {
        state: state.0.clone(),
        bind: "127.0.0.1:0".parse().expect("mesh bind"),
        mission,
        peers: Vec::new(),
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: Duration::from_millis(50),
        run_for: None,
        application: NodeApplication::Relay,
    })
    .await
    .expect("node");
    let agent = BoundAgent::bind("127.0.0.1:0".parse().expect("agent bind"))
        .await
        .expect("agent");
    let address = agent.local_addr().expect("address");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(agent.serve(
        node.selected_events(),
        ClientToken::from_bytes(TEST_TOKEN.to_vec()).expect("token"),
        shutdown_rx,
    ));
    let config = || {
        ClientConfig::new(format!("http://{address}").parse().expect("URI")).with_default_header(
            "authorization",
            format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
        )
    };
    let journal_path = state.0.join("publication-journal.redb");
    let client_id = b"real-numbered-sdk";
    PublicationJournal::initialize(&journal_path, client_id).expect("initialize journal");

    let sequence;
    let committed;
    let occupied_bytes;
    {
        let sdk = NumberedEventSdk::open(
            api::AsterApplicationServiceClient::new(HttpClient::plaintext(), config()),
            &journal_path,
            client_id,
        )
        .expect("open journal");
        let report = sdk.recover().await.expect("initial recovery");
        assert!(report.operations.is_empty());
        (sequence, committed) = sdk
            .publish(api::PublishNumberedEventRequest {
                topic: "chat.events".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                priority: api::Priority::Immediate.into(),
                logical_key: b"numbered-message".to_vec(),
                payload: b"survives SDK restart".to_vec(),
                ..Default::default()
            })
            .await
            .expect("publish");
        assert_eq!(sequence, 1);
        assert_eq!(committed.operation_sequence, 1);

        let status = api::AsterApplicationServiceClient::new(HttpClient::plaintext(), config())
            .get_status(api::GetStatusRequest::default())
            .await
            .expect("numbered status")
            .into_owned();
        let operations = status
            .publish_operation_capacity
            .as_option()
            .expect("publication capacity");
        assert_eq!(operations.rows, 2, "one client and one outstanding result");
        assert!(operations.bytes > 0);
        occupied_bytes = operations.bytes;
        assert_eq!(operations.ordinary_remaining, 683_925);
        assert!(operations.emergency_remaining > 0);
        assert_eq!(operations.profile_remaining, 1_022);
        assert_eq!(
            operations.ledger_mode,
            api::PublishOperationLedgerMode::Numbered
        );
        assert_eq!(operations.numbered_clients, 1);
        assert_eq!(operations.numbered_outstanding_results, 1);
        assert_eq!(operations.numbered_reverse_rows, 1);
        assert!(operations.rolling_accept_rate > 0.0);
    }

    let restarted = NumberedEventSdk::open(
        api::AsterApplicationServiceClient::new(HttpClient::plaintext(), config()),
        &journal_path,
        client_id,
    )
    .expect("reopen journal");
    let report = restarted.recover().await.expect("restart recovery");
    assert_eq!(report.operations.len(), 1);
    assert_eq!(report.operations[0].sequence, sequence);
    assert!(matches!(&report.operations[0].state,
        RecoveredState::Committed(result) if result == &committed));
    assert!(restarted.session().expect("session") > 1);
    assert_eq!(
        restarted
            .publish_journaled(sequence)
            .await
            .expect("recovered committed result"),
        committed
    );
    restarted
        .acknowledge(sequence)
        .await
        .expect("acknowledge recovered result");

    let status = api::AsterApplicationServiceClient::new(HttpClient::plaintext(), config())
        .get_status(api::GetStatusRequest::default())
        .await
        .expect("compacted numbered status")
        .into_owned();
    let operations = status
        .publish_operation_capacity
        .as_option()
        .expect("publication capacity");
    assert_eq!(
        operations.rows, 1,
        "the durable client remains after result acknowledgement"
    );
    assert!(
        operations.bytes < occupied_bytes,
        "acknowledgement must reclaim the result and reverse-edge bytes"
    );
    assert_eq!(operations.ordinary_remaining, 683_926);
    assert!(operations.emergency_remaining > 0);
    assert_eq!(operations.profile_remaining, 1_023);
    assert_eq!(
        operations.ledger_mode,
        api::PublishOperationLedgerMode::Numbered
    );
    assert_eq!(operations.numbered_clients, 1);
    assert_eq!(operations.numbered_outstanding_results, 0);
    assert_eq!(operations.numbered_reverse_rows, 0);

    shutdown_tx.send(true).expect("shutdown");
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("agent shutdown timeout")
        .expect("agent task")
        .expect("agent serve");
    node.shutdown().await.expect("node shutdown");
}
