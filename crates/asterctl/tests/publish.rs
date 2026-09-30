use buffa::Message;
use serde_json::json;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    process::{Command, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

mod proto {
    connectrpc::include_generated!();
}
use proto::aster::application::v1alpha1 as api;

const TOKEN: &str = "asterctl-test-token-00000000000000";
const ID: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

fn run(port: u16, args: &[&str], input: Option<&[u8]>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_asterctl"))
        .args(["--token", TOKEN, "--port", &port.to_string()])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Leave stdin open when absent: MSG and tombstone must not wait for EOF.
    let mut stdin = child.stdin.take().unwrap();
    if let Some(input) = input {
        match stdin.write_all(input) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(error) => panic!("write stdin: {error}"),
        }
        drop(stdin);
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("publish waited for input or failed to finish");
        }
        thread::sleep(Duration::from_millis(5));
    }
    child.wait_with_output().unwrap()
}

fn serve(
    status: &str,
    content_type: &str,
    response: Vec<u8>,
) -> (
    SocketAddr,
    mpsc::Receiver<api::PublishEventRequest>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    );
    let (sender, receiver) = mpsc::channel();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut connection = loop {
            match listener.accept() {
                Ok((connection, _)) => break connection,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("no publication request: {error}"),
            }
        };
        // Accepted sockets inherit nonblocking mode on macOS/BSD.
        connection.set_nonblocking(false).unwrap();
        connection
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        connection
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            connection.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
            assert!(header.len() <= 8192);
        }
        let header = String::from_utf8(header).unwrap().to_ascii_lowercase();
        assert!(header.starts_with(
            "post /aster.application.v1alpha1.asterapplicationservice/publishevent http/1.1\r\n"
        ));
        assert!(header.contains(&format!("authorization: bearer {TOKEN}\r\n")));
        assert!(header.contains("content-type: application/proto\r\n"));
        let length: usize = header
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .unwrap()
            .parse()
            .unwrap();
        assert!(length <= 1024 * 1024);
        let mut body = vec![0; length];
        connection.read_exact(&mut body).unwrap();
        sender
            .send(api::PublishEventRequest::decode_from_slice(&body).unwrap())
            .unwrap();
        connection.write_all(reply.as_bytes()).unwrap();
        connection.write_all(&response).unwrap();
    });
    (address, receiver, server)
}

fn receipt(inserted: bool, ttl_ms: Option<u64>) -> api::PublishEventResponse {
    api::PublishEventResponse {
        id: (0..32).collect(),
        publisher: (32..64).collect(),
        publisher_counter: u64::MAX,
        event_sequence: 17,
        priority: api::Priority::PRIORITY_ROUTINE.into(),
        acceptance_marker: 128,
        inserted,
        ttl_ms,
        ..Default::default()
    }
}

fn publish(
    args: &[&str],
    input: Option<&[u8]>,
    response: api::PublishEventResponse,
) -> (api::PublishEventRequest, Output) {
    let (address, requests, server) =
        serve("200 OK", "application/proto", response.encode_to_vec());
    let output = run(address.port(), args, input);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let request = requests.recv_timeout(Duration::from_secs(1)).unwrap();
    if args.contains(&"--operation-key=auto") {
        assert_eq!(
            output.stderr,
            format!(
                "asterctl: operation-key={}\n",
                std::str::from_utf8(&request.operation_key).unwrap()
            )
            .as_bytes()
        );
    } else {
        assert!(output.stderr.is_empty());
    }
    server.join().unwrap();
    (request, output)
}

#[test]
fn publish_sends_all_fields_and_formats_the_rpc_receipt_as_protojson() {
    let (request, output) = publish(
        &[
            "publish",
            "--topic",
            "chat.events",
            "--scope",
            "mission/team/alpha",
            "--priority",
            "flash",
            "--logical-key",
            "пристрій-1",
            "--operation-key",
            "chat/message-001",
            "--predecessor",
            ID,
            "--ttl-ms",
            "30001",
            "--json",
            "Hello = Aster!\n",
        ],
        None,
        receipt(true, Some(30001)),
    );
    assert_eq!(request.operation_key, b"chat/message-001");
    assert_eq!(request.topic, "chat.events");
    assert_eq!(request.scope, "mission/team/alpha");
    assert_eq!(request.priority, api::Priority::PRIORITY_FLASH);
    assert_eq!(request.logical_key, "пристрій-1".as_bytes());
    assert_eq!(request.payload, b"Hello = Aster!\n");
    assert_eq!(request.predecessor_id, Some((0..32).collect()));
    assert_eq!(request.ttl_ms, Some(30001));
    assert!(!request.tombstone);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value,
        json!({
            "id": ID, "publisher": "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=",
            "publisherCounter": "18446744073709551615", "eventSequence": "17",
            "priority": "PRIORITY_ROUTINE", "acceptanceMarker": "128",
            "inserted": true, "ttlMs": "30001", "operation_key": "chat/message-001",
        })
    );
}

#[test]
fn publish_preserves_binary_stdin_and_generates_a_fresh_key_for_each_invocation() {
    let mut keys = Vec::new();
    for _ in 0..2 {
        let (request, output) = publish(
            &["publish", "--topic=x", "--scope=x", "--operation-key=auto"],
            Some(b"\0\xff\x89PNG\r\n\0\n"),
            receipt(true, None),
        );
        assert_eq!(request.payload, b"\0\xff\x89PNG\r\n\0\n");
        assert_eq!(request.priority, api::Priority::PRIORITY_ROUTINE);
        assert!(request.logical_key.is_empty());
        assert_eq!(request.predecessor_id, None);
        assert_eq!(request.ttl_ms, None);
        assert_eq!(request.operation_key.len(), 32);
        keys.push(request.operation_key);
        let text = String::from_utf8(output.stdout).unwrap();
        for expected in [
            "EVENT:",
            "Published locally",
            ID,
            "18,446,744,073,709,551,615",
            "Routine",
            "None",
        ] {
            assert!(text.contains(expected), "{text}");
        }
    }
    assert_ne!(keys[0], keys[1]);
}

#[test]
fn publish_empty_and_option_like_messages_do_not_read_stdin() {
    for message in ["", "--help", "--json", "a=b", "publish", "status"] {
        let (request, _) = publish(
            &[
                "publish",
                "--topic",
                "x",
                "--scope",
                "x",
                "--operation-key=test",
                "--",
                message,
            ],
            None,
            receipt(true, None),
        );
        assert_eq!(request.payload, message.as_bytes());
    }
}

#[test]
fn publish_tombstone_uses_an_empty_payload_without_waiting_for_stdin() {
    let (request, output) = publish(
        &[
            "publish",
            "--topic",
            "x",
            "--scope",
            "x",
            "--tombstone",
            "--operation-key=test",
            "--json",
        ],
        None,
        receipt(false, None),
    );
    assert!(request.tombstone);
    assert!(request.payload.is_empty());
    assert_eq!(request.ttl_ms, None);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["inserted"], false);
    assert!(value.get("ttlMs").is_none());
    let (_, output) = publish(
        &[
            "publish",
            "--topic",
            "x",
            "--scope",
            "x",
            "--operation-key=test",
            "--tombstone",
        ],
        None,
        receipt(false, None),
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("Already published")
    );
}

#[test]
fn invalid_publication_arguments_fail_before_rpc_or_stdin() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    for extra in [
        vec!["--priority", "urgent"],
        vec!["--topic", ""],
        vec!["--topic", "a/b"],
        vec!["--scope", "/a"],
        vec!["--scope", "a//b"],
        vec!["--scope", "a/../b"],
        vec!["--operation-key", ""],
        vec!["--ttl-ms", "0"],
        vec!["--ttl-ms", "-1"],
        vec!["--ttl-ms", "18446744073709551616"],
        vec!["--predecessor", "AA=="],
        vec!["--predecessor", "invalid"],
        vec!["--tombstone", "nonempty"],
        vec!["--tombstone", "--ttl-ms", "1"],
        vec!["one", "two"],
    ] {
        let mut args = vec!["publish", "--topic", "x", "--scope", "x"];
        args.extend(extra);
        let output = run(listener.local_addr().unwrap().port(), &args, None);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(TOKEN));
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    }
}

#[test]
fn publication_limit_includes_metadata_and_payload() {
    // Three one-byte strings (3 bytes each), priority (2), payload tag and
    // three-byte length (4): exactly 15 bytes of protobuf overhead.
    let payload = vec![42; 1024 * 1024 - 15];
    let args = [
        "publish",
        "--topic",
        "x",
        "--scope",
        "x",
        "--operation-key",
        "x",
    ];
    let (request, _) = publish(&args, Some(&payload), receipt(true, None));
    assert_eq!(request.payload, payload);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    for length in [payload.len() + 1, 1024 * 1024 + 1] {
        let output = run(
            listener.local_addr().unwrap().port(),
            &args,
            Some(&vec![42; length]),
        );
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("1 MiB"));
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    }
}

#[test]
fn publication_errors_hide_remote_text_and_do_not_print_a_receipt() {
    let body = format!(r#"{{"code":"aborted","message":"secret {TOKEN}"}}"#);
    let (address, requests, server) = serve("409 Conflict", "application/json", body.into_bytes());
    let output = run(
        address.port(),
        &[
            "publish",
            "--topic",
            "x",
            "--scope",
            "x",
            "--operation-key=test",
            "hello",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("PublishEvent failed: aborted"), "{error}");
    assert!(!error.contains(TOKEN));
    assert!(!error.contains("secret"));
    assert!(!error.contains("outcome unknown"));
    requests.recv_timeout(Duration::from_secs(1)).unwrap();
    server.join().unwrap();
}

#[test]
fn publish_help_does_not_require_a_token_or_read_stdin() {
    let output = Command::new(env!("CARGO_BIN_EXE_asterctl"))
        .args(["publish", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("[MSG]"));
    assert!(text.contains("--operation-key"));
    assert!(text.contains("--tombstone"));
}

#[test]
fn finite_publication_requires_the_agent_to_confirm_the_requested_ttl() {
    for ttl_ms in [None, Some(2)] {
        let (address, requests, server) = serve(
            "200 OK",
            "application/proto",
            receipt(true, ttl_ms).encode_to_vec(),
        );
        let output = run(
            address.port(),
            &[
                "publish",
                "--topic=x",
                "--scope=x",
                "--operation-key=test",
                "--ttl-ms=1",
                "hello",
            ],
            None,
        );
        requests.recv_timeout(Duration::from_secs(1)).unwrap();
        server.join().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("TTL"));
    }
}
