#![cfg(unix)]

use sha2::{Digest as _, Sha256};
use std::{
    fs,
    io::{self, Read as _},
    net::TcpListener,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use aho_corasick::{AhoCorasick, AhoCorasickKind};
use memchr::memmem::Finder;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
const BINARY_MARKER_SCAN_BYTES: usize = 1024 * 1024;

#[derive(Debug, Eq, PartialEq)]
struct MarkerReport {
    missing_required: Vec<Vec<u8>>,
    present_forbidden: Vec<Vec<u8>>,
}

#[test]
fn binary_marker_scan_reports_boundary_matches_and_io_errors() {
    let fixture = BinaryFixture::new(compose_binary_path());
    let binary = fixture.root.join("marker-fixture.bin");
    let mut bytes = vec![b'x'; BINARY_MARKER_SCAN_BYTES - 2];
    bytes.extend_from_slice(b"required-across-boundary");
    bytes.resize(BINARY_MARKER_SCAN_BYTES * 2 - 3, b'x');
    bytes.extend_from_slice(b"forbidden-across-boundary");
    bytes.extend_from_slice(b"present-required");
    fs::write(&binary, bytes).expect("write marker fixture");

    let report = find_binary_markers(
        &binary,
        &[
            b"required-across-boundary".as_slice(),
            b"across-boundary".as_slice(),
            b"present-required".as_slice(),
            b"missing-required".as_slice(),
            b"missing-required".as_slice(),
        ],
        &[
            b"forbidden-across-boundary".as_slice(),
            b"bidden-across-boundary".as_slice(),
            b"absent-forbidden".as_slice(),
        ],
    )
    .expect("scan marker fixture");
    assert_eq!(report.missing_required, [b"missing-required".to_vec()]);
    assert_eq!(
        report.present_forbidden,
        [
            b"forbidden-across-boundary".to_vec(),
            b"bidden-across-boundary".to_vec()
        ]
    );

    let error = find_binary_markers(&fixture.root.join("missing.bin"), &[], &[])
        .expect_err("unavailable marker path must return its I/O error");
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn compose_binary_accepts_only_exact_schema_v2() {
    // Break caught: a permissive parser could admit schema v1, aliases,
    // duplicate fields, alternate mounts, or provider selection in config.
    let binary_path = compose_binary_path();
    let fixture = BinaryFixture::new(binary_path);
    let accepted = fixture.run_check(&fixture.v2_config());
    assert!(!accepted.status.success());
    assert_eq!(utf8(accepted.stderr), expected_credential_failure());

    let cases = [
        (
            fixture.v1_config(),
            "ERROR configuration schema version is unsupported\n",
        ),
        (
            fixture.v2_config().replace(
                "\"mission_activation_file\":",
                "\"unknown\":true,\"mission_activation_file\":",
            ),
            "ERROR configuration contains an unknown field\n",
        ),
        (
            fixture.v2_config().replace(
                "\"mission_activation_file\":",
                "\"client_token_file\":\"/run/secrets/aster-client-token\",\"mission_activation_file\":",
            ),
            "ERROR configuration contains a duplicate field\n",
        ),
        (
            fixture
                .v2_config()
                .replace("/run/secrets/aster-client-token", "/tmp/client-token"),
            "ERROR credential file boundary is invalid\n",
        ),
        (
            fixture.v2_config().replace("/var/lib/aster", "/tmp/aster"),
            "ERROR configuration state boundary is invalid\n",
        ),
        (
            fixture
                .v2_config()
                .replace("/var/lib/aster", "/var/lib/aster/../aster"),
            "ERROR configuration state boundary is invalid\n",
        ),
        (
            fixture.v2_config().replace(
                "\"storage\":",
                "\"provider\":\"systemd\",\"storage\":",
            ),
            "ERROR configuration contains an unknown field\n",
        ),
    ];
    for (config, expected) in cases {
        let output = fixture.run_check(&config);
        assert!(!output.status.success(), "configuration was admitted");
        assert_eq!(utf8(output.stderr), expected);
    }
}

#[test]
fn compose_check_config_preflights_credentials_without_state_or_listeners() {
    // Break caught: preflight opening state or listeners before all fixed
    // credentials validate would mutate or expose the service on failure.
    let binary_path = compose_binary_path();
    let fixture = BinaryFixture::new(binary_path);
    let initial = fixture.run_check(&fixture.v2_config());
    assert!(!initial.status.success());
    assert!(!fixture.state.exists(), "preflight created durable state");
    let Ok(application) = TcpListener::bind("127.0.0.1:0") else {
        eprintln!("SKIP Compose listener preflight: loopback sockets denied by sandbox");
        return;
    };
    let health = TcpListener::bind("127.0.0.1:0").expect("reserve health listener");
    let config = fixture
        .v2_config()
        .replace(
            "127.0.0.1:41831",
            &application.local_addr().unwrap().to_string(),
        )
        .replace("127.0.0.1:41832", &health.local_addr().unwrap().to_string());
    let output = fixture.run_check(&config);
    assert!(!output.status.success());
    assert_eq!(utf8(output.stderr), expected_credential_failure());
    assert!(!fixture.state.exists(), "preflight created durable state");
    assert_eq!(
        application.local_addr().unwrap().ip().to_string(),
        "127.0.0.1"
    );
    assert_eq!(health.local_addr().unwrap().ip().to_string(), "127.0.0.1");
}

#[test]
fn compose_binary_has_only_the_compose_provider_and_no_legacy_mode() {
    // Break caught: linking systemd/admin code or retaining the unprotected
    // development CLI would create an alternate customer credential path.
    let binary_path = compose_binary_path();
    let report = find_binary_markers(
        Path::new(binary_path),
        &[b"aster-compose-secret-store/v1"],
        &[
            b"aster-systemd-credential-store/v2",
            b"CREDENTIALS_DIRECTORY",
            b"aster-credential-admin",
            b"SystemdCredentialLoader",
            b"aster_systemd_credentials",
            b"--mission-bundle-unprotected-reference",
        ],
    )
    .expect("scan Compose agent binary");
    assert!(
        report.missing_required.is_empty(),
        "required Compose binary contracts missing: {:?}",
        report.missing_required
    );
    assert!(
        report.present_forbidden.is_empty(),
        "forbidden systemd or legacy binary contracts present: {:?}",
        report.present_forbidden
    );

    let fixture = BinaryFixture::new(binary_path);
    let output = Command::new(binary_path)
        .args(["--provider", "systemd", "--check-config"])
        .arg(fixture.write_config(&fixture.v2_config()))
        .env("ASTER_CREDENTIAL_PROVIDER", "systemd")
        .output()
        .expect("run forbidden provider selector");
    assert!(!output.status.success());

    let output = Command::new(binary_path)
        .args([
            "--state",
            "/tmp/state",
            "--mission-bundle-unprotected-reference",
            "/tmp/bundle",
        ])
        .output()
        .expect("run forbidden legacy mode");
    assert!(!output.status.success());
}

#[test]
fn compose_binary_rejects_config_changed_after_delivery_validation() {
    // Break caught: Compose can reopen different config bytes after the
    // delivery validator records its plan digest.
    let binary_path = compose_binary_path();
    let fixture = BinaryFixture::new(binary_path);
    let config_path = fixture.write_config(&fixture.v2_config());
    for (digest, expected) in [
        (None, "ERROR configuration digest is required\n"),
        (
            Some("not-a-digest".to_owned()),
            "ERROR configuration digest is invalid\n",
        ),
        (
            Some("0".repeat(64)),
            "ERROR configuration digest does not match\n",
        ),
    ] {
        let mut command = Command::new(binary_path);
        command
            .args(["--check-config", config_path.to_str().expect("UTF-8 path")])
            .env_remove("ASTER_AGENT_CONFIG_SHA256");
        if let Some(digest) = digest {
            command.env("ASTER_AGENT_CONFIG_SHA256", digest);
        }
        let output = command.output().expect("run digest-bound preflight");
        assert!(!output.status.success());
        assert_eq!(utf8(output.stderr), expected);
    }
}

#[test]
fn compose_binary_rejects_oversized_config_before_hash_or_parse() {
    // Break caught: a selected config replaced after plan validation could be
    // read without bound before its digest mismatch or syntax is rejected.
    let binary_path = compose_binary_path();
    let fixture = BinaryFixture::new(binary_path);
    let config = vec![b' '; 256 * 1024 + 1];
    let config_path = fixture.root.join("oversized-agent.json");
    fs::write(&config_path, &config).expect("write oversized config");
    let digest = Sha256::digest(&config)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let output = Command::new(binary_path)
        .args(["--check-config", config_path.to_str().expect("UTF-8 path")])
        .env("ASTER_AGENT_CONFIG_SHA256", digest)
        .output()
        .expect("run bounded preflight");
    assert!(!output.status.success());
    assert_eq!(utf8(output.stderr), "ERROR configuration file is invalid\n");
}

fn find_binary_markers(
    path: &Path,
    required: &[&[u8]],
    forbidden: &[&[u8]],
) -> io::Result<MarkerReport> {
    let mut binary = fs::File::open(path)?;
    let mut patterns: Vec<Vec<u8>> = Vec::new();
    for marker in required.iter().chain(forbidden) {
        if !marker.is_empty() && !patterns.iter().any(|pattern| pattern == marker) {
            patterns.push(marker.to_vec());
        }
    }
    let matcher = if patterns.is_empty() {
        None
    } else {
        Some(
            AhoCorasick::builder()
                .kind(Some(AhoCorasickKind::DFA))
                .build(&patterns)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
        )
    };
    let finders = patterns.iter().map(Finder::new).collect::<Vec<_>>();
    let longest_marker = patterns.iter().map(Vec::len).max().unwrap_or(0);
    let overlap = longest_marker.saturating_sub(1);
    let mut pattern_present = vec![false; patterns.len()];
    let mut block = vec![0; BINARY_MARKER_SCAN_BYTES];
    let mut tail = Vec::with_capacity(overlap);
    let mut window = Vec::with_capacity(BINARY_MARKER_SCAN_BYTES + overlap);

    loop {
        let read = binary.read(&mut block)?;
        if read == 0 {
            break;
        }
        window.clear();
        window.extend_from_slice(&tail);
        window.extend_from_slice(&block[..read]);
        if let Some(matcher) = &matcher {
            for found in matcher.find_iter(&window) {
                pattern_present[found.pattern().as_usize()] = true;
                let local_start = found.start().saturating_sub(overlap);
                let local_end = (found.end() + overlap).min(window.len());
                for (index, finder) in finders.iter().enumerate() {
                    if !pattern_present[index]
                        && finder.find(&window[local_start..local_end]).is_some()
                    {
                        pattern_present[index] = true;
                    }
                }
            }
        }
        let retained = overlap.min(window.len());
        tail.clear();
        tail.extend_from_slice(&window[window.len() - retained..]);
    }

    Ok(MarkerReport {
        missing_required: report_markers(required, &patterns, &pattern_present, false),
        present_forbidden: report_markers(forbidden, &patterns, &pattern_present, true),
    })
}

fn report_markers(
    markers: &[&[u8]],
    patterns: &[Vec<u8>],
    pattern_present: &[bool],
    selected: bool,
) -> Vec<Vec<u8>> {
    let mut result: Vec<Vec<u8>> = Vec::new();
    for marker in markers {
        let present = marker.is_empty()
            || patterns
                .iter()
                .position(|pattern| pattern == marker)
                .is_some_and(|index| pattern_present[index]);
        if present == selected && !result.iter().any(|item| item.as_slice() == *marker) {
            result.push(marker.to_vec());
        }
    }
    result
}

fn compose_binary_path() -> &'static str {
    env!("CARGO_BIN_EXE_aster-compose-agent")
}

fn utf8(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).expect("UTF-8 process output")
}

const fn expected_credential_failure() -> &'static str {
    if cfg!(target_os = "linux") {
        "ERROR credential mount boundary is invalid\n"
    } else {
        "ERROR unsupported credential platform\n"
    }
}

struct BinaryFixture {
    binary: &'static str,
    root: PathBuf,
    state: PathBuf,
}

impl BinaryFixture {
    fn new(binary: &'static str) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "aster-compose-binary-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("protect fixture");
        let state = root.join("state");
        Self {
            binary,
            root,
            state,
        }
    }

    fn run_check(&self, config: &str) -> std::process::Output {
        let digest = Sha256::digest(config.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Command::new(self.binary)
            .arg("--check-config")
            .arg(self.write_config(config))
            .env("ASTER_AGENT_CONFIG_SHA256", digest)
            .output()
            .expect("run Compose preflight")
    }

    fn write_config(&self, config: &str) -> PathBuf {
        let path = self.root.join("agent.json");
        fs::write(&path, config).expect("write agent config");
        path
    }

    fn v2_config(&self) -> String {
        r#"{"schema_version":2,"state":{"directory":"/var/lib/aster"},"application":{"listen":"127.0.0.1:41831"},"health":{"listen":"127.0.0.1:41832"},"mesh":{"bind":"127.0.0.1:0","sync_interval_ms":500,"emission_policy":"normal","peers":[]},"credentials":{"client_token_file":"/run/secrets/aster-client-token","mission_activation_file":"/run/secrets/aster-mission-activation"},"storage":{"max_items":10000,"max_payload_bytes":67108864,"operations":{"max_records":1000000,"max_logical_bytes":201326592,"emergency_reserve":10000}}}"#.to_owned()
    }

    fn v1_config(&self) -> String {
        self.v2_config()
            .replace("\"schema_version\":2", "\"schema_version\":1")
    }
}

impl Drop for BinaryFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
