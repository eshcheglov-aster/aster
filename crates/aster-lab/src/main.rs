#![forbid(unsafe_code)]

use aster_lab::LabResult;
use aster_lab::live::{
    RelayInfraConfig, RendezvousInfra, RendezvousInfraConfig, parse_node_id, read_private_hex,
};
use aster_lab::mesh_experiment::{
    MeshPrepareConfig, NativeMeshNodeConfig, consume_and_ack_ip_mesh, prepare_ip_mesh,
    run_native_mesh_node, verify_ip_mesh_duplicate_suppression, verify_ip_mesh_relay_custody,
};
use aster_mesh::{Scope, Topic};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aster-lab: {error}");
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> LabResult<()> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(command) = arguments.next() else {
        print_help();
        return Ok(());
    };
    let command = command
        .into_string()
        .map_err(|_| invalid("command must be valid UTF-8"))?;
    if matches!(command.as_str(), "help" | "--help" | "-h") {
        print_help();
        return Ok(());
    }
    let options = Options::parse(arguments.collect())?;
    if !known_command(&command) {
        return Err(invalid(format!("unknown command {command}")));
    }
    options.reject_unknown(&command)?;
    match command.as_str() {
        "mesh-native-node" => run_native_mesh_node_command(&options)?,
        "mesh-prepare" => run_mesh_prepare_command(&options)?,
        "mesh-verify-relay" => run_mesh_verify_relay_command(&options)?,
        "mesh-consume" => run_mesh_consume_command(&options)?,
        "mesh-verify-duplicate" => run_mesh_verify_duplicate_command(&options)?,
        "rendezvous" => run_infrastructure(&options, true)?,
        "infra" => run_infrastructure(&options, false)?,
        _ => unreachable!("option_allowlist accepted an unknown command"),
    }
    Ok(())
}

fn print_help() {
    println!(
        "Aster native mesh laboratory\n\n\
         Usage:\n\
           aster-lab mesh-native-node --root NODE_PATH --bundle FILE --discovery-target ADDRESS --discovery-token FILE [OPTIONS]\n\
           aster-lab mesh-prepare --root PATH [--seed N --payload-bytes N]\n\
           aster-lab mesh-verify-relay --root PATH --invocation NAME\n\
           aster-lab mesh-consume --root PATH --invocation NAME\n\
           aster-lab mesh-verify-duplicate --root PATH --invocation NAME\n\
           aster-lab infra --rendezvous-bind ADDRESS [--relay-bind ADDRESS --relay-pairs N]\n\
           aster-lab rendezvous --bind ADDRESS [--duration-ms N]"
    );
}

#[derive(Debug)]
struct Options(BTreeMap<String, String>);

impl Options {
    fn parse(arguments: Vec<OsString>) -> LabResult<Self> {
        let mut values = BTreeMap::new();
        let mut arguments = arguments.into_iter();
        while let Some(name) = arguments.next() {
            let name = name
                .into_string()
                .map_err(|_| invalid("option name must be valid UTF-8"))?;
            if !name.starts_with("--") || name.len() == 2 {
                return Err(invalid(format!("expected --option, found {name}")));
            }
            let value = arguments
                .next()
                .ok_or_else(|| invalid(format!("{name} requires a value")))?
                .into_string()
                .map_err(|_| invalid(format!("{name} value must be valid UTF-8")))?;
            let key = name.trim_start_matches("--").to_owned();
            if values.insert(key.clone(), value).is_some() {
                return Err(invalid(format!("duplicate option --{key}")));
            }
        }
        Ok(Self(values))
    }

    fn required_path(&self, name: &str) -> LabResult<PathBuf> {
        self.0
            .get(name)
            .map(PathBuf::from)
            .ok_or_else(|| invalid(format!("--{name} is required")))
    }

    fn text(&self, name: &str, default: &str) -> String {
        self.0
            .get(name)
            .cloned()
            .unwrap_or_else(|| default.to_owned())
    }

    fn number<T>(&self, name: &str, default: T) -> LabResult<T>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        self.0.get(name).map_or(Ok(default), |value| {
            value
                .parse()
                .map_err(|error| invalid(format!("invalid --{name}: {error}")))
        })
    }

    fn reject_unknown(&self, command: &str) -> LabResult<()> {
        if let Some(name) = self
            .0
            .keys()
            .find(|name| !option_is_allowed(command, name.as_str()))
        {
            return Err(invalid(format!(
                "option --{name} is not valid for command {command}"
            )));
        }
        Ok(())
    }
}

fn known_command(command: &str) -> bool {
    matches!(
        command,
        "mesh-native-node"
            | "mesh-prepare"
            | "mesh-verify-relay"
            | "mesh-consume"
            | "mesh-verify-duplicate"
            | "rendezvous"
            | "infra"
    )
}

fn option_is_allowed(command: &str, name: &str) -> bool {
    match command {
        "mesh-native-node" => [
            "root",
            "bundle",
            "invocation",
            "topic",
            "scope",
            "duration-ms",
            "bind",
            "discovery-target",
            "discovery-token",
            "max-candidates",
            "max-active-contacts",
            "expected-peers",
            "discovery-enabled",
            "manual-peers",
            "emission-mode",
            "gate-h-control",
            "gate-h-stale-target-peer",
            "durable-item-probe",
        ]
        .contains(&name),
        "mesh-prepare" => ["root", "seed", "payload-bytes"].contains(&name),
        "mesh-verify-relay" | "mesh-consume" | "mesh-verify-duplicate" => {
            ["root", "invocation"].contains(&name)
        }
        "rendezvous" => [
            "bind",
            "relay-bind",
            "relay-pairs",
            "duration-ms",
            "poll-ms",
        ]
        .contains(&name),
        "infra" => [
            "rendezvous-bind",
            "relay-bind",
            "relay-pairs",
            "duration-ms",
            "poll-ms",
        ]
        .contains(&name),
        _ => false,
    }
}

fn run_native_mesh_node_command(options: &Options) -> LabResult<()> {
    let expected_peers = options
        .text("expected-peers", "")
        .split(',')
        .filter(|value| !value.is_empty())
        .map(parse_node_id)
        .collect::<LabResult<BTreeSet<_>>>()?;
    let discovery_enabled_value = options.text("discovery-enabled", "true");
    let discovery_enabled = match discovery_enabled_value.as_str() {
        "true" => true,
        "false" => false,
        _ => return Err(invalid("--discovery-enabled must be true or false")),
    };
    let config = NativeMeshNodeConfig {
        invocation: options
            .0
            .get("invocation")
            .cloned()
            .ok_or_else(|| invalid("--invocation is required"))?,
        root: options.required_path("root")?,
        credential_path: options.required_path("bundle")?,
        topic: Topic::new(options.text("topic", "lab.ip-mesh.commands"))?,
        scope: Scope::new(options.text("scope", "lab/ip-mesh"))?,
        discovery_token: read_private_hex::<16>(&options.required_path("discovery-token")?)?,
        bind: options
            .text("bind", "0.0.0.0:47101")
            .parse()
            .map_err(|error| invalid(format!("invalid --bind: {error}")))?,
        discovery_target: required_socket(options, "discovery-target")?,
        max_candidates: options.number("max-candidates", 128_usize)?,
        max_active_contacts: options.number("max-active-contacts", 8_usize)?,
        run_for: Duration::from_millis(options.number("duration-ms", 60_000_u64)?),
        discovery_enabled,
        expected_peers,
        manual_peers: options.text("manual-peers", ""),
        emission_mode: options.text("emission-mode", "normal"),
        gate_h_control_path: options.0.get("gate-h-control").map(PathBuf::from),
        gate_h_stale_target_peer: options
            .0
            .get("gate-h-stale-target-peer")
            .map(|value| parse_node_id(value))
            .transpose()?,
        durable_item_probe: options
            .0
            .get("durable-item-probe")
            .map(|value| parse_node_id(value))
            .transpose()?,
    };
    let receipt = run_native_mesh_node(&config)?;
    println!("{}", receipt.to_json());
    Ok(())
}

fn run_mesh_prepare_command(options: &Options) -> LabResult<()> {
    let receipt = prepare_ip_mesh(&MeshPrepareConfig {
        root: options.required_path("root")?,
        seed: options.number("seed", 1_u64)?,
        payload_bytes: options.number("payload-bytes", 1_024_usize)?,
    })?;
    println!("{}", receipt.to_json());
    Ok(())
}

fn run_mesh_verify_relay_command(options: &Options) -> LabResult<()> {
    let receipt = verify_ip_mesh_relay_custody(
        &options.required_path("root")?,
        required_invocation(options)?,
    )?;
    println!("{}", receipt.to_json());
    Ok(())
}

fn run_mesh_consume_command(options: &Options) -> LabResult<()> {
    let receipt = consume_and_ack_ip_mesh(
        &options.required_path("root")?,
        required_invocation(options)?,
    )?;
    println!("{}", receipt.to_json());
    Ok(())
}

fn run_mesh_verify_duplicate_command(options: &Options) -> LabResult<()> {
    verify_ip_mesh_duplicate_suppression(
        &options.required_path("root")?,
        required_invocation(options)?,
    )?;
    println!("{{\"duplicate_suppression\":true}}");
    Ok(())
}

fn required_invocation(options: &Options) -> LabResult<&str> {
    options
        .0
        .get("invocation")
        .map(String::as_str)
        .ok_or_else(|| invalid("--invocation is required"))
}

fn run_infrastructure(options: &Options, compatibility_alias: bool) -> LabResult<()> {
    if options.0.contains_key("relay-pairs") && !options.0.contains_key("relay-bind") {
        return Err(invalid("--relay-pairs requires --relay-bind"));
    }
    let rendezvous_bind = required_socket(
        options,
        if compatibility_alias {
            "bind"
        } else {
            "rendezvous-bind"
        },
    )?;
    let relay = if let Some(value) = options.0.get("relay-bind") {
        Some(RelayInfraConfig {
            bind: value
                .parse()
                .map_err(|error| invalid(format!("invalid --relay-bind: {error}")))?,
            pair_limit: options.number("relay-pairs", 0_usize)?,
        })
    } else {
        None
    };
    let duration_ms: u64 = options.number("duration-ms", 60_000)?;
    let poll_ms: u64 = options.number("poll-ms", 1)?;
    if duration_ms == 0 || poll_ms == 0 || poll_ms > 1_000 {
        return Err(invalid(
            "infrastructure duration must be positive and poll interval between 1 and 1000 ms",
        ));
    }
    let mut infrastructure = RendezvousInfra::bind(RendezvousInfraConfig {
        rendezvous_bind,
        relay,
    })?;
    println!(
        "ASTER_LAB_INFRA_READY\tversion=1\trendezvous_address={}\trelay_address={}",
        infrastructure.rendezvous_address(),
        infrastructure
            .relay_address()
            .map_or_else(|| "-".into(), |address| address.to_string())
    );
    let started = Instant::now();
    let deadline = started
        .checked_add(Duration::from_millis(duration_ms))
        .ok_or_else(|| invalid("infrastructure duration overflow"))?;
    while Instant::now() < deadline {
        infrastructure.poll()?;
        thread::sleep(Duration::from_millis(poll_ms));
    }
    println!("{}", infrastructure.poll()?.to_record());
    Ok(())
}

fn required_socket(options: &Options, name: &str) -> LabResult<SocketAddr> {
    options
        .0
        .get(name)
        .ok_or_else(|| invalid(format!("--{name} is required")))?
        .parse()
        .map_err(|error| invalid(format!("invalid --{name}: {error}")))
}

fn invalid(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_rejects_unlisted_options() {
        for command in [
            "mesh-native-node",
            "mesh-prepare",
            "mesh-verify-relay",
            "mesh-consume",
            "mesh-verify-duplicate",
            "rendezvous",
            "infra",
        ] {
            let options = Options(BTreeMap::from([("not-a-real-option".into(), "1".into())]));
            assert!(
                options.reject_unknown(command).is_err(),
                "{command} accepted an unknown option"
            );
        }
    }

    #[test]
    fn relay_pair_limit_requires_a_relay_listener() {
        let options = Options(BTreeMap::from([
            ("bind".into(), "127.0.0.1:0".into()),
            ("relay-pairs".into(), "1".into()),
        ]));
        assert!(run_infrastructure(&options, true).is_err());
    }
}
