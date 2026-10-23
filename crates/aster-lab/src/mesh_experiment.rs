//! Lab-only operational IP mesh host used by Proposal 0001.
//!
//! Candidate discovery and carrier identity remain untrusted. Each contact
//! receives an independent Aster runtime, which authenticates the remote
//! mission identity before any synchronization data is accepted. Candidate
//! state is bounded and disposable; durable truth remains in the shared Aster
//! SQLite and Blob stores.

use crate::LabResult;
use aster_host::{
    AdmissionAbortReason, CandidateId, CandidateLocator, CandidateProvenance, CarrierIdentity,
    ContactCloseReason, ContactDirection, ContactId, ContactOpening, ContactPath,
    ContactResourceClaims, ContactSessionRole, ContactSupervisorConfig, ContactSupervisorError,
    HostAction, HostConfig, MeshHost, MeshHostError, NodeProviderResourceLease, NodeResourceBudget,
    NodeResourceClaim, NodeResourceLimits, NodeResourceSnapshot, ResourceBudgetError,
    SharedNodeContactSupervisor, SharedNodeEvidenceTransition,
};
use aster_ip::IpLink;
use aster_mesh::blob::{BlobStoreConfig, BlobTransferStore};
use aster_mesh::engine::NodeConfig;
use aster_mesh::link::{Link, LinkCharacteristics, ReceivedFrame};
use aster_mesh::runtime::{
    ReferenceSemanticRuntimeAuthority, ReferenceSemanticRuntimeBackend,
    RuntimeAuthorizationGenerationCheck, RuntimeLimits, SignedAuthorizationControl, StartRequest,
};
use aster_mesh::sync::{InterestFilter, InventoryPurpose, SyncConfig};
use aster_mesh::wire::EnvelopeId;
use aster_mesh::{
    ApplicationNode, ApplicationNodeOptions, DataClass, EmissionPolicy, ItemId, NodeId, Priority,
    ProvisioningAccess, ProvisioningBundle, PublishRequest, Query, ReferenceEnvelopeSealer,
    ReferenceProvisioner, Scope, SubscriptionId, Topic, UnprotectedProvisioning,
    open_reference_node,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(test)]
use aster_host::HostEvent;

const CARRIER_HELLO_MAGIC: &[u8; 16] = b"ASTR-MESH-HLO-02";
const CARRIER_DATA_MAGIC: &[u8; 16] = b"ASTR-MESH-DAT-02";
const CARRIER_ID_BYTES: usize = 32;
const CARRIER_INSTANCE_NONCE_BYTES: usize = 16;
const CARRIER_HELLO_LEN: usize =
    CARRIER_HELLO_MAGIC.len() + CARRIER_ID_BYTES + CARRIER_INSTANCE_NONCE_BYTES;
const CARRIER_DATA_HEADER_LEN: usize =
    CARRIER_DATA_MAGIC.len() + (2 * CARRIER_ID_BYTES) + (2 * CARRIER_INSTANCE_NONCE_BYTES);
const MAX_RETIRED_CARRIER_INSTANCES_PER_ENDPOINT: usize = 8;
// Mirrored from the frozen IpLink bounds for discovered endpoints, recent
// announcements, pending discovery challenges, discovery responses, and
// rendezvous attempts. Registered candidate routes are accounted separately
// by supervisor-owned candidate leases.
const NATIVE_PROVIDER_PRE_CANDIDATE_FRAME_SLOTS: usize = 4_096 + 128 + 256 + 1_024 + 128;
const NATIVE_PROVIDER_RECEIVE_SCRATCH_BYTES: usize = 65_507;
const MAX_CREDENTIAL_BYTES: usize = 1_048_576;
const MAX_CANDIDATES_HARD: usize = 1_024;
const MAX_INBOUND_FRAMES_PER_CONTACT: usize = 256;
const MAX_INBOUND_BYTES_PER_CONTACT: usize = 1_024 * 1_024;
const MAX_EVENTS_BYTES: u64 = 16 * 1_024 * 1_024;
const MAX_COMMAND_BYTES: usize = 1_024 * 1_024;
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(5);
const STATUS_INTERVAL: Duration = Duration::from_millis(250);
const MAX_READINESS_WAIT: Duration = Duration::from_millis(250);
const NATIVE_CANDIDATE_TTL: Duration = Duration::from_secs(30);
const NATIVE_CONTACT_QUANTUM: Duration = Duration::from_secs(30);
const NATIVE_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const NATIVE_PRE_AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(10);
const NATIVE_HELLO_INTERVAL: Duration = Duration::from_secs(1);

/// Fresh offline A/B/C preparation input shared by every candidate arm.
#[derive(Clone, Debug)]
pub struct MeshPrepareConfig {
    pub root: PathBuf,
    pub seed: u64,
    pub payload_bytes: usize,
}

/// Stable source facts emitted before any candidate process starts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshPrepareReceipt {
    pub publisher: NodeId,
    pub relay: NodeId,
    pub consumer: NodeId,
    pub item_id: ItemId,
    pub envelope_id: EnvelopeId,
    pub payload_sha256: [u8; 32],
    pub subscription: SubscriptionId,
    pub topic: Topic,
    pub scope: Scope,
    pub authorization_control_id: EnvelopeId,
    pub authorization_control_subject: NodeId,
    pub authorization_control_sha256: [u8; 32],
    pub authorization_control_bytes: usize,
}

impl MeshPrepareReceipt {
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"schema\": \"aster-lab-ip-mesh-prepare/v1\",\n",
                "  \"publisher\": \"{}\",\n",
                "  \"relay\": \"{}\",\n",
                "  \"consumer\": \"{}\",\n",
                "  \"item_id\": \"{}\",\n",
                "  \"envelope_id\": \"{}\",\n",
                "  \"payload_sha256\": \"{}\",\n",
                "  \"subscription\": {},\n",
                "  \"topic\": \"{}\",\n",
                "  \"scope\": \"{}\",\n",
                "  \"authorization_control_id\": \"{}\",\n",
                "  \"authorization_control_subject\": \"{}\",\n",
                "  \"authorization_control_sha256\": \"{}\",\n",
                "  \"authorization_control_bytes\": {}\n",
                "}}"
            ),
            hex(&self.publisher),
            hex(&self.relay),
            hex(&self.consumer),
            hex(&self.item_id),
            hex(self.envelope_id.as_bytes()),
            hex(&self.payload_sha256),
            self.subscription.0,
            json_escape(self.topic.as_str()),
            json_escape(self.scope.as_str()),
            hex(self.authorization_control_id.as_bytes()),
            hex(&self.authorization_control_subject),
            hex(&self.authorization_control_sha256),
            self.authorization_control_bytes,
        )
    }
}

/// Creates three distinct identities and durable stores, publishes one exact
/// Event at offline A, and creates C's durable subscription before any carrier
/// process starts. B receives route/custody authority and no content key.
pub fn prepare_ip_mesh(config: &MeshPrepareConfig) -> LabResult<MeshPrepareReceipt> {
    if config.payload_bytes < 64 || config.payload_bytes > MAX_COMMAND_BYTES {
        return Err(invalid(
            "IP mesh command payload must be 64 bytes through 1 MiB",
        ));
    }
    prepare_fresh_root(&config.root)?;
    let private = config.root.join("private");
    fs::create_dir(&private)?;
    let topic = Topic::new("lab.ip-mesh.commands")?;
    let scope = Scope::new("lab/ip-mesh")?;
    let member = ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()])?;
    let relay_access = ProvisioningAccess::relay(scope.clone(), vec![0])?;
    let mut authority_seed = [0_u8; 32];
    authority_seed[..8].copy_from_slice(&config.seed.to_be_bytes());
    authority_seed[8..16].copy_from_slice(&config.seed.rotate_left(17).to_be_bytes());
    authority_seed[16..24].copy_from_slice(&config.seed.rotate_left(31).to_be_bytes());
    authority_seed[24..].copy_from_slice(&config.seed.rotate_left(47).to_be_bytes());
    let mut provisioner = ReferenceProvisioner::from_seed(authority_seed)?;
    let publisher_bundle = provisioner
        .issue_node(1, std::slice::from_ref(&member))?
        .to_bytes()?;
    let relay_bundle = provisioner
        .issue_node(2, std::slice::from_ref(&relay_access))?
        .to_bytes()?;
    let consumer_bundle = provisioner
        .issue_node(3, std::slice::from_ref(&member))?
        .to_bytes()?;
    let authorization_control_subject =
        ReferenceEnvelopeSealer::open(provisioner.issue_node(4, std::slice::from_ref(&member))?)?
            .identity();
    let mut authorization_control_authority = ReferenceEnvelopeSealer::open(
        provisioner.issue_control_authority(5, std::slice::from_ref(&member))?,
    )?;
    let authorization_control_bytes =
        authorization_control_authority.seal_revocation(authorization_control_subject, 1)?;
    let authorization_control =
        SignedAuthorizationControl::from_sealed(authorization_control_bytes.clone())?;
    let authorization_control_sha256: [u8; 32] =
        Sha256::digest(&authorization_control_bytes).into();
    write_private_new(&private.join("a.bundle"), &publisher_bundle)?;
    write_private_new(&private.join("b.bundle"), &relay_bundle)?;
    write_private_new(&private.join("c.bundle"), &consumer_bundle)?;
    let mut discovery_token = [0_u8; 16];
    getrandom::fill(&mut discovery_token)?;
    write_private_new(
        &private.join("discovery.token"),
        hex(&discovery_token).as_bytes(),
    )?;

    let options = ip_mesh_application_options(config.payload_bytes)?;
    let a_root = config.root.join("a");
    let b_root = config.root.join("b");
    let c_root = config.root.join("c");
    for root in [&a_root, &b_root, &c_root] {
        fs::create_dir(root)?;
    }
    write_private_new(
        &b_root.join("gate-h-authorization-control.bin"),
        &authorization_control_bytes,
    )?;
    let mut publisher = ApplicationNode::open(
        a_root.join("state.sqlite"),
        &publisher_bundle,
        options.clone(),
    )?;
    let relay = ApplicationNode::open(b_root.join("state.sqlite"), &relay_bundle, options.clone())?;
    let mut consumer =
        ApplicationNode::open(c_root.join("state.sqlite"), &consumer_bundle, options)?;
    let publisher_id = publisher.identity();
    let relay_id = relay.identity();
    let consumer_id = consumer.identity();
    if BTreeSet::from([publisher_id, relay_id, consumer_id]).len() != 3 {
        return Err(invalid(
            "IP mesh provisioning produced duplicate identities",
        ));
    }
    let subscription =
        consumer.subscribe(topic.clone(), scope.clone(), Some(DataClass::Event), false)?;
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce)?;
    let mut payload = format!(
        "{{\"command\":\"CHECK_IN\",\"id\":\"demo-{:016x}\",\"nonce\":\"{}\"}}",
        config.seed,
        hex(&nonce)
    )
    .into_bytes();
    extend_mesh_payload(&mut payload, config.payload_bytes);
    payload.truncate(config.payload_bytes);
    let logical_key = format!("demo-{:016x}", config.seed).into_bytes();
    let published = publisher.publish(PublishRequest {
        class: DataClass::Event,
        topic: topic.clone(),
        scope: scope.clone(),
        priority: Priority::Immediate,
        ttl_ms: None,
        logical_key: logical_key.clone(),
        payload: payload.clone(),
        tombstone: false,
    })?;
    drop(publisher);
    drop(relay);
    drop(consumer);
    let envelope_id = single_data_envelope(
        &a_root.join("state.sqlite"),
        &publisher_bundle,
        &topic,
        &scope,
    )?;
    let payload_sha256: [u8; 32] = Sha256::digest(&payload).into();
    write_binary_new(&config.root.join("expected-payload.bin"), &payload)?;
    write_binary_new(&config.root.join("expected-logical-key.bin"), &logical_key)?;
    write_binary_new(&config.root.join("expected-item-id.bin"), &published.id)?;
    write_binary_new(
        &config.root.join("expected-publisher-id.bin"),
        &publisher_id,
    )?;
    write_binary_new(
        &config.root.join("expected-envelope-id.bin"),
        envelope_id.as_bytes(),
    )?;
    write_new(
        &config.root.join("subscription-id.txt"),
        subscription.0.to_string().as_bytes(),
    )?;
    let receipt = MeshPrepareReceipt {
        publisher: publisher_id,
        relay: relay_id,
        consumer: consumer_id,
        item_id: published.id,
        envelope_id,
        payload_sha256,
        subscription,
        topic,
        scope,
        authorization_control_id: authorization_control.envelope_id(),
        authorization_control_subject,
        authorization_control_sha256,
        authorization_control_bytes: authorization_control_bytes.len(),
    };
    write_new(
        &config.root.join("source-receipt.json"),
        receipt.to_json().as_bytes(),
    )?;
    Ok(receipt)
}

fn extend_mesh_payload(payload: &mut Vec<u8>, target_bytes: usize) {
    let mut payload_hasher = Sha256::new();
    payload_hasher.update(&payload);
    while payload.len() < target_bytes {
        // Cloning a SHA-256 state yields the digest of the exact current
        // prefix without re-hashing the growing payload on every 32-byte
        // extension. This preserves the original deterministic byte stream
        // while keeping the 1 MiB lab distribution linear-time.
        let digest = payload_hasher.clone().finalize();
        let remaining = target_bytes - payload.len();
        let chunk = &digest[..remaining.min(digest.len())];
        payload.extend_from_slice(chunk);
        payload_hasher.update(chunk);
    }
}

/// Privileged checkpoint written after A and the first B process are stopped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayCustodyReceipt {
    pub exact_envelope: bool,
    pub application_unreadable: bool,
    pub payload_absent_at_rest: bool,
    pub payload_digest_absent_at_rest: bool,
}

impl RelayCustodyReceipt {
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"schema\": \"aster-lab-ip-mesh-relay-custody/v1\",\n",
                "  \"exact_envelope\": {},\n",
                "  \"application_unreadable\": {},\n",
                "  \"payload_absent_at_rest\": {},\n",
                "  \"payload_digest_absent_at_rest\": {}\n",
                "}}"
            ),
            self.exact_envelope,
            self.application_unreadable,
            self.payload_absent_at_rest,
            self.payload_digest_absent_at_rest,
        )
    }
}

/// Verifies B's exact durable custody and route-only unreadability while B is
/// stopped, before C or the second B process starts.
pub fn verify_ip_mesh_relay_custody(
    root: &Path,
    invocation: &str,
) -> LabResult<RelayCustodyReceipt> {
    validate_invocation(invocation)?;
    let topic = Topic::new("lab.ip-mesh.commands")?;
    let scope = Scope::new("lab/ip-mesh")?;
    let relay_root = root.join("b");
    let relay_bundle = read_bounded(&root.join("private/b.bundle"), MAX_CREDENTIAL_BYTES)?;
    let expected_envelope = read_array::<32>(&root.join("expected-envelope-id.bin"))?;
    let expected_payload = read_bounded(&root.join("expected-payload.bin"), MAX_COMMAND_BYTES)?;
    let expected_digest: [u8; 32] = Sha256::digest(&expected_payload).into();
    let expected_key = read_bounded(&root.join("expected-logical-key.bin"), 4_096)?;
    let actual_envelope = single_data_envelope(
        &relay_root.join("state.sqlite"),
        &relay_bundle,
        &topic,
        &scope,
    )?;
    let exact_envelope = actual_envelope.as_bytes() == &expected_envelope;
    let options = ip_mesh_application_options(expected_payload.len())?;
    let mut relay = ApplicationNode::open(relay_root.join("state.sqlite"), &relay_bundle, options)?;
    let application_unreadable = relay
        .query(Query {
            topic: Some(topic),
            scope: Some(scope),
            class: Some(DataClass::Event),
            logical_key: Some(expected_key),
            limit: 2,
            ..Query::default()
        })
        .map_or(true, |items| items.is_empty());
    drop(relay);
    let payload_absent_at_rest = !tree_contains(&relay_root, &expected_payload)?;
    let payload_digest_absent_at_rest = !tree_contains(&relay_root, &expected_digest)?;
    let receipt = RelayCustodyReceipt {
        exact_envelope,
        application_unreadable,
        payload_absent_at_rest,
        payload_digest_absent_at_rest,
    };
    write_new(
        &root.join(format!("relay-custody-{invocation}.json")),
        receipt.to_json().as_bytes(),
    )?;
    if !exact_envelope
        || !application_unreadable
        || !payload_absent_at_rest
        || !payload_digest_absent_at_rest
    {
        return Err(invalid("route-only relay custody verification failed"));
    }
    Ok(receipt)
}

/// Exact application delivery and durable acknowledgement facts produced after
/// B and C have stopped their second contact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerDeliveryReceipt {
    pub same_item: bool,
    pub same_envelope: bool,
    pub application_acknowledged: bool,
    pub immediate_post_ack_deliveries: usize,
    pub post_restart_deliveries: usize,
    pub retained_query_items: usize,
}

impl ConsumerDeliveryReceipt {
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"schema\": \"aster-lab-ip-mesh-consumer-delivery/v1\",\n",
                "  \"same_item\": {},\n",
                "  \"same_envelope\": {},\n",
                "  \"application_acknowledged\": {},\n",
                "  \"immediate_post_ack_deliveries\": {},\n",
                "  \"post_restart_deliveries\": {},\n",
                "  \"retained_query_items\": {}\n",
                "}}"
            ),
            self.same_item,
            self.same_envelope,
            self.application_acknowledged,
            self.immediate_post_ack_deliveries,
            self.post_restart_deliveries,
            self.retained_query_items,
        )
    }
}

/// Delivers through C's pre-contact subscription, acknowledges only after the
/// exact demo sink check, then reopens C and proves no new redelivery.
pub fn consume_and_ack_ip_mesh(
    root: &Path,
    invocation: &str,
) -> LabResult<ConsumerDeliveryReceipt> {
    validate_invocation(invocation)?;
    let topic = Topic::new("lab.ip-mesh.commands")?;
    let scope = Scope::new("lab/ip-mesh")?;
    let consumer_root = root.join("c");
    let consumer_bundle = read_bounded(&root.join("private/c.bundle"), MAX_CREDENTIAL_BYTES)?;
    let expected_item = read_array::<32>(&root.join("expected-item-id.bin"))?;
    let expected_publisher = read_array::<32>(&root.join("expected-publisher-id.bin"))?;
    let expected_envelope = read_array::<32>(&root.join("expected-envelope-id.bin"))?;
    let expected_payload = read_bounded(&root.join("expected-payload.bin"), MAX_COMMAND_BYTES)?;
    let expected_key = read_bounded(&root.join("expected-logical-key.bin"), 4_096)?;
    let subscription_text = fs::read_to_string(root.join("subscription-id.txt"))?;
    let subscription = SubscriptionId(subscription_text.trim().parse()?);
    let options = ip_mesh_application_options(expected_payload.len())?;
    let mut consumer = ApplicationNode::open(
        consumer_root.join("state.sqlite"),
        &consumer_bundle,
        options.clone(),
    )?;
    let deliveries = consumer.poll(subscription, 2)?;
    if deliveries.len() != 1 {
        return Err(invalid(format!(
            "consumer expected one delivery, found {}",
            deliveries.len()
        )));
    }
    let delivered = &deliveries[0].item;
    let same_item = delivered.id == expected_item
        && delivered.publisher == expected_publisher
        && delivered.class == DataClass::Event
        && delivered.topic == topic
        && delivered.scope == scope
        && delivered.logical_key == expected_key
        && delivered.payload == expected_payload;
    if !same_item {
        return Err(invalid("consumer delivery changed the A-authored Event"));
    }
    write_binary_new(
        &root.join(format!("demo-sink-{invocation}.bin")),
        &delivered.payload,
    )?;
    consumer.acknowledge(subscription, delivered.id)?;
    let immediate_post_ack_deliveries = consumer.poll(subscription, 2)?.len();
    drop(consumer);
    let mut consumer = ApplicationNode::open(
        consumer_root.join("state.sqlite"),
        &consumer_bundle,
        options,
    )?;
    let post_restart_deliveries = consumer.poll(subscription, 2)?.len();
    let retained = consumer.query(Query {
        topic: Some(topic.clone()),
        scope: Some(scope.clone()),
        class: Some(DataClass::Event),
        logical_key: Some(expected_key),
        limit: 2,
        ..Query::default()
    })?;
    drop(consumer);
    let actual_envelope = single_data_envelope(
        &consumer_root.join("state.sqlite"),
        &consumer_bundle,
        &topic,
        &scope,
    )?;
    let receipt = ConsumerDeliveryReceipt {
        same_item,
        same_envelope: actual_envelope.as_bytes() == &expected_envelope,
        application_acknowledged: true,
        immediate_post_ack_deliveries,
        post_restart_deliveries,
        retained_query_items: retained.len(),
    };
    write_new(
        &root.join(format!("consumer-delivery-{invocation}.json")),
        receipt.to_json().as_bytes(),
    )?;
    if !receipt.same_envelope
        || receipt.immediate_post_ack_deliveries != 0
        || receipt.post_restart_deliveries != 0
        || receipt.retained_query_items != 1
    {
        return Err(invalid(
            "consumer acknowledgement/restart verification failed",
        ));
    }
    Ok(receipt)
}

/// Proves recontact did not create a second semantic Event or redeliver the
/// already acknowledged item.
pub fn verify_ip_mesh_duplicate_suppression(root: &Path, invocation: &str) -> LabResult<()> {
    validate_invocation(invocation)?;
    let topic = Topic::new("lab.ip-mesh.commands")?;
    let scope = Scope::new("lab/ip-mesh")?;
    let consumer_root = root.join("c");
    let consumer_bundle = read_bounded(&root.join("private/c.bundle"), MAX_CREDENTIAL_BYTES)?;
    let expected_item = read_array::<32>(&root.join("expected-item-id.bin"))?;
    let expected_key = read_bounded(&root.join("expected-logical-key.bin"), 4_096)?;
    let expected_payload = read_bounded(&root.join("expected-payload.bin"), MAX_COMMAND_BYTES)?;
    let subscription_text = fs::read_to_string(root.join("subscription-id.txt"))?;
    let subscription = SubscriptionId(subscription_text.trim().parse()?);
    let mut consumer = ApplicationNode::open(
        consumer_root.join("state.sqlite"),
        &consumer_bundle,
        ip_mesh_application_options(expected_payload.len())?,
    )?;
    let redeliveries = consumer.poll(subscription, 2)?.len();
    let items = consumer.query(Query {
        topic: Some(topic),
        scope: Some(scope),
        class: Some(DataClass::Event),
        logical_key: Some(expected_key),
        limit: 2,
        ..Query::default()
    })?;
    if redeliveries != 0 || items.len() != 1 || items[0].id != expected_item {
        return Err(invalid(
            "duplicate-suppression recontact verification failed",
        ));
    }
    write_new(
        &root.join(format!("duplicate-suppression-{invocation}.json")),
        b"{\"schema\":\"aster-lab-ip-mesh-duplicate/v1\",\"redeliveries\":0,\"items\":1}",
    )?;
    Ok(())
}

/// Versioned native-mesh worker configuration for one independently running
/// node process.
#[derive(Clone, Debug)]
pub struct NativeMeshNodeConfig {
    pub invocation: String,
    pub root: PathBuf,
    pub credential_path: PathBuf,
    pub topic: Topic,
    pub scope: Scope,
    pub discovery_token: [u8; 16],
    pub bind: SocketAddr,
    pub discovery_target: SocketAddr,
    pub max_candidates: usize,
    pub max_active_contacts: usize,
    pub run_for: Duration,
    /// Enables protected UDP discovery independently of the Aster emission policy.
    pub discovery_enabled: bool,
    pub expected_peers: BTreeSet<NodeId>,
    /// Comma-separated `ASTER_NODE_ID@IP:PORT` entries.
    pub manual_peers: String,
    /// `normal`, `constrained`, `receive-only`, or the paired Gate-H-only
    /// `flash-only` mode.
    pub emission_mode: String,
    /// Lab-only exact authority-signed control used by Proposal-0004 Gate H.
    pub gate_h_control_path: Option<PathBuf>,
    /// Peer whose already-generated outbound frame is retained for the Gate-H race.
    pub gate_h_stale_target_peer: Option<NodeId>,
    /// Exact durable ItemID observed through the process-owned authority.
    ///
    /// This avoids opening the live SQLite WAL from a host on the other side of
    /// a container bind mount, whose locking and mmap semantics are not a safe
    /// substitute for an in-process read.
    pub durable_item_probe: Option<ItemId>,
}

impl NativeMeshNodeConfig {
    pub fn validate(&self) -> LabResult<()> {
        if self.invocation.is_empty()
            || self.invocation.len() > 64
            || !self
                .invocation
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(invalid(
                "native mesh invocation must be 1-64 ASCII letters, digits, hyphens, or underscores",
            ));
        }
        if self.max_candidates == 0 || self.max_candidates > MAX_CANDIDATES_HARD {
            return Err(invalid(
                "native mesh candidate bound must be between 1 and 1024",
            ));
        }
        if self.max_active_contacts == 0 || self.max_active_contacts > self.max_candidates {
            return Err(invalid(
                "active-contact bound must be nonzero and no larger than candidate capacity",
            ));
        }
        if self.run_for.is_zero() {
            return Err(invalid("native mesh runtime must be nonzero"));
        }
        let SocketAddr::V4(target) = self.discovery_target else {
            return Err(invalid(
                "native mesh experiment currently requires IPv4 local discovery",
            ));
        };
        if target.ip().is_unspecified() || target.port() == 0 {
            return Err(invalid(
                "native mesh discovery target must be a concrete multicast or broadcast address",
            ));
        }
        if !matches!(self.bind, SocketAddr::V4(_)) || self.bind.port() != target.port() {
            return Err(invalid(
                "native mesh bind must be IPv4 and use the multicast port",
            ));
        }
        if self.discovery_token == [0; 16] {
            return Err(invalid("native mesh discovery token cannot be zero"));
        }
        let _ = native_emission_policy(&self.emission_mode)?;
        let manual = parse_native_manual_peers(&self.manual_peers)?;
        if manual.len() > self.max_candidates {
            return Err(invalid(
                "native mesh manual peer list exceeds candidate capacity",
            ));
        }
        match (&self.gate_h_control_path, self.gate_h_stale_target_peer) {
            (None, None) if self.emission_mode != "flash-only" => {}
            (None, None) => {
                return Err(invalid(
                    "flash-only mode is reserved for paired Gate-H live-control options",
                ));
            }
            (Some(_), Some(target))
                if target != [0; 32]
                    && self.expected_peers.len() == 2
                    && self.expected_peers.contains(&target)
                    && self.max_active_contacts >= 2
                    && self.emission_mode == "flash-only" => {}
            (Some(_), Some(_)) => {
                return Err(invalid(
                    "Gate-H live control requires flash-only mode, two expected peers including its target, and two active-contact slots",
                ));
            }
            _ => {
                return Err(invalid(
                    "--gate-h-control and --gate-h-stale-target-peer must be configured together",
                ));
            }
        }
        Ok(())
    }
}

/// Final bounded worker receipt. It is operational contact evidence, not a
/// global convergence claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeMeshNodeReceipt {
    pub identity: NodeId,
    pub carrier_id: [u8; 32],
    pub candidates_discovered: u64,
    pub candidates_rejected_capacity: u64,
    pub authenticated_peers: BTreeSet<NodeId>,
    pub admitted_peers: BTreeSet<NodeId>,
    pub unauthorized_peers: BTreeSet<NodeId>,
    pub contact_failures: u64,
    pub duplicate_contacts: u64,
    pub aster_frames_received: u64,
    pub aster_frames_sent: u64,
    pub aster_bytes_received: u64,
    pub aster_bytes_sent: u64,
    pub carrier_control_frames_received: u64,
    pub carrier_control_frames_sent: u64,
    pub carrier_control_bytes_received: u64,
    pub carrier_control_bytes_sent: u64,
    pub pump_calls: u64,
    pub discovery_announcements: u64,
    pub elapsed_ms: u64,
    pub first_candidate_ms: Option<u64>,
    pub first_authenticated_ms: Option<u64>,
    pub active_contact_high_water: usize,
    pub admitted_contact_high_water: usize,
    pub sqlite_node_open_count: u64,
    pub blob_authority_open_count: u64,
    pub semantic_backend_construction_count: u64,
    pub process_authority_construction_count: u64,
    pub durable_authority_open_count: u64,
    pub authorization_generation_checks: u64,
    pub authorization_generation_mismatches: u64,
    pub authorization_generation_unavailable: u64,
    pub authorization_generation_current: u64,
    pub durable_item_probe_id: Option<ItemId>,
    pub durable_item_present: Option<bool>,
    pub gate_h_control_id: Option<EnvelopeId>,
    pub gate_h_generation_before: Option<u64>,
    pub gate_h_generation_after: Option<u64>,
    pub gate_h_stale_target_peer: Option<NodeId>,
    pub gate_h_stale_target_contact: Option<ContactId>,
    pub gate_h_stale_queued_frames: usize,
    pub gate_h_stale_send_frames_before: u64,
    pub gate_h_stale_send_frames_after: u64,
    pub gate_h_stale_send_bytes_before: u64,
    pub gate_h_stale_send_bytes_after: u64,
    pub gate_h_stale_zero_bytes_emitted: bool,
    pub gate_h_stale_contacts_retired: usize,
    pub gate_h_provider_epoch_rotations: u64,
    pub gate_h_fresh_target_contact: Option<ContactId>,
    pub gate_h_fresh_target_generation: Option<u64>,
    pub gate_h_fresh_aster_frames_sent: u64,
    pub gate_h_fresh_aster_bytes_sent: u64,
    pub gate_h_completed: bool,
    pub node_resources: NodeResourceSnapshot,
}

impl NativeMeshNodeReceipt {
    pub fn to_json(&self) -> String {
        let first_candidate = self
            .first_candidate_ms
            .map_or_else(|| "null".to_owned(), |value| value.to_string());
        let first_authenticated = self
            .first_authenticated_ms
            .map_or_else(|| "null".to_owned(), |value| value.to_string());
        let gate_h_control_id = self.gate_h_control_id.map_or_else(
            || "null".to_owned(),
            |value| format!("\"{}\"", hex(value.as_bytes())),
        );
        let gate_h_generation_before = self
            .gate_h_generation_before
            .map_or_else(|| "null".to_owned(), |value| value.to_string());
        let gate_h_generation_after = self
            .gate_h_generation_after
            .map_or_else(|| "null".to_owned(), |value| value.to_string());
        let gate_h_stale_target_peer = self
            .gate_h_stale_target_peer
            .map_or_else(|| "null".to_owned(), |value| format!("\"{}\"", hex(&value)));
        let gate_h_stale_target_contact = self
            .gate_h_stale_target_contact
            .map_or_else(|| "null".to_owned(), |value| value.0.to_string());
        let gate_h_fresh_target_contact = self
            .gate_h_fresh_target_contact
            .map_or_else(|| "null".to_owned(), |value| value.0.to_string());
        let gate_h_fresh_target_generation = self
            .gate_h_fresh_target_generation
            .map_or_else(|| "null".to_owned(), |value| value.to_string());
        let durable_item_probe_id = self
            .durable_item_probe_id
            .map_or_else(|| "null".to_owned(), |value| format!("\"{}\"", hex(&value)));
        let durable_item_present = self
            .durable_item_present
            .map_or_else(|| "null".to_owned(), |value| value.to_string());
        format!(
            concat!(
                "{{\n",
                "  \"schema\": \"aster-lab-native-mesh-node/v2\",\n",
                "  \"identity\": \"{}\",\n",
                "  \"carrier_id\": \"{}\",\n",
                "  \"candidates_discovered\": {},\n",
                "  \"candidates_rejected_capacity\": {},\n",
                "  \"authenticated_peers\": {},\n",
                "  \"admitted_peers\": {},\n",
                "  \"unauthorized_peers\": {},\n",
                "  \"contact_failures\": {},\n",
                "  \"duplicate_contacts\": {},\n",
                "  \"frame_counter_scope\": \"aster_protocol\",\n",
                "  \"frames_received\": {},\n",
                "  \"frames_sent\": {},\n",
                "  \"aster_frames_received\": {},\n",
                "  \"aster_frames_sent\": {},\n",
                "  \"aster_bytes_received\": {},\n",
                "  \"aster_bytes_sent\": {},\n",
                "  \"carrier_control_frames_received\": {},\n",
                "  \"carrier_control_frames_sent\": {},\n",
                "  \"carrier_control_bytes_received\": {},\n",
                "  \"carrier_control_bytes_sent\": {},\n",
                "  \"pump_calls\": {},\n",
                "  \"discovery_announcements\": {},\n",
                "  \"elapsed_ms\": {},\n",
                "  \"first_candidate_ms\": {},\n",
                "  \"first_authenticated_ms\": {},\n",
                "  \"active_contact_high_water\": {},\n",
                "  \"admitted_contact_high_water\": {},\n",
                "  \"sqlite_node_open_count\": {},\n",
                "  \"blob_authority_open_count\": {},\n",
                "  \"semantic_backend_construction_count\": {},\n",
                "  \"process_authority_construction_count\": {},\n",
                "  \"durable_authority_open_count\": {},\n",
                "  \"authorization_generation_checks\": {},\n",
                "  \"authorization_generation_mismatches\": {},\n",
                "  \"authorization_generation_unavailable\": {},\n",
                "  \"authorization_generation_current\": {},\n",
                "  \"durable_item_probe_id\": {},\n",
                "  \"durable_item_present\": {},\n",
                "  \"gate_h_control_id\": {},\n",
                "  \"gate_h_generation_before\": {},\n",
                "  \"gate_h_generation_after\": {},\n",
                "  \"gate_h_stale_target_peer\": {},\n",
                "  \"gate_h_stale_target_contact\": {},\n",
                "  \"gate_h_stale_queued_frames\": {},\n",
                "  \"gate_h_stale_send_frames_before\": {},\n",
                "  \"gate_h_stale_send_frames_after\": {},\n",
                "  \"gate_h_stale_send_bytes_before\": {},\n",
                "  \"gate_h_stale_send_bytes_after\": {},\n",
                "  \"gate_h_stale_zero_bytes_emitted\": {},\n",
                "  \"gate_h_stale_contacts_retired\": {},\n",
                "  \"gate_h_provider_epoch_rotations\": {},\n",
                "  \"gate_h_fresh_target_contact\": {},\n",
                "  \"gate_h_fresh_target_generation\": {},\n",
                "  \"gate_h_fresh_aster_frames_sent\": {},\n",
                "  \"gate_h_fresh_aster_bytes_sent\": {},\n",
                "  \"gate_h_completed\": {},\n",
                "  \"node_resource_limits\": {},\n",
                "  \"node_resource_current\": {},\n",
                "  \"node_resource_high_water\": {},\n",
                "  \"node_resource_rejections\": {},\n",
                "  \"node_resource_rejected_claims\": {}\n",
                "}}"
            ),
            hex(&self.identity),
            hex(&self.carrier_id),
            self.candidates_discovered,
            self.candidates_rejected_capacity,
            json_node_set(&self.authenticated_peers),
            json_node_set(&self.admitted_peers),
            json_node_set(&self.unauthorized_peers),
            self.contact_failures,
            self.duplicate_contacts,
            self.aster_frames_received,
            self.aster_frames_sent,
            self.aster_frames_received,
            self.aster_frames_sent,
            self.aster_bytes_received,
            self.aster_bytes_sent,
            self.carrier_control_frames_received,
            self.carrier_control_frames_sent,
            self.carrier_control_bytes_received,
            self.carrier_control_bytes_sent,
            self.pump_calls,
            self.discovery_announcements,
            self.elapsed_ms,
            first_candidate,
            first_authenticated,
            self.active_contact_high_water,
            self.admitted_contact_high_water,
            self.sqlite_node_open_count,
            self.blob_authority_open_count,
            self.semantic_backend_construction_count,
            self.process_authority_construction_count,
            self.durable_authority_open_count,
            self.authorization_generation_checks,
            self.authorization_generation_mismatches,
            self.authorization_generation_unavailable,
            self.authorization_generation_current,
            durable_item_probe_id,
            durable_item_present,
            gate_h_control_id,
            gate_h_generation_before,
            gate_h_generation_after,
            gate_h_stale_target_peer,
            gate_h_stale_target_contact,
            self.gate_h_stale_queued_frames,
            self.gate_h_stale_send_frames_before,
            self.gate_h_stale_send_frames_after,
            self.gate_h_stale_send_bytes_before,
            self.gate_h_stale_send_bytes_after,
            self.gate_h_stale_zero_bytes_emitted,
            self.gate_h_stale_contacts_retired,
            self.gate_h_provider_epoch_rotations,
            gate_h_fresh_target_contact,
            gate_h_fresh_target_generation,
            self.gate_h_fresh_aster_frames_sent,
            self.gate_h_fresh_aster_bytes_sent,
            self.gate_h_completed,
            json_node_resource_limits(self.node_resources.limits),
            json_node_resource_claim(self.node_resources.current),
            json_node_resource_claim(self.node_resources.high_water),
            json_node_resource_claim(self.node_resources.rejections),
            self.node_resources.rejected_claims,
        )
    }
}

#[derive(Default)]
struct ContactQueue {
    frames: VecDeque<Vec<u8>>,
    bytes: usize,
}

struct NativeContactLink {
    raw: Arc<IpLink>,
    _base_resources: Arc<NodeProviderResourceLease>,
    route: NodeId,
    local_carrier: NativeCarrierHello,
    remote_carrier: NativeCarrierHello,
    inbound: Arc<Mutex<ContactQueue>>,
    sent: Arc<Mutex<NativeAsterSendCounters>>,
    contact_sent: Arc<Mutex<NativeAsterSendCounters>>,
    gate_h_barrier: Arc<Mutex<NativeGateHSendBarrier>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct NativeAsterSendCounters {
    frames: u64,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct NativeGateHSendBarrier {
    target_route: Option<NodeId>,
    enabled: bool,
    blocked_frames: u64,
    blocked_bytes: u64,
}

impl Link for NativeContactLink {
    fn name(&self) -> &str {
        "aster-lab-native-mesh-contact"
    }

    fn characteristics(&self) -> LinkCharacteristics {
        let mut characteristics = self.raw.characteristics();
        characteristics.mtu = characteristics
            .mtu
            .saturating_sub(u16::try_from(CARRIER_DATA_HEADER_LEN).unwrap_or(u16::MAX));
        characteristics
    }

    fn send(&self, _peer: Option<NodeId>, frame: &[u8]) -> io::Result<()> {
        {
            let mut barrier = self.gate_h_barrier.lock().map_err(lock_error)?;
            if barrier.enabled && barrier.target_route == Some(self.route) {
                barrier.blocked_frames = barrier.blocked_frames.saturating_add(1);
                barrier.blocked_bytes = barrier
                    .blocked_bytes
                    .saturating_add(u64::try_from(frame.len()).unwrap_or(u64::MAX));
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Gate-H retained outbound Aster frame",
                ));
            }
        }
        let carrier_frame = encode_carrier_data(self.local_carrier, self.remote_carrier, frame)?;
        self.raw.send(Some(self.route), &carrier_frame)?;
        let mut sent = self.sent.lock().map_err(lock_error)?;
        sent.frames = sent.frames.saturating_add(1);
        sent.bytes = sent
            .bytes
            .saturating_add(u64::try_from(frame.len()).unwrap_or(u64::MAX));
        let mut contact_sent = self.contact_sent.lock().map_err(lock_error)?;
        contact_sent.frames = contact_sent.frames.saturating_add(1);
        contact_sent.bytes = contact_sent
            .bytes
            .saturating_add(u64::try_from(frame.len()).unwrap_or(u64::MAX));
        Ok(())
    }

    fn try_receive(&self) -> io::Result<Option<ReceivedFrame>> {
        let mut queue = self.inbound.lock().map_err(lock_error)?;
        let Some(bytes) = queue.frames.pop_front() else {
            return Ok(None);
        };
        queue.bytes = queue.bytes.saturating_sub(bytes.len());
        Ok(Some(ReceivedFrame { peer: None, bytes }))
    }

    fn set_discovery(&self, enabled: bool) -> io::Result<()> {
        self.raw.set_discovery(enabled)
    }

    fn next_wakeup(&self) -> Option<Instant> {
        self.raw.next_wakeup()
    }

    fn retry_floor(&self) -> Duration {
        self.raw.retry_floor()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeManualPeer {
    peer: NodeId,
    address: SocketAddr,
}

#[derive(Clone)]
struct NativeEndpoint {
    candidate: CandidateId,
    provenance: CandidateProvenance,
    address: SocketAddr,
    route: NodeId,
    last_hello_sent: Option<Instant>,
    retired_instances: VecDeque<NativeCarrierHello>,
}

struct PendingNativeDial {
    locator: CandidateLocator,
    route: NodeId,
    deadline: Instant,
    next_hello: Instant,
}

struct NativeContact {
    contact: ContactId,
    address: SocketAddr,
    route: NodeId,
    inbound: Arc<Mutex<ContactQueue>>,
    admitted_peer: Option<NodeId>,
    remote_instance: NativeCarrierHello,
    sent: Arc<Mutex<NativeAsterSendCounters>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeCarrierHello {
    carrier_id: [u8; CARRIER_ID_BYTES],
    instance_nonce: [u8; CARRIER_INSTANCE_NONCE_BYTES],
}

struct NativeProvider {
    base_resources: Arc<NodeProviderResourceLease>,
    endpoints: BTreeMap<CandidateLocator, NativeEndpoint>,
    route_to_locator: BTreeMap<NodeId, CandidateLocator>,
    pending_dials: BTreeMap<CandidateId, PendingNativeDial>,
    contacts: BTreeMap<ContactId, NativeContact>,
    route_contacts: BTreeMap<NodeId, ContactId>,
    next_contact: u64,
    discovery_enabled: bool,
    gate_h_barrier: Arc<Mutex<NativeGateHSendBarrier>>,
}

impl NativeProvider {
    fn new(base_resources: NodeProviderResourceLease) -> Self {
        Self {
            base_resources: Arc::new(base_resources),
            endpoints: BTreeMap::new(),
            route_to_locator: BTreeMap::new(),
            pending_dials: BTreeMap::new(),
            contacts: BTreeMap::new(),
            route_contacts: BTreeMap::new(),
            next_contact: 1,
            discovery_enabled: false,
            gate_h_barrier: Arc::new(Mutex::new(NativeGateHSendBarrier::default())),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeGateHLivePhase {
    AwaitingTwoAdmittedContacts,
    AwaitingRetainedFrame,
    AwaitingFreshTargetAdmission,
    AwaitingFreshTargetProgress {
        contact: ContactId,
        baseline: NativeAsterSendCounters,
    },
    Complete,
}

struct NativeGateHLiveControl {
    control: SignedAuthorizationControl,
    target_peer: NodeId,
    phase: NativeGateHLivePhase,
    stale_target_contact: Option<ContactId>,
    stale_target_remote_instance: Option<NativeCarrierHello>,
}

fn load_native_gate_h_live_control(
    config: &NativeMeshNodeConfig,
) -> LabResult<Option<NativeGateHLiveControl>> {
    let (Some(path), Some(target_peer)) = (
        config.gate_h_control_path.as_ref(),
        config.gate_h_stale_target_peer,
    ) else {
        return Ok(None);
    };
    let expected_path = config.root.join("gate-h-authorization-control.bin");
    if path != &expected_path {
        return Err(invalid(
            "Gate-H control must use the prepared node-local control path",
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > u64::try_from(MAX_COMMAND_BYTES)?
    {
        return Err(invalid(
            "Gate-H control must be a nonempty, regular, non-symlink file no larger than 1 MiB",
        ));
    }
    let sealed = read_bounded(path, MAX_COMMAND_BYTES)?;
    let control = SignedAuthorizationControl::from_sealed(sealed)?;
    Ok(Some(NativeGateHLiveControl {
        control,
        target_peer,
        phase: NativeGateHLivePhase::AwaitingTwoAdmittedContacts,
        stale_target_contact: None,
        stale_target_remote_instance: None,
    }))
}

fn native_contact_sent(
    provider: &NativeProvider,
    contact: ContactId,
) -> LabResult<NativeAsterSendCounters> {
    let sent = provider
        .contacts
        .get(&contact)
        .ok_or_else(|| invalid("Gate-H contact disappeared before evidence capture"))?
        .sent
        .lock()
        .map_err(lock_error)?;
    Ok(*sent)
}

fn native_provider_resource_claim() -> NodeResourceClaim {
    NodeResourceClaim {
        tasks: 1,
        frames: NATIVE_PROVIDER_PRE_CANDIDATE_FRAME_SLOTS,
        inbound_bytes: NATIVE_PROVIDER_RECEIVE_SCRATCH_BYTES,
        descriptors: 1,
        ..NodeResourceClaim::default()
    }
}

fn initialize_native_provider<T>(
    supervisor: &SharedNodeContactSupervisor,
    initialize: impl FnOnce() -> io::Result<T>,
) -> LabResult<(NativeProvider, T)> {
    // This must remain the first fallible operation: the closure may bind a
    // socket, allocate provider maps/buffers, or start provider-owned work.
    let base_resources = supervisor.reserve_provider_resources(native_provider_resource_claim())?;
    let resource = initialize()?;
    Ok((NativeProvider::new(base_resources), resource))
}

fn remember_retired_native_instance(endpoint: &mut NativeEndpoint, instance: NativeCarrierHello) {
    if endpoint.retired_instances.contains(&instance) {
        return;
    }
    if endpoint.retired_instances.len() >= MAX_RETIRED_CARRIER_INSTANCES_PER_ENDPOINT {
        endpoint.retired_instances.pop_front();
    }
    endpoint.retired_instances.push_back(instance);
}

fn native_runtime_limits() -> RuntimeLimits {
    RuntimeLimits {
        max_in_flight_logical_frames: 8,
        max_reassembly_bytes: 1_024 * 1_024,
        max_received_frames_per_pump: 256,
        max_unauthenticated_failures_per_pump: 16,
        max_pending_retries: 32,
        max_pending_outbox: 32,
        max_pending_logical_bytes: 1_024 * 1_024,
        deferred_want_epoch_reserve: 128 * 1_024,
        max_retry_sends_per_pump: 32,
        max_completed_transfers: 128,
        ..RuntimeLimits::default()
    }
}

fn native_contact_resource_claims(runtime: RuntimeLimits) -> LabResult<ContactResourceClaims> {
    let runtime_frame_metadata = runtime
        .max_in_flight_logical_frames
        .checked_mul(2)
        .and_then(|value| value.checked_add(runtime.max_pending_outbox))
        .and_then(|value| value.checked_add(runtime.max_pending_retries))
        .and_then(|value| {
            runtime
                .max_completed_transfers
                .checked_mul(2)
                .and_then(|completed| value.checked_add(completed))
        })
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| invalid("native runtime frame reservation overflow"))?;
    let frames = runtime_frame_metadata
        .checked_add(MAX_INBOUND_FRAMES_PER_CONTACT)
        .ok_or_else(|| invalid("native contact frame reservation overflow"))?;
    let inbound_bytes = runtime
        .retained_inbound_payload_bytes()
        .checked_add(MAX_INBOUND_BYTES_PER_CONTACT)
        .ok_or_else(|| invalid("native contact inbound reservation overflow"))?;
    let outbound_bytes = runtime.retained_outbound_payload_bytes();
    let contact_claim = |admitted: bool| NodeResourceClaim {
        pre_authentication_contacts: usize::from(!admitted),
        admitted_contacts: usize::from(admitted),
        streams: 1,
        tasks: 1,
        frames,
        inbound_bytes,
        outbound_bytes,
        ..NodeResourceClaim::default()
    };
    Ok(ContactResourceClaims::new(
        NodeResourceClaim {
            candidates: 1,
            ..NodeResourceClaim::default()
        },
        NodeResourceClaim {
            pending_connections: 1,
            ..NodeResourceClaim::default()
        },
        contact_claim(false),
        contact_claim(true),
    )?)
}

fn native_node_resource_limits(config: &NativeMeshNodeConfig) -> LabResult<NodeResourceLimits> {
    let tasks = config
        .max_active_contacts
        .checked_add(1)
        .ok_or_else(|| invalid("native provider task limit overflow"))?;
    Ok(NodeResourceLimits {
        candidates: config.max_candidates,
        pending_connections: config.max_active_contacts,
        pre_authentication_contacts: config.max_active_contacts,
        admitted_contacts: config.max_active_contacts,
        streams: config.max_active_contacts,
        tasks,
        frames: 8_192,
        inbound_bytes: 8 * 1_024 * 1_024,
        outbound_bytes: 8 * 1_024 * 1_024,
        descriptors: 1,
        relay_reservations: 0,
    })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct NativeAuthorityConstructionFacts {
    sqlite_node_open_count: u64,
    blob_authority_open_count: u64,
    semantic_backend_construction_count: u64,
    process_authority_construction_count: u64,
}

fn open_native_shared_supervisor(
    config: &NativeMeshNodeConfig,
    emission: EmissionPolicy,
    credentials: Vec<u8>,
) -> LabResult<(
    NodeId,
    SharedNodeContactSupervisor,
    NativeAuthorityConstructionFacts,
)> {
    open_native_shared_supervisor_with_limits(
        config,
        emission,
        credentials,
        native_node_resource_limits(config)?,
    )
}

fn open_native_shared_supervisor_with_limits(
    config: &NativeMeshNodeConfig,
    emission: EmissionPolicy,
    credentials: Vec<u8>,
    node_resource_limits: NodeResourceLimits,
) -> LabResult<(
    NodeId,
    SharedNodeContactSupervisor,
    NativeAuthorityConstructionFacts,
)> {
    let mut construction = NativeAuthorityConstructionFacts::default();
    let provisioning = UnprotectedProvisioning::new(credentials)?;
    let bundle = ProvisioningBundle::from_bytes(provisioning.expose())?;
    let node = open_reference_node(
        config.root.join("state.sqlite"),
        bundle,
        NodeConfig {
            emission,
            ..NodeConfig::default()
        },
    )?;
    construction.sqlite_node_open_count = construction.sqlite_node_open_count.saturating_add(1);
    let identity = node.identity();
    let blobs =
        BlobTransferStore::open_with_config(config.root.join("blobs"), BlobStoreConfig::default())?;
    construction.blob_authority_open_count =
        construction.blob_authority_open_count.saturating_add(1);
    let backend = ReferenceSemanticRuntimeBackend::new(node, blobs)?;
    construction.semantic_backend_construction_count = construction
        .semantic_backend_construction_count
        .saturating_add(1);
    let authority = ReferenceSemanticRuntimeAuthority::new(backend);
    construction.process_authority_construction_count = construction
        .process_authority_construction_count
        .saturating_add(1);
    let host = MeshHost::new(
        HostConfig {
            max_candidates: config.max_candidates,
            max_active_contacts: config.max_active_contacts,
            candidate_ttl: NATIVE_CANDIDATE_TTL,
            contact_quantum: NATIVE_CONTACT_QUANTUM,
            reconnect_initial: Duration::from_millis(250),
            reconnect_max: Duration::from_secs(30),
        },
        emission,
    )?;
    let runtime = native_runtime_limits();
    let mut supervisor_config = ContactSupervisorConfig::new(
        SyncConfig::default(),
        runtime,
        StartRequest {
            exchange_id: 0,
            topics: vec![config.topic.as_str().to_owned()],
            scopes: vec![config.scope.as_str().to_owned()],
            // Emission constrains what this node transmits. It never narrows
            // inbound interest: constrained and radio-silent nodes still
            // request and durably custody Routine-or-higher mission traffic.
            min_priority: Priority::Routine as u8,
        },
        NATIVE_PRE_AUTHENTICATION_TIMEOUT,
        native_contact_resource_claims(runtime)?,
    )?;
    if !config.expected_peers.is_empty() {
        supervisor_config = supervisor_config.with_allowed_peers(config.expected_peers.clone())?;
    }
    let supervisor = SharedNodeContactSupervisor::new(
        host,
        NodeResourceBudget::new(node_resource_limits)?,
        authority,
        provisioning,
        supervisor_config,
    )?;
    Ok((identity, supervisor, construction))
}

/// Runs one bounded native MeshHost-composed IP mesh node.
pub fn run_native_mesh_node(config: &NativeMeshNodeConfig) -> LabResult<NativeMeshNodeReceipt> {
    config.validate()?;
    let emission = native_emission_policy(&config.emission_mode)?;
    let manual = parse_native_manual_peers(&config.manual_peers)?;
    fs::create_dir_all(&config.root)?;
    let database_path = config.root.join("state.sqlite");
    if !database_path.is_file() {
        return Err(invalid(
            "native mesh node store must be initialized by the offline preparation step",
        ));
    }
    let credentials = read_bounded(&config.credential_path, MAX_CREDENTIAL_BYTES)?;
    let (identity, mut supervisor, construction) =
        open_native_shared_supervisor(config, emission, credentials)?;
    let carrier_id = load_or_create_carrier_id(&config.root)?;
    let mut local_carrier = NativeCarrierHello {
        carrier_id,
        instance_nonce: new_native_carrier_instance_nonce()?,
    };
    let (mut provider, raw) = initialize_native_provider(&supervisor, || {
        if config.discovery_target.ip().is_multicast() {
            IpLink::bind_shared_multicast(
                "aster-lab-native-mesh",
                config.bind,
                config.discovery_token,
                config.discovery_target,
            )
        } else {
            IpLink::bind(
                "aster-lab-native-mesh",
                config.bind,
                config.discovery_token,
                Some(config.discovery_target),
            )
        }
    })?;
    let raw = Arc::new(raw);
    // MeshHost is the sole source of provider-discovery policy. Start closed
    // so a constrained or receive-only node cannot process one discovery
    // packet before the first host plan is applied.
    raw.set_discovery(false)?;
    let events_path = config
        .root
        .join(format!("native-mesh-{}-events.jsonl", config.invocation));
    let status_path = config
        .root
        .join(format!("native-mesh-{}-status.json", config.invocation));
    let final_path = config
        .root
        .join(format!("native-mesh-{}-final.json", config.invocation));
    if final_path.exists() {
        return Err(invalid("native mesh final receipt already exists"));
    }
    append_event(
        &events_path,
        &format!(
            "{{\"event\":\"started\",\"identity\":\"{}\",\"carrier_id\":\"{}\",\"carrier_instance_nonce\":\"{}\"}}",
            hex(&identity),
            hex(&carrier_id),
            hex(&local_carrier.instance_nonce)
        ),
    )?;

    let started = Instant::now();
    let deadline = started
        .checked_add(config.run_for)
        .ok_or_else(|| invalid("native mesh deadline overflow"))?;
    let mut next_discovery = started;
    let mut next_status = started;
    let aster_sent = Arc::new(Mutex::new(NativeAsterSendCounters::default()));
    let mut receipt = NativeMeshNodeReceipt {
        identity,
        carrier_id,
        candidates_discovered: 0,
        candidates_rejected_capacity: 0,
        authenticated_peers: BTreeSet::new(),
        admitted_peers: BTreeSet::new(),
        unauthorized_peers: BTreeSet::new(),
        contact_failures: 0,
        duplicate_contacts: 0,
        aster_frames_received: 0,
        aster_frames_sent: 0,
        aster_bytes_received: 0,
        aster_bytes_sent: 0,
        carrier_control_frames_received: 0,
        carrier_control_frames_sent: 0,
        carrier_control_bytes_received: 0,
        carrier_control_bytes_sent: 0,
        pump_calls: 0,
        discovery_announcements: 0,
        elapsed_ms: 0,
        first_candidate_ms: None,
        first_authenticated_ms: None,
        active_contact_high_water: 0,
        admitted_contact_high_water: 0,
        sqlite_node_open_count: construction.sqlite_node_open_count,
        blob_authority_open_count: construction.blob_authority_open_count,
        semantic_backend_construction_count: construction.semantic_backend_construction_count,
        process_authority_construction_count: construction.process_authority_construction_count,
        durable_authority_open_count: construction.process_authority_construction_count,
        authorization_generation_checks: 0,
        authorization_generation_mismatches: 0,
        authorization_generation_unavailable: 0,
        authorization_generation_current: 0,
        durable_item_probe_id: config.durable_item_probe,
        durable_item_present: None,
        gate_h_control_id: None,
        gate_h_generation_before: None,
        gate_h_generation_after: None,
        gate_h_stale_target_peer: None,
        gate_h_stale_target_contact: None,
        gate_h_stale_queued_frames: 0,
        gate_h_stale_send_frames_before: 0,
        gate_h_stale_send_frames_after: 0,
        gate_h_stale_send_bytes_before: 0,
        gate_h_stale_send_bytes_after: 0,
        gate_h_stale_zero_bytes_emitted: false,
        gate_h_stale_contacts_retired: 0,
        gate_h_provider_epoch_rotations: 0,
        gate_h_fresh_target_contact: None,
        gate_h_fresh_target_generation: None,
        gate_h_fresh_aster_frames_sent: 0,
        gate_h_fresh_aster_bytes_sent: 0,
        gate_h_completed: false,
        node_resources: supervisor.resource_snapshot()?,
    };
    let mut gate_h_live_control = load_native_gate_h_live_control(config)?;
    if let Some(gate_h) = gate_h_live_control.as_ref() {
        receipt.gate_h_control_id = Some(gate_h.control.envelope_id());
        receipt.gate_h_stale_target_peer = Some(gate_h.target_peer);
    }

    for peer in manual {
        let candidate = CandidateId::new(format!("manual:{}", hex(&peer.peer)))?;
        let locator = CandidateLocator::new(peer.address.to_string())?;
        observe_native_endpoint(
            &raw,
            &mut supervisor,
            &mut provider,
            candidate,
            locator,
            peer.address,
            CandidateProvenance::Manual,
            Some(peer.peer),
            started,
        )?;
        append_event(
            &events_path,
            &format!(
                "{{\"event\":\"candidate_configured\",\"peer\":\"{}\",\"address\":\"{}\"}}",
                hex(&peer.peer),
                peer.address
            ),
        )?;
    }
    let initial_plan = supervisor.plan(started)?;
    receipt.candidates_rejected_capacity = receipt
        .candidates_rejected_capacity
        .saturating_add(u64::try_from(initial_plan.dial_resource_rejections)?);
    apply_native_actions(
        initial_plan.actions,
        &mut supervisor,
        &raw,
        &mut provider,
        &mut receipt,
        &events_path,
        local_carrier,
        config.discovery_enabled,
        started,
        deadline,
    )?;

    while Instant::now() < deadline {
        let now = Instant::now();
        expire_native_dials(
            &mut supervisor,
            &raw,
            &mut provider,
            &mut receipt,
            &events_path,
            local_carrier,
            now,
        )?;
        if provider.discovery_enabled && now >= next_discovery {
            match raw.announce() {
                Ok(()) => {
                    receipt.discovery_announcements =
                        receipt.discovery_announcements.saturating_add(1);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            next_discovery = now.checked_add(DISCOVERY_INTERVAL).unwrap_or(deadline);
        } else if !provider.discovery_enabled {
            next_discovery = deadline;
        }

        let hellos = drain_native_frames(&raw, &mut provider, &mut receipt, local_carrier)?;
        for (route, remote_carrier) in hellos {
            handle_native_hello(
                route,
                remote_carrier,
                &mut supervisor,
                &raw,
                &mut provider,
                &aster_sent,
                &mut receipt,
                &events_path,
                local_carrier,
                now,
            )?;
        }
        for address in raw.take_discovered() {
            if !provider.discovery_enabled {
                continue;
            }
            let candidate = CandidateId::new(format!("auto:{address}"))?;
            let locator = CandidateLocator::new(address.to_string())?;
            match observe_native_endpoint(
                &raw,
                &mut supervisor,
                &mut provider,
                candidate,
                locator,
                address,
                CandidateProvenance::Automatic,
                None,
                now,
            ) {
                Ok(true) => {
                    receipt.candidates_discovered = receipt.candidates_discovered.saturating_add(1);
                    receipt
                        .first_candidate_ms
                        .get_or_insert_with(|| elapsed_ms(started));
                    append_event(
                        &events_path,
                        &format!(
                            "{{\"event\":\"candidate_discovered\",\"address\":\"{}\",\"provenance\":\"aster-protected-ip-discovery\"}}",
                            address
                        ),
                    )?;
                }
                Ok(false) => {}
                Err(error) if is_mesh_capacity(error.as_ref()) => {
                    receipt.candidates_rejected_capacity =
                        receipt.candidates_rejected_capacity.saturating_add(1);
                }
                Err(error) => return Err(error),
            }
        }

        pump_native_contacts(
            &mut supervisor,
            &raw,
            &mut provider,
            config,
            &mut receipt,
            &events_path,
            started,
            &mut local_carrier,
            deadline,
        )?;

        let plan = supervisor.plan(now)?;
        receipt.candidates_rejected_capacity = receipt
            .candidates_rejected_capacity
            .saturating_add(u64::try_from(plan.dial_resource_rejections)?);
        apply_native_actions(
            plan.actions,
            &mut supervisor,
            &raw,
            &mut provider,
            &mut receipt,
            &events_path,
            local_carrier,
            config.discovery_enabled,
            now,
            deadline,
        )?;
        if let Some(gate_h) = gate_h_live_control.as_mut() {
            advance_native_gate_h_live_control(
                gate_h,
                &mut supervisor,
                &raw,
                &mut provider,
                &mut receipt,
                &events_path,
                started,
                &mut local_carrier,
            )?;
        }
        receipt.active_contact_high_water = receipt
            .active_contact_high_water
            .max(supervisor.host_snapshot().active_contacts);

        if now >= next_status {
            receipt.elapsed_ms = elapsed_ms(started);
            refresh_native_receipt_observations(&mut receipt, &supervisor, &aster_sent)?;
            write_replace(&status_path, receipt.to_json().as_bytes())?;
            next_status = now.checked_add(STATUS_INTERVAL).unwrap_or(deadline);
        }

        let wakeup = next_native_wakeup(
            &supervisor,
            &raw,
            &provider,
            next_discovery,
            next_status,
            deadline,
            now,
        );
        let wait = wakeup
            .saturating_duration_since(Instant::now())
            .min(MAX_READINESS_WAIT);
        if let Some(frame) = raw.wait_receive(wait)?
            && let Some((route, remote_carrier)) =
                dispatch_native_frame(frame, &mut provider, &mut receipt, local_carrier)?
        {
            handle_native_hello(
                route,
                remote_carrier,
                &mut supervisor,
                &raw,
                &mut provider,
                &aster_sent,
                &mut receipt,
                &events_path,
                local_carrier,
                Instant::now(),
            )?;
        }
    }

    if gate_h_live_control
        .as_ref()
        .is_some_and(|state| state.phase != NativeGateHLivePhase::Complete)
    {
        return Err(invalid(
            "Gate-H live authorization-control sequence did not complete before deadline",
        ));
    }

    let active = provider.contacts.keys().copied().collect::<Vec<_>>();
    for contact in active {
        close_native_contact(
            &mut supervisor,
            &mut provider,
            contact,
            false,
            None,
            &events_path,
        )?;
    }
    receipt.elapsed_ms = elapsed_ms(started);
    refresh_native_receipt_observations(&mut receipt, &supervisor, &aster_sent)?;
    write_new(&final_path, receipt.to_json().as_bytes())?;
    write_replace(&status_path, receipt.to_json().as_bytes())?;
    append_event(
        &events_path,
        &format!(
            "{{\"event\":\"stopped\",\"elapsed_ms\":{}}}",
            receipt.elapsed_ms
        ),
    )?;
    Ok(receipt)
}

fn refresh_native_receipt_observations(
    receipt: &mut NativeMeshNodeReceipt,
    supervisor: &SharedNodeContactSupervisor,
    sent: &Arc<Mutex<NativeAsterSendCounters>>,
) -> LabResult<()> {
    let sent = *sent.lock().map_err(lock_error)?;
    receipt.aster_frames_sent = sent.frames;
    receipt.aster_bytes_sent = sent.bytes;
    let evidence = supervisor.evidence_counters();
    receipt.authorization_generation_checks = evidence.authorization_generation_checks;
    receipt.authorization_generation_mismatches = evidence.authorization_generation_mismatches;
    receipt.authorization_generation_unavailable = evidence.authorization_generation_unavailable;
    receipt.authorization_generation_current = supervisor.authorization_generation()?;
    receipt.durable_item_present = receipt
        .durable_item_probe_id
        .map(|item_id| supervisor.durable_item_present(item_id))
        .transpose()?;
    receipt.node_resources = supervisor.resource_snapshot()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn observe_native_endpoint(
    raw: &IpLink,
    supervisor: &mut SharedNodeContactSupervisor,
    provider: &mut NativeProvider,
    candidate: CandidateId,
    locator: CandidateLocator,
    address: SocketAddr,
    provenance: CandidateProvenance,
    expected_peer: Option<NodeId>,
    now: Instant,
) -> LabResult<bool> {
    if let Some(existing) = provider.endpoints.get_mut(&locator) {
        if existing.candidate != candidate {
            if provenance == CandidateProvenance::Automatic
                && existing.provenance == CandidateProvenance::Manual
            {
                return Ok(false);
            }
            return Err(invalid(
                "native mesh endpoint was bound to conflicting candidates",
            ));
        }
        if existing.provenance == CandidateProvenance::Automatic
            && provenance == CandidateProvenance::Automatic
        {
            supervisor.refresh_candidate(candidate, locator, now)?;
        } else {
            supervisor.observe_candidate(
                candidate,
                locator,
                provenance,
                ContactPath::Direct,
                expected_peer,
                now,
            )?;
        }
        return Ok(false);
    }
    supervisor.observe_candidate(
        candidate.clone(),
        locator.clone(),
        provenance,
        ContactPath::Direct,
        expected_peer,
        now,
    )?;
    let route = match raw.register_endpoint(address) {
        Ok(route) => route,
        Err(error) => {
            let _ = supervisor.expire_candidate(candidate, locator, now);
            return Err(error.into());
        }
    };
    if provider.route_to_locator.contains_key(&route) {
        let _ = supervisor.expire_candidate(candidate, locator, now);
        return Err(invalid(
            "native mesh route was bound to conflicting endpoint locators",
        ));
    }
    provider.route_to_locator.insert(route, locator.clone());
    provider.endpoints.insert(
        locator.clone(),
        NativeEndpoint {
            candidate,
            provenance,
            address,
            route,
            last_hello_sent: None,
            retired_instances: VecDeque::new(),
        },
    );
    Ok(true)
}

fn is_mesh_capacity(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    error
        .downcast_ref::<MeshHostError>()
        .is_some_and(|error| matches!(error, MeshHostError::Capacity(_)))
        || error
            .downcast_ref::<ContactSupervisorError>()
            .is_some_and(|error| {
                matches!(
                    error,
                    ContactSupervisorError::Host(MeshHostError::Capacity(_))
                        | ContactSupervisorError::Resource(ResourceBudgetError::Capacity(_))
                )
            })
}

#[allow(clippy::too_many_arguments)]
fn apply_native_actions(
    actions: Vec<HostAction>,
    supervisor: &mut SharedNodeContactSupervisor,
    raw: &IpLink,
    provider: &mut NativeProvider,
    receipt: &mut NativeMeshNodeReceipt,
    events_path: &Path,
    local_carrier: NativeCarrierHello,
    discovery_configured: bool,
    now: Instant,
    deadline: Instant,
) -> LabResult<()> {
    for action in actions {
        match action {
            HostAction::SetDiscovery { enabled } => {
                let enabled = enabled && discovery_configured;
                raw.set_discovery(enabled)?;
                provider.discovery_enabled = enabled;
            }
            HostAction::Dial { candidate, locator } => {
                start_native_dial(
                    supervisor,
                    raw,
                    provider,
                    receipt,
                    events_path,
                    local_carrier,
                    candidate,
                    locator,
                    now,
                    deadline,
                )?;
            }
            HostAction::ForgetCandidateLocator { candidate, locator } => {
                if let Some(route) = forget_native_endpoint(provider, &candidate, &locator) {
                    raw.remove_peer(&route);
                }
            }
            HostAction::Close { contact, reason } => {
                if reason == ContactCloseReason::Duplicate {
                    receipt.duplicate_contacts = receipt.duplicate_contacts.saturating_add(1);
                } else if reason == ContactCloseReason::Capacity {
                    receipt.candidates_rejected_capacity =
                        receipt.candidates_rejected_capacity.saturating_add(1);
                }
                close_native_contact(
                    supervisor,
                    provider,
                    contact,
                    false,
                    Some(reason),
                    events_path,
                )?;
            }
        }
    }
    Ok(())
}

fn forget_native_endpoint(
    provider: &mut NativeProvider,
    candidate: &CandidateId,
    locator: &CandidateLocator,
) -> Option<NodeId> {
    if let Some(endpoint) = provider.endpoints.get(locator)
        && &endpoint.candidate == candidate
    {
        let route = endpoint.route;
        provider.endpoints.remove(locator);
        if provider.route_to_locator.get(&route) == Some(locator) {
            provider.route_to_locator.remove(&route);
            return Some(route);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn start_native_dial(
    supervisor: &mut SharedNodeContactSupervisor,
    raw: &IpLink,
    provider: &mut NativeProvider,
    receipt: &mut NativeMeshNodeReceipt,
    events_path: &Path,
    local_carrier: NativeCarrierHello,
    candidate: CandidateId,
    locator: CandidateLocator,
    now: Instant,
    deadline: Instant,
) -> LabResult<()> {
    let Some(endpoint) = provider.endpoints.get_mut(&locator) else {
        settle_native_dial_failure(supervisor, candidate, locator, now)?;
        receipt.contact_failures = receipt.contact_failures.saturating_add(1);
        return Ok(());
    };
    if endpoint.candidate != candidate
        || provider.pending_dials.contains_key(&candidate)
        || provider.route_contacts.contains_key(&endpoint.route)
    {
        settle_native_dial_failure(supervisor, candidate, locator, now)?;
        receipt.contact_failures = receipt.contact_failures.saturating_add(1);
        return Ok(());
    }
    if let Err(error) = send_carrier_hello(raw, endpoint.route, local_carrier, receipt) {
        settle_native_dial_failure(supervisor, candidate, locator, now)?;
        receipt.contact_failures = receipt.contact_failures.saturating_add(1);
        append_event(
            events_path,
            &format!(
                "{{\"event\":\"contact_failed\",\"address\":\"{}\",\"reason\":\"{}\"}}",
                endpoint.address,
                json_escape(&error.to_string())
            ),
        )?;
        return Ok(());
    }
    endpoint.last_hello_sent = Some(now);
    provider.pending_dials.insert(
        candidate.clone(),
        PendingNativeDial {
            locator: locator.clone(),
            route: endpoint.route,
            deadline: now
                .checked_add(NATIVE_DIAL_TIMEOUT)
                .unwrap_or(deadline)
                .min(deadline),
            next_hello: now.checked_add(NATIVE_HELLO_INTERVAL).unwrap_or(deadline),
        },
    );
    append_event(
        events_path,
        &format!(
            "{{\"event\":\"contact_dialing\",\"candidate\":\"{}\",\"address\":\"{}\"}}",
            json_escape(candidate.as_str()),
            endpoint.address
        ),
    )?;
    Ok(())
}

fn settle_native_dial_failure(
    supervisor: &mut SharedNodeContactSupervisor,
    candidate: CandidateId,
    locator: CandidateLocator,
    now: Instant,
) -> LabResult<()> {
    supervisor.dial_failed(candidate, locator, now)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn expire_native_dials(
    supervisor: &mut SharedNodeContactSupervisor,
    raw: &IpLink,
    provider: &mut NativeProvider,
    receipt: &mut NativeMeshNodeReceipt,
    events_path: &Path,
    local_carrier: NativeCarrierHello,
    now: Instant,
) -> LabResult<()> {
    let candidates = provider.pending_dials.keys().cloned().collect::<Vec<_>>();
    for candidate in candidates {
        let Some(pending) = provider.pending_dials.get(&candidate) else {
            continue;
        };
        if now >= pending.deadline {
            let pending = provider
                .pending_dials
                .remove(&candidate)
                .expect("pending native dial disappeared");
            settle_native_dial_failure(supervisor, candidate, pending.locator, now)?;
            receipt.contact_failures = receipt.contact_failures.saturating_add(1);
            append_event(
                events_path,
                "{\"event\":\"contact_failed\",\"reason\":\"native carrier hello deadline reached\"}",
            )?;
            continue;
        }
        if now < pending.next_hello {
            continue;
        }
        let locator = pending.locator.clone();
        let route = pending.route;
        let deadline = pending.deadline;
        match send_carrier_hello(raw, route, local_carrier, receipt) {
            Ok(()) => {
                if let Some(endpoint) = provider.endpoints.get_mut(&locator) {
                    endpoint.last_hello_sent = Some(now);
                }
                if let Some(pending) = provider.pending_dials.get_mut(&candidate) {
                    pending.next_hello = now.checked_add(NATIVE_HELLO_INTERVAL).unwrap_or(deadline);
                }
            }
            Err(error) => {
                provider.pending_dials.remove(&candidate);
                settle_native_dial_failure(supervisor, candidate, locator, now)?;
                receipt.contact_failures = receipt.contact_failures.saturating_add(1);
                append_event(
                    events_path,
                    &format!(
                        "{{\"event\":\"contact_failed\",\"reason\":\"{}\"}}",
                        json_escape(&error.to_string())
                    ),
                )?;
            }
        }
    }
    Ok(())
}

fn drain_native_frames(
    raw: &IpLink,
    provider: &mut NativeProvider,
    receipt: &mut NativeMeshNodeReceipt,
    local_carrier: NativeCarrierHello,
) -> LabResult<Vec<(NodeId, NativeCarrierHello)>> {
    let mut hellos = Vec::new();
    while let Some(frame) = raw.try_receive()? {
        if let Some(hello) = dispatch_native_frame(frame, provider, receipt, local_carrier)? {
            hellos.push(hello);
        }
    }
    Ok(hellos)
}

fn dispatch_native_frame(
    frame: ReceivedFrame,
    provider: &mut NativeProvider,
    receipt: &mut NativeMeshNodeReceipt,
    local_carrier: NativeCarrierHello,
) -> LabResult<Option<(NodeId, NativeCarrierHello)>> {
    if let Some(remote) = decode_carrier_hello(&frame.bytes) {
        receipt.carrier_control_frames_received =
            receipt.carrier_control_frames_received.saturating_add(1);
        receipt.carrier_control_bytes_received = receipt
            .carrier_control_bytes_received
            .saturating_add(u64::try_from(frame.bytes.len()).unwrap_or(u64::MAX));
        let Some(route) = frame.peer else {
            return Ok(None);
        };
        return Ok(Some((route, remote)));
    }
    let Some((sender_carrier, expected_receiver, aster_frame)) = decode_carrier_data(&frame.bytes)
    else {
        return Ok(None);
    };
    let Some(route) = frame.peer else {
        return Ok(None);
    };
    let Some(contact_id) = provider.route_contacts.get(&route).copied() else {
        // A registered candidate may send carrier data before MeshHost opens
        // its contact. Only the fixed carrier hello crosses that boundary.
        return Ok(None);
    };
    let Some(contact) = provider.contacts.get_mut(&contact_id) else {
        return Ok(None);
    };
    if sender_carrier != contact.remote_instance || expected_receiver != local_carrier {
        // The route is stable across process and authorization-session
        // replacement. Bind every opaque Aster frame to both exact carrier
        // epochs so a delayed predecessor packet cannot enter its successor's
        // fresh RuntimeSession.
        return Ok(None);
    }
    receipt.aster_frames_received = receipt.aster_frames_received.saturating_add(1);
    receipt.aster_bytes_received = receipt
        .aster_bytes_received
        .saturating_add(u64::try_from(aster_frame.len()).unwrap_or(u64::MAX));
    let mut queue = contact.inbound.lock().map_err(lock_error)?;
    if queue.frames.len() >= MAX_INBOUND_FRAMES_PER_CONTACT
        || queue.bytes.saturating_add(aster_frame.len()) > MAX_INBOUND_BYTES_PER_CONTACT
    {
        return Ok(None);
    }
    queue.bytes = queue.bytes.saturating_add(aster_frame.len());
    queue.frames.push_back(aster_frame.to_vec());
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
fn handle_native_hello(
    route: NodeId,
    remote_carrier: NativeCarrierHello,
    supervisor: &mut SharedNodeContactSupervisor,
    raw: &Arc<IpLink>,
    provider: &mut NativeProvider,
    aster_sent: &Arc<Mutex<NativeAsterSendCounters>>,
    receipt: &mut NativeMeshNodeReceipt,
    events_path: &Path,
    local_carrier: NativeCarrierHello,
    now: Instant,
) -> LabResult<()> {
    let Some(locator) = provider.route_to_locator.get(&route).cloned() else {
        return Ok(());
    };
    let Some(endpoint) = provider.endpoints.get(&locator).cloned() else {
        return Ok(());
    };
    if remote_carrier.carrier_id == local_carrier.carrier_id {
        if let Some(pending) = provider.pending_dials.remove(&endpoint.candidate) {
            settle_native_dial_failure(supervisor, endpoint.candidate, pending.locator, now)?;
            receipt.contact_failures = receipt.contact_failures.saturating_add(1);
        }
        return Ok(());
    }

    let active = provider.route_contacts.get(&route).copied();
    let active_instance = match active {
        Some(contact) => Some(
            provider
                .contacts
                .get(&contact)
                .ok_or_else(|| invalid("native route referenced a missing contact"))?
                .remote_instance,
        ),
        None => None,
    };
    if active_instance != Some(remote_carrier)
        && endpoint.retired_instances.contains(&remote_carrier)
    {
        // A datagram from the replaced socket may arrive after its successor's
        // hello. Never flip the live session back to a retired process nonce.
        return Ok(());
    }
    let replacing = active_instance.is_some_and(|instance| instance != remote_carrier);
    if replacing {
        let old_contact = active.expect("a replacement has an active contact");
        let old_instance = active_instance.expect("a replacement has an active instance");
        close_native_contact_with_label(
            supervisor,
            provider,
            old_contact,
            false,
            "carrier-instance-replaced",
            events_path,
        )?;
        let endpoint = provider
            .endpoints
            .get_mut(&locator)
            .ok_or_else(|| invalid("native endpoint disappeared during contact replacement"))?;
        remember_retired_native_instance(endpoint, old_instance);
        append_event(
            events_path,
            &format!(
                "{{\"event\":\"carrier_instance_replaced\",\"address\":\"{}\",\"carrier_id\":\"{}\",\"old_instance_nonce\":\"{}\",\"new_instance_nonce\":\"{}\"}}",
                endpoint.address,
                hex(&remote_carrier.carrier_id),
                hex(&old_instance.instance_nonce),
                hex(&remote_carrier.instance_nonce)
            ),
        )?;
    }

    let should_answer = replacing
        || endpoint
            .last_hello_sent
            .is_none_or(|sent| now.saturating_duration_since(sent) >= NATIVE_HELLO_INTERVAL);
    if should_answer {
        if let Err(error) = send_carrier_hello(raw, route, local_carrier, receipt) {
            receipt.contact_failures = receipt.contact_failures.saturating_add(1);
            append_event(
                events_path,
                &format!(
                    "{{\"event\":\"contact_failed\",\"address\":\"{}\",\"reason\":\"{}\"}}",
                    endpoint.address,
                    json_escape(&error.to_string())
                ),
            )?;
            return Ok(());
        }
        if let Some(endpoint) = provider.endpoints.get_mut(&locator) {
            endpoint.last_hello_sent = Some(now);
        }
    }
    if provider.route_contacts.contains_key(&route) {
        return Ok(());
    }

    let direction = if provider
        .pending_dials
        .get(&endpoint.candidate)
        .is_some_and(|pending| pending.route == route && pending.locator == locator)
    {
        ContactDirection::Outbound
    } else {
        ContactDirection::Inbound
    };
    let contact = ContactId(provider.next_contact);
    provider.next_contact = provider.next_contact.saturating_add(1).max(1);
    let initiator = local_carrier.carrier_id < remote_carrier.carrier_id;
    let mut allocated_link_state = None;
    let opened = match supervisor.open_contact_with_factory(
        ContactOpening {
            contact,
            candidate: endpoint.candidate.clone(),
            locator: locator.clone(),
            carrier_identity: Some(CarrierIdentity::new(remote_carrier.carrier_id.to_vec())?),
            direction,
            path: ContactPath::Direct,
            role: if initiator {
                ContactSessionRole::Initiator { peer_hint: None }
            } else {
                ContactSessionRole::Responder { peer_hint: None }
            },
        },
        now,
        || {
            let inbound = Arc::new(Mutex::new(ContactQueue::default()));
            let contact_sent = Arc::new(Mutex::new(NativeAsterSendCounters::default()));
            let link = NativeContactLink {
                raw: Arc::clone(raw),
                _base_resources: Arc::clone(&provider.base_resources),
                route,
                local_carrier,
                remote_carrier,
                inbound: Arc::clone(&inbound),
                sent: Arc::clone(aster_sent),
                contact_sent: Arc::clone(&contact_sent),
                gate_h_barrier: Arc::clone(&provider.gate_h_barrier),
            };
            allocated_link_state = Some((inbound, contact_sent));
            link
        },
    ) {
        Ok(report) => report,
        Err(ContactSupervisorError::Host(MeshHostError::Capacity(_)))
        | Err(ContactSupervisorError::Resource(ResourceBudgetError::Capacity(_))) => {
            receipt.candidates_rejected_capacity =
                receipt.candidates_rejected_capacity.saturating_add(1);
            provider.pending_dials.remove(&endpoint.candidate);
            return Ok(());
        }
        Err(ContactSupervisorError::Host(MeshHostError::UnknownCandidate))
            if direction == ContactDirection::Outbound =>
        {
            receipt.contact_failures = receipt.contact_failures.saturating_add(1);
            provider.pending_dials.remove(&endpoint.candidate);
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    provider.pending_dials.remove(&endpoint.candidate);
    if let Some(reason) = opened.actions.iter().find_map(|action| match action {
        HostAction::Close {
            contact: closed,
            reason,
        } if *closed == contact => Some(*reason),
        _ => None,
    }) {
        if reason == ContactCloseReason::Duplicate {
            receipt.duplicate_contacts = receipt.duplicate_contacts.saturating_add(1);
        } else if reason == ContactCloseReason::Capacity {
            receipt.candidates_rejected_capacity =
                receipt.candidates_rejected_capacity.saturating_add(1);
        }
        append_event(
            events_path,
            &format!(
                "{{\"event\":\"contact_rejected\",\"address\":\"{}\",\"reason\":\"{}\"}}",
                endpoint.address,
                native_close_reason(reason)
            ),
        )?;
        return Ok(());
    }
    if !opened.opened || !opened.actions.is_empty() {
        return Err(invalid(
            "native shared supervisor returned an inconsistent contact-open result",
        ));
    }
    let (inbound, contact_sent) = allocated_link_state
        .ok_or_else(|| invalid("native contact opened without reserved link state"))?;
    provider.route_contacts.insert(route, contact);
    provider.contacts.insert(
        contact,
        NativeContact {
            contact,
            address: endpoint.address,
            route,
            inbound,
            admitted_peer: None,
            remote_instance: remote_carrier,
            sent: contact_sent,
        },
    );
    receipt.active_contact_high_water = receipt
        .active_contact_high_water
        .max(supervisor.host_snapshot().active_contacts);
    append_event(
        events_path,
        &format!(
            "{{\"event\":\"contact_started\",\"contact\":{},\"address\":\"{}\",\"direction\":\"{}\",\"role\":\"{}\"}}",
            contact.0,
            endpoint.address,
            if direction == ContactDirection::Outbound {
                "outbound"
            } else {
                "inbound"
            },
            if initiator { "initiator" } else { "responder" }
        ),
    )?;
    // The driver has not been pumped yet, so only the carrier hello has crossed
    // the MeshHost contact-open boundary.
    Ok(())
}

fn append_shared_node_evidence(
    supervisor: &mut SharedNodeContactSupervisor,
    provider: &mut NativeProvider,
    receipt: &mut NativeMeshNodeReceipt,
    events_path: &Path,
    started: Instant,
) -> LabResult<()> {
    for transition in supervisor.take_evidence() {
        match transition {
            SharedNodeEvidenceTransition::AsterAuthenticated { contact, peer } => {
                receipt.authenticated_peers.insert(peer);
                receipt
                    .first_authenticated_ms
                    .get_or_insert_with(|| elapsed_ms(started));
                append_event(
                    events_path,
                    &format!(
                        "{{\"event\":\"aster_authenticated\",\"contact\":{},\"peer\":\"{}\"}}",
                        contact.0,
                        hex(&peer)
                    ),
                )?;
            }
            SharedNodeEvidenceTransition::AdmissionPrepared { contact, peer } => {
                append_event(
                    events_path,
                    &format!(
                        "{{\"event\":\"admission_prepared\",\"contact\":{},\"peer\":\"{}\"}}",
                        contact.0,
                        hex(&peer)
                    ),
                )?;
            }
            SharedNodeEvidenceTransition::AdmissionCommitted { contact, peer } => {
                let active = provider.contacts.get_mut(&contact).ok_or_else(|| {
                    invalid("admitted common-host contact is absent from provider")
                })?;
                active.admitted_peer = Some(peer);
                receipt.admitted_peers.insert(peer);
                append_event(
                    events_path,
                    &format!(
                        "{{\"event\":\"admission_committed\",\"contact\":{},\"peer\":\"{}\"}}",
                        contact.0,
                        hex(&peer)
                    ),
                )?;
            }
            SharedNodeEvidenceTransition::AdmissionAborted {
                contact,
                peer,
                reason,
            } => {
                let reason = match reason {
                    AdmissionAbortReason::Resource => "resource",
                    AdmissionAbortReason::Authorization => "authorization",
                    AdmissionAbortReason::HostCommit => "host-commit",
                    AdmissionAbortReason::ResourceRollback => "resource-rollback",
                };
                append_event(
                    events_path,
                    &format!(
                        "{{\"event\":\"admission_aborted\",\"contact\":{},\"peer\":\"{}\",\"reason\":\"{}\"}}",
                        contact.0,
                        hex(&peer),
                        reason
                    ),
                )?;
            }
            SharedNodeEvidenceTransition::GenerationChecked {
                contact,
                peer,
                check,
            } => {
                let (result, expected, observed) = match check {
                    RuntimeAuthorizationGenerationCheck::Current { generation } => {
                        ("current", generation.to_string(), generation.to_string())
                    }
                    RuntimeAuthorizationGenerationCheck::Changed {
                        expected_generation,
                        observed_generation,
                    } => (
                        "mismatch",
                        expected_generation.to_string(),
                        observed_generation.to_string(),
                    ),
                    RuntimeAuthorizationGenerationCheck::Unavailable {
                        expected_generation,
                    } => (
                        "unavailable",
                        expected_generation
                            .map_or_else(|| "null".to_owned(), |value| value.to_string()),
                        "null".to_owned(),
                    ),
                };
                append_event(
                    events_path,
                    &format!(
                        "{{\"event\":\"generation_checked\",\"contact\":{},\"peer\":\"{}\",\"result\":\"{}\",\"expected_generation\":{},\"observed_generation\":{}}}",
                        contact.0,
                        hex(&peer),
                        result,
                        expected,
                        observed
                    ),
                )?;
            }
            SharedNodeEvidenceTransition::PendingConnectionExpired { candidate, locator } => {
                append_event(
                    events_path,
                    &format!(
                        "{{\"event\":\"pending_connection_expired\",\"candidate\":\"{}\",\"locator\":\"{}\"}}",
                        json_escape(candidate.as_str()),
                        json_escape(locator.as_str())
                    ),
                )?;
            }
            SharedNodeEvidenceTransition::PendingConnectionCancelled { candidate, locator } => {
                append_event(
                    events_path,
                    &format!(
                        "{{\"event\":\"pending_connection_cancelled\",\"candidate\":\"{}\",\"locator\":\"{}\"}}",
                        json_escape(candidate.as_str()),
                        json_escape(locator.as_str())
                    ),
                )?;
            }
        }
    }
    let counters = supervisor.evidence_counters();
    receipt.authorization_generation_checks = counters.authorization_generation_checks;
    receipt.authorization_generation_mismatches = counters.authorization_generation_mismatches;
    receipt.authorization_generation_unavailable = counters.authorization_generation_unavailable;
    Ok(())
}

fn terminal_supervisor_contact(error: &ContactSupervisorError) -> Option<ContactId> {
    match error {
        ContactSupervisorError::UnauthorizedPeer { contact, .. }
        | ContactSupervisorError::PreAuthenticationExpired(contact)
        | ContactSupervisorError::AuthorizationChanged(contact)
        | ContactSupervisorError::Runtime { contact, .. }
        | ContactSupervisorError::Admission { contact, .. }
        | ContactSupervisorError::InventoryFanout { contact, .. } => Some(*contact),
        ContactSupervisorError::InvalidConfig(_)
        | ContactSupervisorError::UnobservedCandidate(_)
        | ContactSupervisorError::DuplicateContact(_)
        | ContactSupervisorError::UnknownContact(_)
        | ContactSupervisorError::Credential
        | ContactSupervisorError::ExchangeIdExhausted
        | ContactSupervisorError::Host(_)
        | ContactSupervisorError::Resource(_) => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn rotate_native_authorization_session_epoch(
    supervisor: &mut SharedNodeContactSupervisor,
    raw: &Arc<IpLink>,
    provider: &mut NativeProvider,
    receipt: &mut NativeMeshNodeReceipt,
    events_path: &Path,
    failed_contact: ContactId,
    local_carrier: &mut NativeCarrierHello,
) -> LabResult<()> {
    let retiring = provider.contacts.keys().copied().collect::<Vec<_>>();
    for contact in &retiring {
        close_native_contact_with_label(
            supervisor,
            provider,
            *contact,
            true,
            "authorization-generation-retired",
            events_path,
        )?;
    }
    if !retiring.contains(&failed_contact)
        || !supervisor.contact_status().is_empty()
        || !provider.contacts.is_empty()
    {
        return Err(invalid(
            "authorization-generation rotation did not retire every local Aster session",
        ));
    }
    let generation = supervisor.authorization_generation()?;
    append_event(
        events_path,
        &format!(
            "{{\"event\":\"authorization_generation_sessions_retired\",\"generation\":{},\"trigger_contact\":{},\"contacts_retired\":{}}}",
            generation,
            failed_contact.0,
            retiring.len(),
        ),
    )?;
    let old_instance_nonce = local_carrier.instance_nonce;
    let new_instance_nonce = new_native_carrier_instance_nonce()?;
    if old_instance_nonce == new_instance_nonce {
        return Err(invalid(
            "authorization-generation provider epoch nonce did not rotate",
        ));
    }
    local_carrier.instance_nonce = new_instance_nonce;
    let routes = provider
        .endpoints
        .values()
        .map(|endpoint| endpoint.route)
        .collect::<Vec<_>>();
    for route in routes {
        send_carrier_hello(raw, route, *local_carrier, receipt)?;
        let locator = provider.route_to_locator.get(&route).cloned();
        if let Some(locator) = locator
            && let Some(endpoint) = provider.endpoints.get_mut(&locator)
        {
            endpoint.last_hello_sent = Some(Instant::now());
        }
    }
    append_event(
        events_path,
        &format!(
            "{{\"event\":\"carrier_session_epoch_rotated\",\"cause\":\"authorization-generation-changed\",\"generation\":{},\"carrier_id\":\"{}\",\"old_instance_nonce\":\"{}\",\"new_instance_nonce\":\"{}\",\"stale_contacts_retired\":{}}}",
            generation,
            hex(&local_carrier.carrier_id),
            hex(&old_instance_nonce),
            hex(&new_instance_nonce),
            retiring.len(),
        ),
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn pump_native_contacts(
    supervisor: &mut SharedNodeContactSupervisor,
    raw: &Arc<IpLink>,
    provider: &mut NativeProvider,
    config: &NativeMeshNodeConfig,
    receipt: &mut NativeMeshNodeReceipt,
    events_path: &Path,
    started: Instant,
    local_carrier: &mut NativeCarrierHello,
    deadline: Instant,
) -> LabResult<()> {
    let ids = provider.contacts.keys().copied().collect::<Vec<_>>();
    for contact_id in ids {
        let Some(address) = provider
            .contacts
            .get(&contact_id)
            .map(|contact| contact.address)
        else {
            continue;
        };
        receipt.pump_calls = receipt.pump_calls.saturating_add(1);
        let drive = supervisor.drive_contact(contact_id, Instant::now());
        append_shared_node_evidence(supervisor, provider, receipt, events_path, started)?;
        match drive {
            Err(ContactSupervisorError::UnauthorizedPeer { contact, peer }) => {
                receipt.unauthorized_peers.insert(peer);
                receipt.contact_failures = receipt.contact_failures.saturating_add(1);
                append_event(
                    events_path,
                    &format!(
                        "{{\"event\":\"authenticated_unexpected_peer\",\"contact\":{},\"peer\":\"{}\"}}",
                        contact.0,
                        hex(&peer)
                    ),
                )?;
                close_native_contact(supervisor, provider, contact, true, None, events_path)?;
            }
            Err(ContactSupervisorError::AuthorizationChanged(contact)) => {
                rotate_native_authorization_session_epoch(
                    supervisor,
                    raw,
                    provider,
                    receipt,
                    events_path,
                    contact,
                    local_carrier,
                )?;
            }
            Err(error) => {
                let failed_contact = terminal_supervisor_contact(&error).unwrap_or(contact_id);
                let failed_address = provider
                    .contacts
                    .get(&failed_contact)
                    .map_or(address, |contact| contact.address);
                receipt.contact_failures = receipt.contact_failures.saturating_add(1);
                append_event(
                    events_path,
                    &format!(
                        "{{\"event\":\"contact_failed\",\"contact\":{},\"address\":\"{}\",\"reason\":\"{}\"}}",
                        failed_contact.0,
                        failed_address,
                        json_escape(&error.to_string())
                    ),
                )?;
                close_native_contact(
                    supervisor,
                    provider,
                    failed_contact,
                    true,
                    None,
                    events_path,
                )?;
            }
            Ok(report) => {
                if report.actions.iter().any(|action| {
                    matches!(
                        action,
                        HostAction::Close {
                            contact,
                            reason: ContactCloseReason::AuthenticationRejected,
                        } if *contact == contact_id
                    )
                }) && let Some(peer) = report.authenticated_peer
                {
                    receipt.unauthorized_peers.insert(peer);
                }
                if report.admitted
                    && let Some(peer) = report.authenticated_peer
                {
                    let evidenced_peer = provider
                        .contacts
                        .get(&contact_id)
                        .and_then(|contact| contact.admitted_peer);
                    if evidenced_peer != Some(peer) {
                        return Err(invalid(
                            "native admission report lacks common-host commit evidence",
                        ));
                    }
                }
                if report.inventory_contacts_notified > 0 {
                    append_event(
                        events_path,
                        &format!(
                            "{{\"event\":\"inventory_changed\",\"contact\":{},\"contacts_planned\":{}}}",
                            contact_id.0, report.inventory_contacts_notified
                        ),
                    )?;
                    append_event(
                        events_path,
                        &format!(
                            "{{\"event\":\"inventory_fanout_queued\",\"contact\":{},\"contacts_queued\":{}}}",
                            contact_id.0, report.inventory_contacts_notified
                        ),
                    )?;
                }
                apply_native_actions(
                    report.actions,
                    supervisor,
                    raw,
                    provider,
                    receipt,
                    events_path,
                    *local_carrier,
                    config.discovery_enabled,
                    Instant::now(),
                    deadline,
                )?;
                receipt.admitted_contact_high_water = receipt
                    .admitted_contact_high_water
                    .max(supervisor.resource_snapshot()?.current.admitted_contacts);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn advance_native_gate_h_live_control(
    state: &mut NativeGateHLiveControl,
    supervisor: &mut SharedNodeContactSupervisor,
    raw: &Arc<IpLink>,
    provider: &mut NativeProvider,
    receipt: &mut NativeMeshNodeReceipt,
    events_path: &Path,
    started: Instant,
    local_carrier: &mut NativeCarrierHello,
) -> LabResult<()> {
    match state.phase {
        NativeGateHLivePhase::AwaitingTwoAdmittedContacts => {
            let admitted = supervisor
                .contact_status()
                .into_iter()
                .filter_map(|status| {
                    (status.admitted && !status.terminal)
                        .then_some((status.contact, status.authenticated_peer?))
                })
                .collect::<Vec<_>>();
            if admitted.len() != 2 {
                return Ok(());
            }
            let Some((target_contact, _)) = admitted
                .iter()
                .find(|(_, peer)| *peer == state.target_peer)
                .copied()
            else {
                return Err(invalid(
                    "Gate-H two-contact admission omitted the configured stale target",
                ));
            };
            let target_route = provider
                .contacts
                .get(&target_contact)
                .ok_or_else(|| invalid("Gate-H target admission lacks provider contact"))?
                .route;
            state.stale_target_remote_instance = Some(
                provider
                    .contacts
                    .get(&target_contact)
                    .ok_or_else(|| invalid("Gate-H target provider contact disappeared"))?
                    .remote_instance,
            );
            let mut barrier = provider.gate_h_barrier.lock().map_err(lock_error)?;
            *barrier = NativeGateHSendBarrier {
                target_route: Some(target_route),
                enabled: true,
                blocked_frames: 0,
                blocked_bytes: 0,
            };
            state.stale_target_contact = Some(target_contact);
            state.phase = NativeGateHLivePhase::AwaitingRetainedFrame;
        }
        NativeGateHLivePhase::AwaitingRetainedFrame => {
            let target_contact = state
                .stale_target_contact
                .ok_or_else(|| invalid("Gate-H stale target contact was not retained"))?;
            let statuses = supervisor.contact_status();
            if statuses.iter().filter(|status| status.admitted).count() != 2 {
                return Err(invalid(
                    "Gate-H lost a stale contact before the authorization control commit",
                ));
            }
            let Some(target_status) = statuses
                .iter()
                .find(|status| status.contact == target_contact)
            else {
                return Err(invalid(
                    "Gate-H stale target disappeared before frame retention",
                ));
            };
            let barrier = *provider.gate_h_barrier.lock().map_err(lock_error)?;
            if target_status.pending_outbound_frames == 0 || barrier.blocked_frames == 0 {
                return Ok(());
            }

            let stale_contacts = statuses
                .iter()
                .filter(|status| status.admitted)
                .map(|status| status.contact)
                .collect::<Vec<_>>();
            let before = native_contact_sent(provider, target_contact)?;
            receipt.gate_h_control_id = Some(state.control.envelope_id());
            receipt.gate_h_stale_target_peer = Some(state.target_peer);
            receipt.gate_h_stale_target_contact = Some(target_contact);
            receipt.gate_h_stale_queued_frames = target_status.pending_outbound_frames;
            receipt.gate_h_stale_send_frames_before = before.frames;
            receipt.gate_h_stale_send_bytes_before = before.bytes;
            append_event(
                events_path,
                &format!(
                    "{{\"event\":\"stale_frame_retained\",\"peer\":\"{}\",\"contact\":{},\"queued_frames\":{},\"blocked_attempts\":{},\"blocked_bytes\":{},\"sent_frames\":{},\"sent_bytes\":{}}}",
                    hex(&state.target_peer),
                    target_contact.0,
                    target_status.pending_outbound_frames,
                    barrier.blocked_frames,
                    barrier.blocked_bytes,
                    before.frames,
                    before.bytes,
                ),
            )?;

            let mutation = supervisor.apply_authorization_control(&state.control)?;
            if mutation.control.envelope_id != state.control.envelope_id()
                || mutation.control.generation_after
                    != mutation.control.generation_before.saturating_add(1)
                || mutation.contacts_requiring_reauthentication != stale_contacts
            {
                return Err(invalid(
                    "Gate-H signed-control mutation did not cover both exact stale contacts",
                ));
            }
            receipt.gate_h_generation_before = Some(mutation.control.generation_before);
            receipt.gate_h_generation_after = Some(mutation.control.generation_after);
            append_event(
                events_path,
                &format!(
                    "{{\"event\":\"authorization_control_applied\",\"control_id\":\"{}\",\"generation_before\":{},\"generation_after\":{},\"contacts_invalidated\":{}}}",
                    hex(mutation.control.envelope_id.as_bytes()),
                    mutation.control.generation_before,
                    mutation.control.generation_after,
                    mutation.contacts_requiring_reauthentication.len(),
                ),
            )?;

            match supervisor.drive_contact(target_contact, Instant::now()) {
                Err(ContactSupervisorError::AuthorizationChanged(changed))
                    if changed == target_contact => {}
                Ok(_) => {
                    return Err(invalid(
                        "Gate-H stale queued frame did not fail its pre-flush generation check",
                    ));
                }
                Err(error) => return Err(error.into()),
            }
            append_shared_node_evidence(supervisor, provider, receipt, events_path, started)?;
            let after = native_contact_sent(provider, target_contact)?;
            receipt.gate_h_stale_send_frames_after = after.frames;
            receipt.gate_h_stale_send_bytes_after = after.bytes;
            receipt.gate_h_stale_zero_bytes_emitted = before == after;
            if !receipt.gate_h_stale_zero_bytes_emitted {
                return Err(invalid(
                    "Gate-H stale-generation Aster bytes crossed the carrier boundary",
                ));
            }
            append_event(
                events_path,
                &format!(
                    "{{\"event\":\"stale_generation_blocked\",\"peer\":\"{}\",\"contact\":{},\"queued_frames\":{},\"sent_frames_before\":{},\"sent_frames_after\":{},\"sent_bytes_before\":{},\"sent_bytes_after\":{},\"zero_bytes_emitted\":true}}",
                    hex(&state.target_peer),
                    target_contact.0,
                    receipt.gate_h_stale_queued_frames,
                    before.frames,
                    after.frames,
                    before.bytes,
                    after.bytes,
                ),
            )?;

            for contact in &stale_contacts {
                close_native_contact_with_label(
                    supervisor,
                    provider,
                    *contact,
                    true,
                    "authorization-control-retired",
                    events_path,
                )?;
            }
            receipt.gate_h_stale_contacts_retired = stale_contacts.len();
            if receipt.gate_h_stale_contacts_retired != 2
                || !supervisor.contact_status().is_empty()
                || !provider.contacts.is_empty()
            {
                return Err(invalid(
                    "Gate-H did not retire both stale Aster sessions before epoch rotation",
                ));
            }
            append_event(
                events_path,
                &format!(
                    "{{\"event\":\"stale_contacts_retired\",\"contacts\":[{},{}],\"count\":2}}",
                    stale_contacts[0].0, stale_contacts[1].0,
                ),
            )?;

            {
                let mut barrier = provider.gate_h_barrier.lock().map_err(lock_error)?;
                barrier.enabled = false;
                barrier.target_route = None;
            }
            let old_instance_nonce = local_carrier.instance_nonce;
            let new_instance_nonce = new_native_carrier_instance_nonce()?;
            if new_instance_nonce == old_instance_nonce {
                return Err(invalid("Gate-H provider epoch nonce did not rotate"));
            }
            local_carrier.instance_nonce = new_instance_nonce;
            let routes = provider
                .endpoints
                .values()
                .map(|endpoint| endpoint.route)
                .collect::<Vec<_>>();
            for route in routes {
                send_carrier_hello(raw, route, *local_carrier, receipt)?;
                if let Some(locator) = provider.route_to_locator.get(&route)
                    && let Some(endpoint) = provider.endpoints.get_mut(locator)
                {
                    endpoint.last_hello_sent = Some(Instant::now());
                }
            }
            receipt.gate_h_provider_epoch_rotations = 1;
            append_event(
                events_path,
                &format!(
                    "{{\"event\":\"carrier_session_epoch_rotated\",\"cause\":\"local-signed-control\",\"generation\":{},\"carrier_id\":\"{}\",\"old_instance_nonce\":\"{}\",\"new_instance_nonce\":\"{}\",\"stale_contacts_retired\":2}}",
                    mutation.control.generation_after,
                    hex(&local_carrier.carrier_id),
                    hex(&old_instance_nonce),
                    hex(&new_instance_nonce),
                ),
            )?;
            state.phase = NativeGateHLivePhase::AwaitingFreshTargetAdmission;
        }
        NativeGateHLivePhase::AwaitingFreshTargetAdmission => {
            let Some((contact, _)) = provider.contacts.iter().find(|(contact, active)| {
                active.admitted_peer == Some(state.target_peer)
                    && Some(**contact) != state.stale_target_contact
                    && Some(active.remote_instance) != state.stale_target_remote_instance
                    && supervisor
                        .contact_status()
                        .iter()
                        .any(|status| status.contact == **contact && status.admitted)
            }) else {
                return Ok(());
            };
            let contact = *contact;
            let generation = supervisor.authorization_generation()?;
            let baseline = native_contact_sent(provider, contact)?;
            receipt.gate_h_fresh_target_contact = Some(contact);
            receipt.gate_h_fresh_target_generation = Some(generation);
            state.phase = NativeGateHLivePhase::AwaitingFreshTargetProgress { contact, baseline };
        }
        NativeGateHLivePhase::AwaitingFreshTargetProgress { contact, baseline } => {
            let Some(active) = provider.contacts.get(&contact) else {
                state.phase = NativeGateHLivePhase::AwaitingFreshTargetAdmission;
                return Ok(());
            };
            if active.admitted_peer != Some(state.target_peer) {
                return Err(invalid("Gate-H fresh contact changed authenticated peer"));
            }
            let current = *active.sent.lock().map_err(lock_error)?;
            if current.frames <= baseline.frames || current.bytes <= baseline.bytes {
                return Ok(());
            }
            let generation = supervisor.authorization_generation()?;
            if Some(generation) != receipt.gate_h_generation_after {
                return Err(invalid(
                    "Gate-H fresh progress did not use the post-control generation",
                ));
            }
            receipt.gate_h_fresh_aster_frames_sent = current.frames.saturating_sub(baseline.frames);
            receipt.gate_h_fresh_aster_bytes_sent = current.bytes.saturating_sub(baseline.bytes);
            receipt.gate_h_completed = true;
            append_event(
                events_path,
                &format!(
                    "{{\"event\":\"fresh_authorized_progress\",\"peer\":\"{}\",\"contact\":{},\"generation\":{},\"aster_frames_sent\":{},\"aster_bytes_sent\":{}}}",
                    hex(&state.target_peer),
                    contact.0,
                    generation,
                    receipt.gate_h_fresh_aster_frames_sent,
                    receipt.gate_h_fresh_aster_bytes_sent,
                ),
            )?;
            state.phase = NativeGateHLivePhase::Complete;
        }
        NativeGateHLivePhase::Complete => {}
    }
    Ok(())
}

fn close_native_contact(
    supervisor: &mut SharedNodeContactSupervisor,
    provider: &mut NativeProvider,
    contact: ContactId,
    failed: bool,
    reason: Option<ContactCloseReason>,
    events_path: &Path,
) -> LabResult<()> {
    close_native_contact_with_label(
        supervisor,
        provider,
        contact,
        failed,
        reason.map_or(
            if failed { "failure" } else { "shutdown" },
            native_close_reason,
        ),
        events_path,
    )
}

fn close_native_contact_with_label(
    supervisor: &mut SharedNodeContactSupervisor,
    provider: &mut NativeProvider,
    contact: ContactId,
    failed: bool,
    reason: &str,
    events_path: &Path,
) -> LabResult<()> {
    let Some(active) = provider.contacts.get(&contact) else {
        return Ok(());
    };
    let route = active.route;
    let address = active.address;
    let active_contact = active.contact;
    match supervisor.close_contact(contact, failed, Instant::now()) {
        Ok(_) => {}
        Err(ContactSupervisorError::UnknownContact(retired)) if retired == contact => {
            // Terminal drive failures retire the common runtime/session/lease
            // and Host state before returning. Provider teardown remains
            // responsible only for its carrier route and queue.
        }
        Err(error) => return Err(error.into()),
    }
    provider.contacts.remove(&contact);
    if provider.route_contacts.get(&route) == Some(&contact) {
        provider.route_contacts.remove(&route);
    }
    append_event(
        events_path,
        &format!(
            "{{\"event\":\"contact_closed\",\"contact\":{},\"address\":\"{}\",\"reason\":\"{}\"}}",
            active_contact.0,
            address,
            json_escape(reason)
        ),
    )?;
    Ok(())
}

fn native_close_reason(reason: ContactCloseReason) -> &'static str {
    match reason {
        ContactCloseReason::Capacity => "capacity",
        ContactCloseReason::Duplicate => "duplicate",
        ContactCloseReason::FairnessQuantum => "fairness-quantum",
        ContactCloseReason::AuthenticationRejected => "authentication-rejected",
        ContactCloseReason::EmissionPolicy => "emission-policy",
    }
}

#[allow(clippy::too_many_arguments)]
fn next_native_wakeup(
    supervisor: &SharedNodeContactSupervisor,
    raw: &Arc<IpLink>,
    provider: &NativeProvider,
    next_discovery: Instant,
    next_status: Instant,
    deadline: Instant,
    now: Instant,
) -> Instant {
    provider
        .pending_dials
        .values()
        .flat_map(|pending| [pending.next_hello, pending.deadline])
        .chain(supervisor.next_wakeup(now))
        .chain(raw.next_wakeup())
        .chain([next_discovery, next_status, deadline])
        .min()
        .unwrap_or(deadline)
}

fn send_carrier_hello(
    raw: &IpLink,
    route: NodeId,
    carrier: NativeCarrierHello,
    receipt: &mut NativeMeshNodeReceipt,
) -> io::Result<()> {
    raw.send(Some(route), &encode_carrier_hello(carrier))?;
    receipt.carrier_control_frames_sent = receipt.carrier_control_frames_sent.saturating_add(1);
    receipt.carrier_control_bytes_sent = receipt
        .carrier_control_bytes_sent
        .saturating_add(u64::try_from(CARRIER_HELLO_LEN).unwrap_or(u64::MAX));
    Ok(())
}

fn encode_carrier_hello(carrier: NativeCarrierHello) -> [u8; CARRIER_HELLO_LEN] {
    let mut hello = [0_u8; CARRIER_HELLO_LEN];
    hello[..CARRIER_HELLO_MAGIC.len()].copy_from_slice(CARRIER_HELLO_MAGIC);
    let carrier_end = CARRIER_HELLO_MAGIC.len() + CARRIER_ID_BYTES;
    hello[CARRIER_HELLO_MAGIC.len()..carrier_end].copy_from_slice(&carrier.carrier_id);
    hello[carrier_end..].copy_from_slice(&carrier.instance_nonce);
    hello
}

fn decode_carrier_hello(bytes: &[u8]) -> Option<NativeCarrierHello> {
    if bytes.len() != CARRIER_HELLO_LEN
        || &bytes[..CARRIER_HELLO_MAGIC.len()] != CARRIER_HELLO_MAGIC
    {
        return None;
    }
    let carrier_end = CARRIER_HELLO_MAGIC.len() + CARRIER_ID_BYTES;
    let mut carrier_id = [0_u8; CARRIER_ID_BYTES];
    carrier_id.copy_from_slice(&bytes[CARRIER_HELLO_MAGIC.len()..carrier_end]);
    let mut instance_nonce = [0_u8; CARRIER_INSTANCE_NONCE_BYTES];
    instance_nonce.copy_from_slice(&bytes[carrier_end..]);
    (carrier_id != [0; CARRIER_ID_BYTES] && instance_nonce != [0; CARRIER_INSTANCE_NONCE_BYTES])
        .then_some(NativeCarrierHello {
            carrier_id,
            instance_nonce,
        })
}

fn encode_carrier_data(
    sender: NativeCarrierHello,
    expected_receiver: NativeCarrierHello,
    frame: &[u8],
) -> io::Result<Vec<u8>> {
    if frame.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty native Aster carrier frame",
        ));
    }
    let capacity = CARRIER_DATA_HEADER_LEN
        .checked_add(frame.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "carrier frame overflow"))?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(CARRIER_DATA_MAGIC);
    encoded.extend_from_slice(&sender.carrier_id);
    encoded.extend_from_slice(&sender.instance_nonce);
    encoded.extend_from_slice(&expected_receiver.carrier_id);
    encoded.extend_from_slice(&expected_receiver.instance_nonce);
    encoded.extend_from_slice(frame);
    Ok(encoded)
}

fn decode_carrier_data(bytes: &[u8]) -> Option<(NativeCarrierHello, NativeCarrierHello, &[u8])> {
    if bytes.len() <= CARRIER_DATA_HEADER_LEN
        || &bytes[..CARRIER_DATA_MAGIC.len()] != CARRIER_DATA_MAGIC
    {
        return None;
    }
    let mut cursor = CARRIER_DATA_MAGIC.len();
    let mut sender_id = [0_u8; CARRIER_ID_BYTES];
    sender_id.copy_from_slice(&bytes[cursor..cursor + CARRIER_ID_BYTES]);
    cursor += CARRIER_ID_BYTES;
    let mut sender_nonce = [0_u8; CARRIER_INSTANCE_NONCE_BYTES];
    sender_nonce.copy_from_slice(&bytes[cursor..cursor + CARRIER_INSTANCE_NONCE_BYTES]);
    cursor += CARRIER_INSTANCE_NONCE_BYTES;
    let mut receiver_id = [0_u8; CARRIER_ID_BYTES];
    receiver_id.copy_from_slice(&bytes[cursor..cursor + CARRIER_ID_BYTES]);
    cursor += CARRIER_ID_BYTES;
    let mut receiver_nonce = [0_u8; CARRIER_INSTANCE_NONCE_BYTES];
    receiver_nonce.copy_from_slice(&bytes[cursor..cursor + CARRIER_INSTANCE_NONCE_BYTES]);
    cursor += CARRIER_INSTANCE_NONCE_BYTES;
    if sender_id == [0; CARRIER_ID_BYTES]
        || sender_nonce == [0; CARRIER_INSTANCE_NONCE_BYTES]
        || receiver_id == [0; CARRIER_ID_BYTES]
        || receiver_nonce == [0; CARRIER_INSTANCE_NONCE_BYTES]
    {
        return None;
    }
    Some((
        NativeCarrierHello {
            carrier_id: sender_id,
            instance_nonce: sender_nonce,
        },
        NativeCarrierHello {
            carrier_id: receiver_id,
            instance_nonce: receiver_nonce,
        },
        &bytes[cursor..],
    ))
}

fn parse_native_manual_peers(value: &str) -> LabResult<Vec<NativeManualPeer>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut peers = Vec::new();
    let mut exact = BTreeSet::new();
    let mut address_owners = BTreeMap::<SocketAddr, NodeId>::new();
    for entry in value.split(',') {
        let (node, address) = entry
            .split_once('@')
            .ok_or_else(|| invalid("native manual peers must use NODE_ID@IP:PORT"))?;
        let peer = decode_native_node_id(node)?;
        let address: SocketAddr = address
            .parse()
            .map_err(|error| invalid(format!("invalid native manual peer address: {error}")))?;
        if address.port() == 0 || address.ip().is_unspecified() || !address.is_ipv4() {
            return Err(invalid(
                "native manual peer requires a concrete IPv4 address and nonzero port",
            ));
        }
        if let Some(owner) = address_owners.insert(address, peer)
            && owner != peer
        {
            return Err(invalid(
                "native manual peer address was assigned to conflicting NodeIDs",
            ));
        }
        if exact.insert((peer, address)) {
            peers.push(NativeManualPeer { peer, address });
        }
    }
    if peers.len() > MAX_CANDIDATES_HARD {
        return Err(invalid("native manual peer list exceeds the hard bound"));
    }
    Ok(peers)
}

fn decode_native_node_id(value: &str) -> LabResult<NodeId> {
    if value.len() != 64 {
        return Err(invalid(
            "native manual peer NodeID must contain 64 hex digits",
        ));
    }
    let mut result = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair)?;
        result[index] = u8::from_str_radix(text, 16)?;
    }
    if result == [0; 32] {
        return Err(invalid("native manual peer NodeID cannot be zero"));
    }
    Ok(result)
}

fn native_emission_policy(value: &str) -> LabResult<EmissionPolicy> {
    match value {
        "normal" => Ok(EmissionPolicy::default()),
        "constrained" => Ok(EmissionPolicy {
            minimum_priority: Some(Priority::Immediate),
        }),
        "receive-only" => Ok(EmissionPolicy::receive_only()),
        "flash-only" => Ok(EmissionPolicy {
            minimum_priority: Some(Priority::Flash),
        }),
        _ => Err(invalid(
            "native emission mode must be normal, constrained, receive-only, or flash-only",
        )),
    }
}

fn ip_mesh_application_options(payload_bytes: usize) -> LabResult<ApplicationNodeOptions> {
    let mut node = ApplicationNodeOptions::default();
    node.max_items = node.max_items.max(4_096);
    node.max_bytes = node.max_bytes.max(
        u64::try_from(payload_bytes)?
            .saturating_mul(32)
            .saturating_add(4 * 1_024 * 1_024),
    );
    Ok(node)
}

fn single_data_envelope(
    database: &Path,
    credentials: &[u8],
    topic: &Topic,
    scope: &Scope,
) -> LabResult<EnvelopeId> {
    let bundle = ProvisioningBundle::from_bytes(credentials)?;
    let mut node = open_reference_node(database, bundle, NodeConfig::default())?;
    let filter = InterestFilter {
        topics: vec![topic.as_str().to_owned()],
        scopes: vec![scope.as_str().to_owned()],
        min_priority: Priority::Routine as u8,
    };
    let descriptors = node
        .authorized_envelopes([0xff; 32], &[], &filter, InventoryPurpose::ReceiveBaseline)?
        .into_iter()
        .filter(|descriptor| !descriptor.control)
        .collect::<Vec<_>>();
    if descriptors.len() != 1 {
        return Err(invalid(format!(
            "expected exactly one data envelope in {}, found {}",
            database.display(),
            descriptors.len()
        )));
    }
    Ok(descriptors[0].envelope_id)
}

fn prepare_fresh_root(root: &Path) -> LabResult<()> {
    match fs::metadata(root) {
        Ok(metadata) if !metadata.is_dir() => Err(invalid(
            "IP mesh preparation root exists and is not a directory",
        )),
        Ok(_) if fs::read_dir(root)?.next().is_some() => {
            Err(invalid("IP mesh preparation root must be absent or empty"))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(root)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn load_or_create_carrier_id(root: &Path) -> LabResult<[u8; 32]> {
    let path = root.join("native-carrier.key");
    if path.is_file() {
        let bytes = read_bounded(&path, 32)?;
        if bytes.len() != 32 {
            return Err(invalid("native carrier key has the wrong length"));
        }
        let mut id = [0_u8; 32];
        id.copy_from_slice(&bytes);
        if id == [0; 32] {
            return Err(invalid("native carrier key cannot be zero"));
        }
        return Ok(id);
    }
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret)?;
    let identity: [u8; 32] = Sha256::digest(secret).into();
    secret.fill(0);
    write_private_new(&path, &identity)?;
    Ok(identity)
}

fn new_native_carrier_instance_nonce() -> LabResult<[u8; CARRIER_INSTANCE_NONCE_BYTES]> {
    let mut nonce = [0_u8; CARRIER_INSTANCE_NONCE_BYTES];
    for _ in 0..4 {
        getrandom::fill(&mut nonce)?;
        if nonce != [0; CARRIER_INSTANCE_NONCE_BYTES] {
            return Ok(nonce);
        }
    }
    Err(invalid(
        "could not allocate a nonzero native carrier instance nonce",
    ))
}

fn read_bounded(path: &Path, limit: usize) -> LabResult<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    let length = usize::try_from(metadata.len())?;
    if !metadata.is_file() || length == 0 || length > limit {
        return Err(invalid(format!("invalid bounded file {}", path.display())));
    }
    let bytes = fs::read(path)?;
    if bytes.len() != length {
        return Err(invalid("bounded file changed while being read"));
    }
    Ok(bytes)
}

fn read_array<const N: usize>(path: &Path) -> LabResult<[u8; N]> {
    let bytes = read_bounded(path, N)?;
    if bytes.len() != N {
        return Err(invalid(format!(
            "{} must contain exactly {N} bytes",
            path.display()
        )));
    }
    let mut value = [0_u8; N];
    value.copy_from_slice(&bytes);
    Ok(value)
}

fn tree_contains(root: &Path, needle: &[u8]) -> LabResult<bool> {
    if needle.is_empty() || !root.exists() {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() {
        return Err(invalid(format!(
            "refusing to scan symbolic link {}",
            root.display()
        )));
    }
    if metadata.is_file() {
        let bytes = fs::read(root)?;
        return Ok(bytes.windows(needle.len()).any(|window| window == needle));
    }
    for entry in fs::read_dir(root)? {
        if tree_contains(&entry?.path(), needle)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_invocation(invocation: &str) -> LabResult<()> {
    if invocation.is_empty()
        || invocation.len() > 64
        || !invocation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid("invalid evidence invocation label"));
    }
    Ok(())
}

fn append_event(path: &Path, line: &str) -> LabResult<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    if file.metadata()?.len() >= MAX_EVENTS_BYTES {
        return Err(invalid("native mesh event log capacity reached"));
    }
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_data()?;
    Ok(())
}

fn write_replace(path: &Path, bytes: &[u8]) -> LabResult<()> {
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, path)?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> LabResult<()> {
    // Prepare and sync the complete artifact before publishing its pathname.
    // A same-directory hard link is an atomic, no-clobber commit marker: if
    // any preparation step fails, `path` never exists and a rerun is possible.
    let temporary = path.with_extension(format!("commit-{}.tmp", std::process::id()));
    let prepared = (|| -> LabResult<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = prepared {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = fs::hard_link(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    // The linked inode is the durable artifact; temp cleanup is best effort
    // and cannot turn a committed success into a reported failure.
    let _ = fs::remove_file(&temporary);
    Ok(())
}

fn write_binary_new(path: &Path, bytes: &[u8]) -> LabResult<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_private_new(path: &Path, bytes: &[u8]) -> LabResult<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn json_node_resource_limits(limits: NodeResourceLimits) -> String {
    format!(
        concat!(
            "{{\"candidates\":{},\"pending_connections\":{},",
            "\"pre_authentication_contacts\":{},\"admitted_contacts\":{},",
            "\"streams\":{},\"tasks\":{},\"frames\":{},",
            "\"inbound_bytes\":{},\"outbound_bytes\":{},",
            "\"descriptors\":{},\"relay_reservations\":{}}}"
        ),
        limits.candidates,
        limits.pending_connections,
        limits.pre_authentication_contacts,
        limits.admitted_contacts,
        limits.streams,
        limits.tasks,
        limits.frames,
        limits.inbound_bytes,
        limits.outbound_bytes,
        limits.descriptors,
        limits.relay_reservations,
    )
}

fn json_node_resource_claim(claim: NodeResourceClaim) -> String {
    format!(
        concat!(
            "{{\"candidates\":{},\"pending_connections\":{},",
            "\"pre_authentication_contacts\":{},\"admitted_contacts\":{},",
            "\"streams\":{},\"tasks\":{},\"frames\":{},",
            "\"inbound_bytes\":{},\"outbound_bytes\":{},",
            "\"descriptors\":{},\"relay_reservations\":{}}}"
        ),
        claim.candidates,
        claim.pending_connections,
        claim.pre_authentication_contacts,
        claim.admitted_contacts,
        claim.streams,
        claim.tasks,
        claim.frames,
        claim.inbound_bytes,
        claim.outbound_bytes,
        claim.descriptors,
        claim.relay_reservations,
    )
}

fn json_node_set(values: &BTreeSet<NodeId>) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| format!("\"{}\"", hex(value)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn json_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect(),
            '\n' | '\r' | '\t' => " ".chars().collect(),
            value if value.is_control() => "?".chars().collect(),
            value => vec![value],
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn lock_error<T>(_: std::sync::PoisonError<T>) -> io::Error {
    io::Error::other("native mesh state lock poisoned")
}

fn invalid(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    const NATIVE_TEST_MTU_BYTES: u16 = 1_400;
    const GATE_H_MULTI_FRAME_TEST_PAYLOAD_BYTES: usize = NATIVE_TEST_MTU_BYTES as usize + 1;

    #[derive(Clone)]
    struct NativeTestLink {
        inbound: Arc<Mutex<VecDeque<ReceivedFrame>>>,
        outbound: Arc<Mutex<VecDeque<ReceivedFrame>>>,
        sends: Arc<AtomicU64>,
    }

    impl NativeTestLink {
        fn pair() -> (Self, Self, Arc<AtomicU64>, Arc<AtomicU64>) {
            let left = Arc::new(Mutex::new(VecDeque::new()));
            let right = Arc::new(Mutex::new(VecDeque::new()));
            let left_sends = Arc::new(AtomicU64::new(0));
            let right_sends = Arc::new(AtomicU64::new(0));
            (
                Self {
                    inbound: Arc::clone(&left),
                    outbound: Arc::clone(&right),
                    sends: Arc::clone(&left_sends),
                },
                Self {
                    inbound: right,
                    outbound: left,
                    sends: Arc::clone(&right_sends),
                },
                left_sends,
                right_sends,
            )
        }
    }

    impl Link for NativeTestLink {
        fn name(&self) -> &str {
            "native-test-link"
        }

        fn characteristics(&self) -> LinkCharacteristics {
            LinkCharacteristics {
                mtu: NATIVE_TEST_MTU_BYTES,
                bits_per_second: None,
                cost: 0,
                emission: 0,
                broadcast: false,
            }
        }

        fn send(&self, _peer: Option<NodeId>, frame: &[u8]) -> io::Result<()> {
            self.outbound
                .lock()
                .map_err(lock_error)?
                .push_back(ReceivedFrame {
                    peer: None,
                    bytes: frame.to_vec(),
                });
            self.sends.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn try_receive(&self) -> io::Result<Option<ReceivedFrame>> {
            Ok(self.inbound.lock().map_err(lock_error)?.pop_front())
        }

        fn set_discovery(&self, _enabled: bool) -> io::Result<()> {
            Ok(())
        }
    }

    fn native_test_root(label: &str) -> PathBuf {
        let mut suffix = [0_u8; 8];
        getrandom::fill(&mut suffix).unwrap();
        std::env::temp_dir().join(format!("aster-native-{label}-{}", hex(&suffix)))
    }

    fn native_test_config(
        root: &Path,
        role: &str,
        prepared: &MeshPrepareReceipt,
        expected_peers: BTreeSet<NodeId>,
        max_active_contacts: usize,
    ) -> NativeMeshNodeConfig {
        NativeMeshNodeConfig {
            invocation: format!("test-{role}"),
            root: root.join(role),
            credential_path: root.join(format!("private/{role}.bundle")),
            topic: prepared.topic.clone(),
            scope: prepared.scope.clone(),
            discovery_token: [0x51; 16],
            bind: "127.0.0.1:47101".parse().unwrap(),
            discovery_target: "127.0.0.1:47101".parse().unwrap(),
            max_candidates: 8,
            max_active_contacts,
            run_for: Duration::from_secs(1),
            discovery_enabled: false,
            expected_peers,
            manual_peers: String::new(),
            emission_mode: "normal".to_owned(),
            gate_h_control_path: None,
            gate_h_stale_target_peer: None,
            durable_item_probe: None,
        }
    }

    fn open_native_test_supervisor(
        config: &NativeMeshNodeConfig,
        limits: Option<NodeResourceLimits>,
    ) -> (NodeId, SharedNodeContactSupervisor) {
        let credentials = fs::read(&config.credential_path).unwrap();
        let emission = native_emission_policy(&config.emission_mode).unwrap();
        let (identity, supervisor, construction) = match limits {
            Some(limits) => {
                open_native_shared_supervisor_with_limits(config, emission, credentials, limits)
            }
            None => open_native_shared_supervisor(config, emission, credentials),
        }
        .unwrap();
        assert_eq!(
            construction,
            NativeAuthorityConstructionFacts {
                sqlite_node_open_count: 1,
                blob_authority_open_count: 1,
                semantic_backend_construction_count: 1,
                process_authority_construction_count: 1,
            }
        );
        (identity, supervisor)
    }

    fn open_native_test_contact(
        supervisor: &mut SharedNodeContactSupervisor,
        contact: ContactId,
        ordinal: u16,
        remote: NodeId,
        role: ContactSessionRole,
        link: NativeTestLink,
    ) {
        let now = Instant::now();
        let candidate = CandidateId::new(format!("gate-h-{ordinal:04}")).unwrap();
        let locator = CandidateLocator::new(format!("127.0.0.1:{}", 40_000_u16 + ordinal)).unwrap();
        supervisor
            .observe_candidate(
                candidate.clone(),
                locator.clone(),
                CandidateProvenance::Manual,
                ContactPath::Direct,
                Some(remote),
                now,
            )
            .unwrap();
        let report = supervisor
            .open_contact_with_factory(
                ContactOpening {
                    contact,
                    candidate,
                    locator,
                    carrier_identity: Some(
                        CarrierIdentity::new(ordinal.to_be_bytes().repeat(4)).unwrap(),
                    ),
                    direction: ContactDirection::Inbound,
                    path: ContactPath::Direct,
                    role,
                },
                now,
                || link,
            )
            .unwrap();
        assert!(report.opened);
        assert!(report.actions.is_empty());
    }

    fn contact_is_admitted(supervisor: &SharedNodeContactSupervisor, contact: ContactId) -> bool {
        supervisor
            .contact_status()
            .into_iter()
            .find(|status| status.contact == contact)
            .is_some_and(|status| status.admitted)
    }

    fn pending_outbound_frames(
        supervisor: &SharedNodeContactSupervisor,
        contact: ContactId,
    ) -> usize {
        supervisor
            .contact_status()
            .into_iter()
            .find(|status| status.contact == contact)
            .map_or(0, |status| status.pending_outbound_frames)
    }

    fn native_test_receipt(
        identity: NodeId,
        carrier_id: [u8; CARRIER_ID_BYTES],
        supervisor: &SharedNodeContactSupervisor,
    ) -> NativeMeshNodeReceipt {
        NativeMeshNodeReceipt {
            identity,
            carrier_id,
            candidates_discovered: 0,
            candidates_rejected_capacity: 0,
            authenticated_peers: BTreeSet::new(),
            admitted_peers: BTreeSet::new(),
            unauthorized_peers: BTreeSet::new(),
            contact_failures: 0,
            duplicate_contacts: 0,
            aster_frames_received: 0,
            aster_frames_sent: 0,
            aster_bytes_received: 0,
            aster_bytes_sent: 0,
            carrier_control_frames_received: 0,
            carrier_control_frames_sent: 0,
            carrier_control_bytes_received: 0,
            carrier_control_bytes_sent: 0,
            pump_calls: 0,
            discovery_announcements: 0,
            elapsed_ms: 0,
            first_candidate_ms: None,
            first_authenticated_ms: None,
            active_contact_high_water: 0,
            admitted_contact_high_water: 0,
            sqlite_node_open_count: 1,
            blob_authority_open_count: 1,
            semantic_backend_construction_count: 1,
            process_authority_construction_count: 1,
            durable_authority_open_count: 1,
            authorization_generation_checks: 0,
            authorization_generation_mismatches: 0,
            authorization_generation_unavailable: 0,
            authorization_generation_current: 0,
            durable_item_probe_id: None,
            durable_item_present: None,
            gate_h_control_id: None,
            gate_h_generation_before: None,
            gate_h_generation_after: None,
            gate_h_stale_target_peer: None,
            gate_h_stale_target_contact: None,
            gate_h_stale_queued_frames: 0,
            gate_h_stale_send_frames_before: 0,
            gate_h_stale_send_frames_after: 0,
            gate_h_stale_send_bytes_before: 0,
            gate_h_stale_send_bytes_after: 0,
            gate_h_stale_zero_bytes_emitted: false,
            gate_h_stale_contacts_retired: 0,
            gate_h_provider_epoch_rotations: 0,
            gate_h_fresh_target_contact: None,
            gate_h_fresh_target_generation: None,
            gate_h_fresh_aster_frames_sent: 0,
            gate_h_fresh_aster_bytes_sent: 0,
            gate_h_completed: false,
            node_resources: supervisor.resource_snapshot().unwrap(),
        }
    }

    fn native_test_provider(supervisor: &SharedNodeContactSupervisor) -> NativeProvider {
        initialize_native_provider(supervisor, || Ok(())).unwrap().0
    }

    #[test]
    fn native_receipt_serializes_exact_durable_item_observation() {
        let root = native_test_root("receipt-durable-item");
        let prepared = prepare_ip_mesh(&MeshPrepareConfig {
            root: root.clone(),
            seed: 0xd341,
            payload_bytes: 64,
        })
        .unwrap();
        let config = native_test_config(&root, "b", &prepared, BTreeSet::new(), 1);
        let (identity, supervisor) = open_native_test_supervisor(&config, None);
        let mut receipt = native_test_receipt(identity, [0xa4; CARRIER_ID_BYTES], &supervisor);
        receipt.durable_item_probe_id = Some([0xd3; 32]);
        receipt.durable_item_present = Some(false);

        let json = receipt.to_json();
        assert!(json.contains(&format!(
            "\"durable_item_probe_id\": \"{}\"",
            hex(&[0xd3; 32])
        )));
        assert!(json.contains("\"durable_item_present\": false"));

        drop(supervisor);
        fs::remove_dir_all(root).unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    fn pump_native_test_process(
        supervisor: &mut SharedNodeContactSupervisor,
        raw: &Arc<IpLink>,
        provider: &mut NativeProvider,
        aster_sent: &Arc<Mutex<NativeAsterSendCounters>>,
        receipt: &mut NativeMeshNodeReceipt,
        config: &NativeMeshNodeConfig,
        events_path: &Path,
        started: Instant,
        local_carrier: NativeCarrierHello,
        deadline: Instant,
    ) {
        let mut local_carrier = local_carrier;
        for (route, remote_carrier) in drain_native_frames(raw, provider, receipt, local_carrier)
            .expect("native test receive must succeed")
        {
            handle_native_hello(
                route,
                remote_carrier,
                supervisor,
                raw,
                provider,
                aster_sent,
                receipt,
                events_path,
                local_carrier,
                Instant::now(),
            )
            .expect("native test hello must succeed");
        }
        pump_native_contacts(
            supervisor,
            raw,
            provider,
            config,
            receipt,
            events_path,
            started,
            &mut local_carrier,
            deadline,
        )
        .expect("native test contact pump must succeed");
    }

    #[test]
    fn carrier_hello_round_trips_without_mission_identity() {
        let carrier = NativeCarrierHello {
            carrier_id: [0x73; CARRIER_ID_BYTES],
            instance_nonce: [0x91; CARRIER_INSTANCE_NONCE_BYTES],
        };
        let mut bytes = encode_carrier_hello(carrier);
        assert_eq!(decode_carrier_hello(&bytes), Some(carrier));
        bytes[0] ^= 1;
        assert_eq!(decode_carrier_hello(&bytes), None);

        let mut bytes = encode_carrier_hello(carrier);
        let instance_start = CARRIER_HELLO_MAGIC.len() + CARRIER_ID_BYTES;
        bytes[instance_start..].fill(0);
        assert_eq!(decode_carrier_hello(&bytes), None);
    }

    #[test]
    fn native_carrier_data_rejects_delayed_predecessor_epoch_frames() {
        let root = native_test_root("carrier-data-epoch");
        let prepared = prepare_ip_mesh(&MeshPrepareConfig {
            root: root.clone(),
            seed: 0xc412,
            payload_bytes: 64,
        })
        .unwrap();
        let config = native_test_config(&root, "c", &prepared, BTreeSet::from([prepared.relay]), 1);
        let (identity, supervisor) = open_native_test_supervisor(&config, None);
        let mut provider = native_test_provider(&supervisor);
        let route = [0x51; 32];
        let contact = ContactId(1);
        let remote = NativeCarrierHello {
            carrier_id: [0x61; CARRIER_ID_BYTES],
            instance_nonce: [0x62; CARRIER_INSTANCE_NONCE_BYTES],
        };
        let retired_local = NativeCarrierHello {
            carrier_id: [0x71; CARRIER_ID_BYTES],
            instance_nonce: [0x72; CARRIER_INSTANCE_NONCE_BYTES],
        };
        let current_local = NativeCarrierHello {
            carrier_id: retired_local.carrier_id,
            instance_nonce: [0x73; CARRIER_INSTANCE_NONCE_BYTES],
        };
        let inbound = Arc::new(Mutex::new(ContactQueue::default()));
        provider.route_contacts.insert(route, contact);
        provider.contacts.insert(
            contact,
            NativeContact {
                contact,
                address: "127.0.0.1:40112".parse().unwrap(),
                route,
                inbound: Arc::clone(&inbound),
                admitted_peer: Some(prepared.relay),
                remote_instance: remote,
                sent: Arc::new(Mutex::new(NativeAsterSendCounters::default())),
            },
        );
        let mut receipt = native_test_receipt(identity, current_local.carrier_id, &supervisor);

        let stale = encode_carrier_data(remote, retired_local, b"stale predecessor").unwrap();
        assert!(
            dispatch_native_frame(
                ReceivedFrame {
                    peer: Some(route),
                    bytes: stale,
                },
                &mut provider,
                &mut receipt,
                current_local,
            )
            .unwrap()
            .is_none()
        );
        assert!(inbound.lock().unwrap().frames.is_empty());
        assert_eq!(receipt.aster_frames_received, 0);
        assert_eq!(receipt.aster_bytes_received, 0);

        let retired_remote = NativeCarrierHello {
            carrier_id: remote.carrier_id,
            instance_nonce: [0x63; CARRIER_INSTANCE_NONCE_BYTES],
        };
        let stale = encode_carrier_data(retired_remote, current_local, b"stale sender").unwrap();
        dispatch_native_frame(
            ReceivedFrame {
                peer: Some(route),
                bytes: stale,
            },
            &mut provider,
            &mut receipt,
            current_local,
        )
        .unwrap();
        dispatch_native_frame(
            ReceivedFrame {
                peer: Some(route),
                bytes: b"unwrapped Aster frame".to_vec(),
            },
            &mut provider,
            &mut receipt,
            current_local,
        )
        .unwrap();
        dispatch_native_frame(
            ReceivedFrame {
                peer: Some(route),
                bytes: CARRIER_DATA_MAGIC.to_vec(),
            },
            &mut provider,
            &mut receipt,
            current_local,
        )
        .unwrap();
        assert!(inbound.lock().unwrap().frames.is_empty());
        assert_eq!(receipt.aster_frames_received, 0);
        assert_eq!(receipt.aster_bytes_received, 0);

        let current = encode_carrier_data(remote, current_local, b"fresh session").unwrap();
        dispatch_native_frame(
            ReceivedFrame {
                peer: Some(route),
                bytes: current,
            },
            &mut provider,
            &mut receipt,
            current_local,
        )
        .unwrap();
        let queue = inbound.lock().unwrap();
        assert_eq!(queue.frames, VecDeque::from([b"fresh session".to_vec()]));
        assert_eq!(queue.bytes, b"fresh session".len());
        assert_eq!(receipt.aster_frames_received, 1);
        assert_eq!(receipt.aster_bytes_received, b"fresh session".len() as u64);
        drop(queue);
        drop(provider);
        drop(supervisor);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retired_carrier_instance_history_is_strictly_bounded() {
        let mut endpoint = NativeEndpoint {
            candidate: CandidateId::new("bounded-instance-history").unwrap(),
            provenance: CandidateProvenance::Automatic,
            address: "127.0.0.1:47001".parse().unwrap(),
            route: [0x47; 32],
            last_hello_sent: None,
            retired_instances: VecDeque::new(),
        };
        let total = MAX_RETIRED_CARRIER_INSTANCES_PER_ENDPOINT + 2;
        for ordinal in 1..=total {
            let mut instance_nonce = [0_u8; CARRIER_INSTANCE_NONCE_BYTES];
            instance_nonce[..std::mem::size_of::<usize>()].copy_from_slice(&ordinal.to_be_bytes());
            remember_retired_native_instance(
                &mut endpoint,
                NativeCarrierHello {
                    carrier_id: [0x81; CARRIER_ID_BYTES],
                    instance_nonce,
                },
            );
        }
        assert_eq!(
            endpoint.retired_instances.len(),
            MAX_RETIRED_CARRIER_INSTANCES_PER_ENDPOINT
        );
        assert_eq!(
            endpoint.retired_instances.front().unwrap().instance_nonce
                [..std::mem::size_of::<usize>()],
            3_usize.to_be_bytes()
        );
    }

    #[test]
    fn same_address_carrier_restart_replaces_and_reauthenticates_one_session() {
        let root = native_test_root("carrier-restart-epoch");
        let prepared = prepare_ip_mesh(&MeshPrepareConfig {
            root: root.clone(),
            seed: 0xc411,
            payload_bytes: 64,
        })
        .unwrap();
        let a_config =
            native_test_config(&root, "a", &prepared, BTreeSet::from([prepared.relay]), 1);
        let b_config = native_test_config(
            &root,
            "b",
            &prepared,
            BTreeSet::from([prepared.publisher]),
            1,
        );
        let (a_identity, mut a) = open_native_test_supervisor(&a_config, None);
        let (b_identity, mut b) = open_native_test_supervisor(&b_config, None);
        let a_carrier_id = load_or_create_carrier_id(&a_config.root).unwrap();
        let b_carrier_id = load_or_create_carrier_id(&b_config.root).unwrap();
        let a_carrier = NativeCarrierHello {
            carrier_id: a_carrier_id,
            instance_nonce: [0xa1; CARRIER_INSTANCE_NONCE_BYTES],
        };
        let b_first = NativeCarrierHello {
            carrier_id: b_carrier_id,
            instance_nonce: [0xb1; CARRIER_INSTANCE_NONCE_BYTES],
        };

        let (mut a_provider, a_raw) = initialize_native_provider(&a, || {
            IpLink::bind(
                "native-restart-a",
                "127.0.0.1:0".parse().unwrap(),
                [0x51; 16],
                None,
            )
        })
        .unwrap();
        let a_raw = Arc::new(a_raw);
        let (mut b_provider, b_raw) = initialize_native_provider(&b, || {
            IpLink::bind(
                "native-restart-b",
                "127.0.0.1:0".parse().unwrap(),
                [0x51; 16],
                None,
            )
        })
        .unwrap();
        let b_raw = Arc::new(b_raw);
        let a_address = a_raw.local_addr().unwrap();
        let b_address = b_raw.local_addr().unwrap();
        let a_candidate = CandidateId::new(format!("manual:{}", hex(&b_identity))).unwrap();
        let a_locator = CandidateLocator::new(b_address.to_string()).unwrap();
        assert!(
            observe_native_endpoint(
                &a_raw,
                &mut a,
                &mut a_provider,
                a_candidate,
                a_locator.clone(),
                b_address,
                CandidateProvenance::Manual,
                Some(b_identity),
                Instant::now(),
            )
            .unwrap()
        );
        let b_candidate = CandidateId::new(format!("manual:{}", hex(&a_identity))).unwrap();
        let b_locator = CandidateLocator::new(a_address.to_string()).unwrap();
        assert!(
            observe_native_endpoint(
                &b_raw,
                &mut b,
                &mut b_provider,
                b_candidate,
                b_locator,
                a_address,
                CandidateProvenance::Manual,
                Some(a_identity),
                Instant::now(),
            )
            .unwrap()
        );
        let a_route = a_provider.endpoints[&a_locator].route;
        let b_route = b_provider.route_to_locator.keys().copied().next().unwrap();
        let a_frames = Arc::new(Mutex::new(NativeAsterSendCounters::default()));
        let b_frames = Arc::new(Mutex::new(NativeAsterSendCounters::default()));
        let a_events = root.join("restart-a-events.jsonl");
        let b_events = root.join("restart-b-first-events.jsonl");
        let started = Instant::now();
        let deadline = started.checked_add(Duration::from_secs(5)).unwrap();
        let mut a_receipt = native_test_receipt(a_identity, a_carrier_id, &a);
        let mut b_receipt = native_test_receipt(b_identity, b_carrier_id, &b);
        handle_native_hello(
            a_route,
            b_first,
            &mut a,
            &a_raw,
            &mut a_provider,
            &a_frames,
            &mut a_receipt,
            &a_events,
            a_carrier,
            started,
        )
        .unwrap();
        handle_native_hello(
            b_route,
            a_carrier,
            &mut b,
            &b_raw,
            &mut b_provider,
            &b_frames,
            &mut b_receipt,
            &b_events,
            b_first,
            started,
        )
        .unwrap();
        while Instant::now() < deadline
            && !(contact_is_admitted(&a, ContactId(1)) && contact_is_admitted(&b, ContactId(1)))
        {
            pump_native_test_process(
                &mut a,
                &a_raw,
                &mut a_provider,
                &a_frames,
                &mut a_receipt,
                &a_config,
                &a_events,
                started,
                a_carrier,
                deadline,
            );
            pump_native_test_process(
                &mut b,
                &b_raw,
                &mut b_provider,
                &b_frames,
                &mut b_receipt,
                &b_config,
                &b_events,
                started,
                b_first,
                deadline,
            );
            std::thread::yield_now();
        }
        assert!(contact_is_admitted(&a, ContactId(1)));
        assert!(contact_is_admitted(&b, ContactId(1)));
        assert_eq!(a.host_snapshot().carrier_binding_count, 1);
        assert!(a_receipt.authenticated_peers.contains(&b_identity));
        assert!(a_receipt.admitted_peers.contains(&b_identity));
        assert!(a_receipt.authorization_generation_checks > 0);
        let lifecycle = fs::read_to_string(&a_events).unwrap();
        let authenticated = lifecycle.find("\"event\":\"aster_authenticated\"").unwrap();
        let prepared = lifecycle.find("\"event\":\"admission_prepared\"").unwrap();
        let generation = lifecycle.find("\"event\":\"generation_checked\"").unwrap();
        let committed = lifecycle.find("\"event\":\"admission_committed\"").unwrap();
        assert!(authenticated < prepared && prepared < generation && generation < committed);

        // Recreate B's process authority and UDP carrier at the exact same
        // durable root and socket address, retaining only its stable carrier ID.
        drop(b);
        drop(b_raw);
        drop(b_provider);
        let (restarted_b_identity, mut b) = open_native_test_supervisor(&b_config, None);
        assert_eq!(restarted_b_identity, b_identity);
        assert_eq!(
            load_or_create_carrier_id(&b_config.root).unwrap(),
            b_carrier_id
        );
        let b_restarted = NativeCarrierHello {
            carrier_id: b_carrier_id,
            instance_nonce: [0xb2; CARRIER_INSTANCE_NONCE_BYTES],
        };
        let (mut b_provider, b_raw) = initialize_native_provider(&b, || {
            IpLink::bind("native-restart-b", b_address, [0x51; 16], None)
        })
        .unwrap();
        let b_raw = Arc::new(b_raw);
        assert_eq!(b_raw.local_addr().unwrap(), b_address);
        let b_candidate = CandidateId::new(format!("manual:{}", hex(&a_identity))).unwrap();
        let b_locator = CandidateLocator::new(a_address.to_string()).unwrap();
        observe_native_endpoint(
            &b_raw,
            &mut b,
            &mut b_provider,
            b_candidate,
            b_locator,
            a_address,
            CandidateProvenance::Manual,
            Some(a_identity),
            Instant::now(),
        )
        .unwrap();
        let b_route = b_provider.route_to_locator.keys().copied().next().unwrap();
        let b_frames = Arc::new(Mutex::new(NativeAsterSendCounters::default()));
        let b_events = root.join("restart-b-second-events.jsonl");
        let restarted_at = Instant::now();
        let restart_deadline = restarted_at.checked_add(Duration::from_secs(5)).unwrap();
        let mut b_receipt = native_test_receipt(b_identity, b_carrier_id, &b);

        handle_native_hello(
            a_route,
            b_restarted,
            &mut a,
            &a_raw,
            &mut a_provider,
            &a_frames,
            &mut a_receipt,
            &a_events,
            a_carrier,
            restarted_at,
        )
        .unwrap();
        handle_native_hello(
            b_route,
            a_carrier,
            &mut b,
            &b_raw,
            &mut b_provider,
            &b_frames,
            &mut b_receipt,
            &b_events,
            b_first,
            restarted_at,
        )
        .unwrap();

        assert!(!a_provider.contacts.contains_key(&ContactId(1)));
        assert_eq!(
            a_provider.contacts[&ContactId(2)].remote_instance,
            b_restarted
        );
        assert_eq!(a.contact_status().len(), 1);
        assert_eq!(a.host_snapshot().active_contacts, 1);
        assert_eq!(a.host_snapshot().carrier_binding_count, 1);
        assert_eq!(
            a.resource_snapshot()
                .unwrap()
                .current
                .pre_authentication_contacts,
            1
        );

        // Reproduce the formal trial-4 ordering: A has bound B's replacement
        // epoch, while B's new RuntimeSession is accidentally exposed through
        // its predecessor local epoch. Discard the two carrier-hello replies
        // so the deliberately split pair remains stable while the opaque
        // Aster handshakes are attempted over real UDP.
        while a_raw.try_receive().unwrap().is_some() {}
        while b_raw.try_receive().unwrap().is_some() {}
        let split_frames_before = a_frames.lock().unwrap().frames + b_frames.lock().unwrap().frames;
        let split_received_before =
            a_receipt.aster_frames_received + b_receipt.aster_frames_received;
        let split_bytes_before = a_receipt.aster_bytes_received + b_receipt.aster_bytes_received;
        for _ in 0..128 {
            pump_native_test_process(
                &mut a,
                &a_raw,
                &mut a_provider,
                &a_frames,
                &mut a_receipt,
                &a_config,
                &a_events,
                restarted_at,
                a_carrier,
                restart_deadline,
            );
            pump_native_test_process(
                &mut b,
                &b_raw,
                &mut b_provider,
                &b_frames,
                &mut b_receipt,
                &b_config,
                &b_events,
                restarted_at,
                b_first,
                restart_deadline,
            );
        }
        let split_frames_after = a_frames.lock().unwrap().frames + b_frames.lock().unwrap().frames;
        assert!(split_frames_after > split_frames_before);
        assert_eq!(
            a_receipt.aster_frames_received + b_receipt.aster_frames_received,
            split_received_before
        );
        assert_eq!(
            a_receipt.aster_bytes_received + b_receipt.aster_bytes_received,
            split_bytes_before
        );
        for (supervisor, contact) in [(&a, ContactId(2)), (&b, ContactId(1))] {
            let status = supervisor
                .contact_status()
                .into_iter()
                .find(|status| status.contact == contact)
                .unwrap();
            assert_eq!(status.authenticated_peer, None);
            assert!(!status.admitted);
            assert!(!status.terminal);
            let host = supervisor.host_snapshot();
            assert_eq!(host.authenticated_contacts, 0);
            assert_eq!(host.pending_admissions, 0);
            let resources = supervisor.resource_snapshot().unwrap().current;
            assert_eq!(resources.pre_authentication_contacts, 1);
            assert_eq!(resources.admitted_contacts, 0);
        }
        assert_eq!(a_receipt.contact_failures, 0);
        assert_eq!(b_receipt.contact_failures, 0);

        // Retire the split B contact and expose the same carrier epoch A
        // already observed. Fresh Aster authentication may now proceed; no
        // predecessor DATA packet is eligible for the successor session.
        close_native_contact_with_label(
            &mut b,
            &mut b_provider,
            ContactId(1),
            false,
            "split-carrier-epoch",
            &b_events,
        )
        .unwrap();
        handle_native_hello(
            b_route,
            a_carrier,
            &mut b,
            &b_raw,
            &mut b_provider,
            &b_frames,
            &mut b_receipt,
            &b_events,
            b_restarted,
            Instant::now(),
        )
        .unwrap();
        assert_eq!(b_provider.contacts.len(), 1);
        assert_eq!(
            b_provider.contacts[&ContactId(2)].remote_instance,
            a_carrier
        );

        while Instant::now() < restart_deadline
            && !(contact_is_admitted(&a, ContactId(2)) && contact_is_admitted(&b, ContactId(2)))
        {
            pump_native_test_process(
                &mut a,
                &a_raw,
                &mut a_provider,
                &a_frames,
                &mut a_receipt,
                &a_config,
                &a_events,
                restarted_at,
                a_carrier,
                restart_deadline,
            );
            pump_native_test_process(
                &mut b,
                &b_raw,
                &mut b_provider,
                &b_frames,
                &mut b_receipt,
                &b_config,
                &b_events,
                restarted_at,
                b_restarted,
                restart_deadline,
            );
            std::thread::yield_now();
        }
        assert!(contact_is_admitted(&a, ContactId(2)));
        assert!(contact_is_admitted(&b, ContactId(2)));
        assert_eq!(a.host_snapshot().carrier_binding_count, 1);
        assert_eq!(a.resource_snapshot().unwrap().current.admitted_contacts, 1);
        assert_eq!(a_receipt.contact_failures, 0);
        assert_eq!(b_receipt.contact_failures, 0);

        // A reordered datagram from B's dead process is ignored instead of
        // replacing the freshly authenticated session a second time.
        handle_native_hello(
            a_route,
            b_first,
            &mut a,
            &a_raw,
            &mut a_provider,
            &a_frames,
            &mut a_receipt,
            &a_events,
            a_carrier,
            Instant::now(),
        )
        .unwrap();
        assert_eq!(a_provider.contacts.len(), 1);
        assert_eq!(
            a_provider.contacts[&ContactId(2)].remote_instance,
            b_restarted
        );
        assert!(contact_is_admitted(&a, ContactId(2)));
        assert_eq!(a.host_snapshot().carrier_binding_count, 1);
        assert_eq!(
            a_provider.endpoints[&a_locator].retired_instances,
            VecDeque::from([b_first])
        );

        drop(a);
        drop(b);
        drop(a_raw);
        drop(b_raw);
        drop(a_provider);
        drop(b_provider);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn linear_payload_extension_matches_the_original_byte_stream() {
        let mut original = b"stable mesh payload prefix".to_vec();
        while original.len() < 4_096 {
            let digest = Sha256::digest(&original);
            let remaining = 4_096 - original.len();
            original.extend_from_slice(&digest[..remaining.min(digest.len())]);
        }
        let mut linear = b"stable mesh payload prefix".to_vec();
        extend_mesh_payload(&mut linear, 4_096);
        assert_eq!(linear, original);
    }

    #[test]
    fn native_manual_peers_require_exact_identity_bound_endpoints() {
        let peer = [0x42; 32];
        let entry = format!("{}@127.0.0.1:47101", hex(&peer));
        let peers = parse_native_manual_peers(&format!("{entry},{entry}")).unwrap();
        assert_eq!(
            peers,
            vec![NativeManualPeer {
                peer,
                address: "127.0.0.1:47101".parse().unwrap(),
            }]
        );
        assert!(parse_native_manual_peers("127.0.0.1:47101").is_err());
        assert!(parse_native_manual_peers(&format!("{}@0.0.0.0:47101", hex(&peer))).is_err());
        assert!(parse_native_manual_peers(&format!("{}@127.0.0.1:0", hex(&peer))).is_err());
        assert!(
            parse_native_manual_peers(&format!("{}@127.0.0.1:47101", "00".repeat(32))).is_err()
        );
    }

    #[test]
    fn native_emission_modes_keep_discovery_and_dial_policy_fail_closed() {
        assert!(native_emission_policy("normal").unwrap().allows_discovery());
        let constrained = native_emission_policy("constrained").unwrap();
        assert!(!constrained.allows_discovery());
        assert_eq!(constrained.minimum_priority, Some(Priority::Immediate));
        assert_eq!(
            native_emission_policy("receive-only").unwrap(),
            EmissionPolicy::receive_only()
        );
        let flash_only = native_emission_policy("flash-only").unwrap();
        assert_eq!(flash_only.minimum_priority, Some(Priority::Flash));
        assert!(!flash_only.allows_discovery());
        assert!(native_emission_policy("passive").is_err());

        let now = Instant::now();
        let candidate = CandidateId::new(format!("manual:{}", hex(&[7; 32]))).unwrap();
        let locator = CandidateLocator::new("127.0.0.1:47101").unwrap();
        let mut host = MeshHost::new(
            HostConfig {
                max_candidates: 2,
                max_active_contacts: 1,
                candidate_ttl: NATIVE_CANDIDATE_TTL,
                contact_quantum: NATIVE_CONTACT_QUANTUM,
                reconnect_initial: Duration::from_millis(250),
                reconnect_max: Duration::from_secs(30),
            },
            EmissionPolicy::receive_only(),
        )
        .unwrap();
        host.handle_event(
            HostEvent::CandidateObserved {
                candidate: candidate.clone(),
                locator: locator.clone(),
                provenance: CandidateProvenance::Manual,
                path: ContactPath::Direct,
                expected_peer: Some([7; 32]),
            },
            now,
        )
        .unwrap();
        assert_eq!(
            host.plan(now),
            vec![HostAction::SetDiscovery { enabled: false }]
        );
        assert!(
            host.handle_event(
                HostEvent::ContactOpened {
                    contact: ContactId(1),
                    candidate,
                    locator,
                    carrier_identity: Some(CarrierIdentity::new(vec![8; 32]).unwrap()),
                    direction: ContactDirection::Inbound,
                    path: ContactPath::Direct,
                },
                now,
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(host.snapshot().active_inbound_contacts, 1);
        assert_eq!(
            host.plan(now.checked_add(NATIVE_CONTACT_QUANTUM).unwrap()),
            vec![HostAction::Close {
                contact: ContactId(1),
                reason: ContactCloseReason::FairnessQuantum,
            }]
        );
    }

    #[test]
    fn native_gate_h_flash_only_mode_is_pair_bound() {
        let target = [0x31; 32];
        let mut config = NativeMeshNodeConfig {
            invocation: "gate-h-policy".to_owned(),
            root: PathBuf::from("/tmp/gate-h-policy"),
            credential_path: PathBuf::from("/tmp/gate-h-policy.bundle"),
            topic: Topic::new("gate.h.policy").unwrap(),
            scope: Scope::new("mission/gate-h-policy").unwrap(),
            discovery_token: [0x41; 16],
            bind: "127.0.0.1:47101".parse().unwrap(),
            discovery_target: "127.0.0.1:47101".parse().unwrap(),
            max_candidates: 8,
            max_active_contacts: 2,
            run_for: Duration::from_secs(1),
            discovery_enabled: false,
            expected_peers: BTreeSet::from([[0x21; 32], target]),
            manual_peers: String::new(),
            emission_mode: "flash-only".to_owned(),
            gate_h_control_path: None,
            gate_h_stale_target_peer: None,
            durable_item_probe: None,
        };
        assert!(config.validate().is_err());
        config.gate_h_control_path = Some(config.root.join("gate-h-authorization-control.bin"));
        config.gate_h_stale_target_peer = Some(target);
        assert!(config.validate().is_ok());
        config.emission_mode = "receive-only".to_owned();
        assert!(config.validate().is_err());
        config.emission_mode = "flash-only".to_owned();
        config.gate_h_stale_target_peer = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn native_command_payload_limit_remains_one_mib_without_allocating_it() {
        assert_eq!(MAX_COMMAND_BYTES, 1_024 * 1_024);
        assert!(GATE_H_MULTI_FRAME_TEST_PAYLOAD_BYTES > usize::from(NATIVE_TEST_MTU_BYTES));
    }

    #[test]
    fn native_gate_h_signed_control_queued_generation_invalidation_and_recovery() {
        let root = native_test_root("shared-authority");
        let prepared = prepare_ip_mesh(&MeshPrepareConfig {
            root: root.clone(),
            seed: 0x5a17,
            payload_bytes: GATE_H_MULTI_FRAME_TEST_PAYLOAD_BYTES,
        })
        .unwrap();
        let a_config =
            native_test_config(&root, "a", &prepared, BTreeSet::from([prepared.relay]), 1);
        let mut b_config = native_test_config(
            &root,
            "b",
            &prepared,
            BTreeSet::from([prepared.publisher, prepared.consumer]),
            2,
        );
        // Match the live Gate-H pre-restart process: B may receive Routine and
        // Immediate custody, but serves only the signed Flash control while A,
        // B, and C are concurrently live.
        b_config.emission_mode = "flash-only".to_owned();
        let c_config =
            native_test_config(&root, "c", &prepared, BTreeSet::from([prepared.relay]), 1);
        let (a_identity, mut a) = open_native_test_supervisor(&a_config, None);
        let (b_identity, mut b) = open_native_test_supervisor(&b_config, None);
        let (c_identity, mut c) = open_native_test_supervisor(&c_config, None);
        assert_eq!(a_identity, prepared.publisher);
        assert_eq!(b_identity, prepared.relay);
        assert_eq!(c_identity, prepared.consumer);

        // Establish and settle B<->C before A can publish into B. This leaves
        // the delivery contact live but idle when B commits A's multi-frame object.
        let (b_to_c, c_from_b, b_c_sends, _) = NativeTestLink::pair();
        open_native_test_contact(
            &mut b,
            ContactId(1),
            1,
            c_identity,
            ContactSessionRole::Initiator { peer_hint: None },
            b_to_c,
        );
        open_native_test_contact(
            &mut c,
            ContactId(1),
            2,
            b_identity,
            ContactSessionRole::Responder { peer_hint: None },
            c_from_b,
        );
        for _ in 0..128 {
            let now = Instant::now();
            if !contact_is_admitted(&b, ContactId(1)) {
                b.drive_contact(ContactId(1), now).unwrap();
            }
            if !contact_is_admitted(&c, ContactId(1)) {
                c.drive_contact(ContactId(1), now).unwrap();
            }
            if contact_is_admitted(&b, ContactId(1)) && contact_is_admitted(&c, ContactId(1)) {
                break;
            }
        }
        assert!(contact_is_admitted(&b, ContactId(1)));
        assert!(contact_is_admitted(&c, ContactId(1)));
        for _ in 0..512 {
            let now = Instant::now();
            b.drive_contact(ContactId(1), now).unwrap();
            c.drive_contact(ContactId(1), now).unwrap();
            if pending_outbound_frames(&b, ContactId(1)) == 0
                && pending_outbound_frames(&c, ContactId(1)) == 0
            {
                break;
            }
        }
        assert_eq!(pending_outbound_frames(&b, ContactId(1)), 0);

        let (a_to_b, b_from_a, _, b_a_sends) = NativeTestLink::pair();
        open_native_test_contact(
            &mut a,
            ContactId(1),
            3,
            b_identity,
            ContactSessionRole::Initiator { peer_hint: None },
            a_to_b,
        );
        open_native_test_contact(
            &mut b,
            ContactId(2),
            4,
            a_identity,
            ContactSessionRole::Responder { peer_hint: None },
            b_from_a,
        );
        for _ in 0..128 {
            let now = Instant::now();
            if !contact_is_admitted(&a, ContactId(1)) {
                a.drive_contact(ContactId(1), now).unwrap();
            }
            if !contact_is_admitted(&b, ContactId(2)) {
                b.drive_contact(ContactId(2), now).unwrap();
            }
            if contact_is_admitted(&a, ContactId(1)) && contact_is_admitted(&b, ContactId(2)) {
                break;
            }
        }
        assert!(contact_is_admitted(&a, ContactId(1)));
        assert!(contact_is_admitted(&b, ContactId(2)));
        assert_eq!(
            b.contact_status()
                .iter()
                .filter(|status| status.admitted)
                .count(),
            2
        );
        assert_eq!(b.resource_snapshot().unwrap().current.admitted_contacts, 2);

        // Pump only A<->B until B's durable commit causes the common
        // supervisor to queue a B->C inventory frame. Do not pump B->C after
        // that point: the queued bytes are the stale-generation race target.
        let b_c_sends_before_publish = b_c_sends.load(Ordering::Relaxed);
        let mut queued_stale_frames = 0_usize;
        for _ in 0..8_192 {
            let now = Instant::now();
            a.drive_contact(ContactId(1), now).unwrap();
            let report = b.drive_contact(ContactId(2), now).unwrap();
            if report.inventory_contacts_notified > 0 {
                queued_stale_frames = pending_outbound_frames(&b, ContactId(1));
                if queued_stale_frames > 0 {
                    break;
                }
            }
        }
        assert!(queued_stale_frames > 0);
        assert_eq!(b_c_sends.load(Ordering::Relaxed), b_c_sends_before_publish);
        let b_resources = b.resource_snapshot().unwrap();
        assert_eq!(b_resources.limits.inbound_bytes, 8 * 1_024 * 1_024);
        assert_eq!(b_resources.limits.outbound_bytes, 8 * 1_024 * 1_024);
        assert_eq!(b_resources.high_water.admitted_contacts, 2);

        b.take_evidence();
        let signed_control = SignedAuthorizationControl::from_sealed(
            fs::read(root.join("b/gate-h-authorization-control.bin")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            signed_control.envelope_id(),
            prepared.authorization_control_id
        );
        let mutation = b.apply_authorization_control(&signed_control).unwrap();
        assert_eq!(
            mutation.control.envelope_id,
            prepared.authorization_control_id
        );
        assert_eq!(mutation.control.generation_before, 0);
        assert_eq!(mutation.control.generation_after, 1);
        assert_eq!(
            mutation.contacts_requiring_reauthentication,
            vec![ContactId(1), ContactId(2)]
        );
        let stale_sends_before = b_c_sends.load(Ordering::Relaxed);
        let counters_before = b.evidence_counters();
        assert!(matches!(
            b.drive_contact(ContactId(1), Instant::now()),
            Err(ContactSupervisorError::AuthorizationChanged(ContactId(1)))
        ));
        assert_eq!(b_c_sends.load(Ordering::Relaxed), stale_sends_before);
        assert_eq!(
            b.take_evidence(),
            vec![SharedNodeEvidenceTransition::GenerationChecked {
                contact: ContactId(1),
                peer: c_identity,
                check: RuntimeAuthorizationGenerationCheck::Changed {
                    expected_generation: 0,
                    observed_generation: 1,
                },
            }]
        );
        let counters_after = b.evidence_counters();
        assert_eq!(
            counters_after.authorization_generation_checks,
            counters_before.authorization_generation_checks + 1
        );
        assert_eq!(
            counters_after.authorization_generation_mismatches,
            counters_before.authorization_generation_mismatches + 1
        );
        assert_eq!(counters_after.authorization_generation_unavailable, 0);

        // Retire the other invalidated contact without pumping it, so this
        // witness contains exactly one pre-flush mismatch. Both remote halves
        // are closed before the fresh post-generation B<->C authentication.
        b.close_contact(ContactId(2), true, Instant::now()).unwrap();
        a.close_contact(ContactId(1), true, Instant::now()).unwrap();
        c.close_contact(ContactId(1), true, Instant::now()).unwrap();
        assert!(b.contact_status().is_empty());
        assert_eq!(b.resource_snapshot().unwrap().current.admitted_contacts, 0);
        let b_host = b.host_snapshot();
        assert_eq!(b_host.active_contacts, 0);
        assert_eq!(b_host.authenticated_contacts, 0);
        assert_eq!(b_host.pending_admissions, 0);
        assert_eq!(b_host.carrier_binding_count, 2);
        let b_a_sends_after_retirement = b_a_sends.load(Ordering::Relaxed);

        // Match the real Gate-H process boundary: B-pre was Flash-only, while
        // B-post reopens the same durable store with normal emission. The
        // applied control and source remain durable, but the new process-local
        // authorization generation starts at zero.
        drop(b);
        b_config.emission_mode = "normal".to_owned();
        let (restarted_b_identity, restarted_b) = open_native_test_supervisor(&b_config, None);
        assert_eq!(restarted_b_identity, b_identity);
        let mut b = restarted_b;
        assert_eq!(b.authorization_generation().unwrap(), 0);

        // A fresh post-restart session can send the exact durable control and
        // object to C without weakening B-pre's Flash-only policy.
        let (b_fresh, c_fresh, b_fresh_sends, _) = NativeTestLink::pair();
        open_native_test_contact(
            &mut b,
            ContactId(3),
            5,
            c_identity,
            ContactSessionRole::Initiator { peer_hint: None },
            b_fresh,
        );
        open_native_test_contact(
            &mut c,
            ContactId(2),
            6,
            b_identity,
            ContactSessionRole::Responder { peer_hint: None },
            c_fresh,
        );
        for _ in 0..128 {
            let now = Instant::now();
            if !contact_is_admitted(&b, ContactId(3)) {
                b.drive_contact(ContactId(3), now).unwrap();
            }
            if !contact_is_admitted(&c, ContactId(2)) {
                c.drive_contact(ContactId(2), now).unwrap();
            }
            if contact_is_admitted(&b, ContactId(3)) && contact_is_admitted(&c, ContactId(2)) {
                break;
            }
        }
        assert!(contact_is_admitted(&b, ContactId(3)));
        assert!(contact_is_admitted(&c, ContactId(2)));
        assert!(b.take_evidence().iter().any(|event| {
            matches!(
                event,
                SharedNodeEvidenceTransition::GenerationChecked {
                    contact: ContactId(3),
                    peer,
                    check: RuntimeAuthorizationGenerationCheck::Current { generation: 0 },
                } if *peer == c_identity
            )
        }));
        let mut c_applied_control = false;
        for _ in 0..8_192 {
            let now = Instant::now();
            b.drive_contact(ContactId(3), now).unwrap();
            match c.drive_contact(ContactId(2), now) {
                Ok(_) => {}
                Err(ContactSupervisorError::AuthorizationChanged(ContactId(2))) => {
                    c_applied_control = true;
                    break;
                }
                Err(error) => panic!("unexpected propagated-control failure: {error}"),
            }
        }
        assert!(b_fresh_sends.load(Ordering::Relaxed) > 0);
        assert!(c_applied_control);
        assert_eq!(c.authorization_generation().unwrap(), 1);
        b.close_contact(ContactId(3), true, Instant::now()).unwrap();

        // C's first fresh session correctly invalidates when it durably
        // applies B's newly advertised control. A second fresh pair captures
        // B-post generation 0 and C generation 1; the duplicate control is not
        // an authorization change and cannot cause an epoch-rotation loop.
        let (b_final, c_final, b_final_sends, _) = NativeTestLink::pair();
        open_native_test_contact(
            &mut b,
            ContactId(4),
            7,
            c_identity,
            ContactSessionRole::Initiator { peer_hint: None },
            b_final,
        );
        open_native_test_contact(
            &mut c,
            ContactId(3),
            8,
            b_identity,
            ContactSessionRole::Responder { peer_hint: None },
            c_final,
        );
        for _ in 0..128 {
            let now = Instant::now();
            if !contact_is_admitted(&b, ContactId(4)) {
                b.drive_contact(ContactId(4), now).unwrap();
            }
            if !contact_is_admitted(&c, ContactId(3)) {
                c.drive_contact(ContactId(3), now).unwrap();
            }
            if contact_is_admitted(&b, ContactId(4)) && contact_is_admitted(&c, ContactId(3)) {
                break;
            }
        }
        assert!(contact_is_admitted(&b, ContactId(4)));
        assert!(contact_is_admitted(&c, ContactId(3)));
        assert!(b.take_evidence().iter().any(|event| matches!(
            event,
            SharedNodeEvidenceTransition::GenerationChecked {
                contact: ContactId(4),
                check: RuntimeAuthorizationGenerationCheck::Current { generation: 0 },
                ..
            }
        )));
        assert!(c.take_evidence().iter().any(|event| matches!(
            event,
            SharedNodeEvidenceTransition::GenerationChecked {
                contact: ContactId(3),
                check: RuntimeAuthorizationGenerationCheck::Current { generation: 1 },
                ..
            }
        )));
        for _ in 0..8_192 {
            let now = Instant::now();
            b.drive_contact(ContactId(4), now).unwrap();
            c.drive_contact(ContactId(3), now).unwrap();
        }
        assert!(b_final_sends.load(Ordering::Relaxed) > 0);
        assert_eq!(c.authorization_generation().unwrap(), 1);
        assert_eq!(
            b_a_sends.load(Ordering::Relaxed),
            b_a_sends_after_retirement
        );

        drop(a);
        drop(b);
        drop(c);
        let custody = verify_ip_mesh_relay_custody(&root, "shared-authority").unwrap();
        assert!(custody.exact_envelope);
        let delivery = consume_and_ack_ip_mesh(&root, "shared-authority").unwrap();
        assert!(delivery.same_item);
        assert!(delivery.same_envelope);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_aggregate_contact_budget_rejects_then_releases() {
        let root = native_test_root("aggregate-budget");
        let prepared = prepare_ip_mesh(&MeshPrepareConfig {
            root: root.clone(),
            seed: 0x7712,
            payload_bytes: 64,
        })
        .unwrap();
        let config = native_test_config(&root, "a", &prepared, BTreeSet::new(), 3);
        let claims = native_contact_resource_claims(native_runtime_limits()).unwrap();
        let mut limits = native_node_resource_limits(&config).unwrap();
        limits.pre_authentication_contacts = 2;
        limits.admitted_contacts = 2;
        limits.streams = 2;
        limits.tasks = 2;
        limits.frames = claims.pre_authentication().frames * 2;
        limits.inbound_bytes = claims.pre_authentication().inbound_bytes * 2;
        limits.outbound_bytes = claims.pre_authentication().outbound_bytes * 2;
        limits.descriptors = 2;
        let (_, mut supervisor) = open_native_test_supervisor(&config, Some(limits));
        let peers = [[0x31; 32], [0x32; 32], [0x33; 32]];
        let (first, _, _, _) = NativeTestLink::pair();
        let (second, _, _, _) = NativeTestLink::pair();
        let (third, _, _, _) = NativeTestLink::pair();
        open_native_test_contact(
            &mut supervisor,
            ContactId(1),
            11,
            peers[0],
            ContactSessionRole::Responder { peer_hint: None },
            first,
        );
        open_native_test_contact(
            &mut supervisor,
            ContactId(2),
            12,
            peers[1],
            ContactSessionRole::Responder { peer_hint: None },
            second,
        );
        let candidate = CandidateId::new("gate-h-0013").unwrap();
        let locator = CandidateLocator::new("127.0.0.1:40013").unwrap();
        supervisor
            .observe_candidate(
                candidate.clone(),
                locator.clone(),
                CandidateProvenance::Manual,
                ContactPath::Direct,
                Some(peers[2]),
                Instant::now(),
            )
            .unwrap();
        let third_opening = ContactOpening {
            contact: ContactId(3),
            candidate,
            locator,
            carrier_identity: None,
            direction: ContactDirection::Inbound,
            path: ContactPath::Direct,
            role: ContactSessionRole::Responder { peer_hint: None },
        };
        assert!(matches!(
            supervisor.open_contact_with_factory(
                third_opening.clone(),
                Instant::now(),
                || third.clone(),
            ),
            Err(ContactSupervisorError::Resource(
                ResourceBudgetError::Capacity("pre-authentication contacts")
            ))
        ));
        assert_eq!(
            supervisor
                .resource_snapshot()
                .unwrap()
                .current
                .pre_authentication_contacts,
            2
        );
        supervisor
            .close_contact(ContactId(1), false, Instant::now())
            .unwrap();
        assert!(
            supervisor
                .open_contact_with_factory(third_opening, Instant::now(), || third)
                .unwrap()
                .opened
        );
        supervisor
            .close_contact(ContactId(2), false, Instant::now())
            .unwrap();
        supervisor
            .close_contact(ContactId(3), false, Instant::now())
            .unwrap();
        let snapshot = supervisor.resource_snapshot().unwrap();
        assert_eq!(snapshot.current.pre_authentication_contacts, 0);
        assert_eq!(snapshot.high_water.pre_authentication_contacts, 2);
        assert_eq!(snapshot.rejections.pre_authentication_contacts, 1);
        assert_eq!(snapshot.rejected_claims, 1);
        drop(supervisor);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_provider_base_reservation_precedes_bind_and_lives_with_provider() {
        let root = native_test_root("provider-base-ordering");
        let prepared = prepare_ip_mesh(&MeshPrepareConfig {
            root: root.clone(),
            seed: 0x7714,
            payload_bytes: 64,
        })
        .unwrap();
        let config = native_test_config(&root, "a", &prepared, BTreeSet::new(), 1);

        let mut limits = native_node_resource_limits(&config).unwrap();
        limits.descriptors = 0;
        let (_, supervisor) = open_native_test_supervisor(&config, Some(limits));
        let bind_probed = AtomicBool::new(false);
        let error = match initialize_native_provider(&supervisor, || {
            bind_probed.store(true, Ordering::Relaxed);
            Ok(())
        }) {
            Ok(_) => panic!("descriptor-less provider initialization unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(!bind_probed.load(Ordering::Relaxed));
        assert!(matches!(
            error.downcast_ref::<ContactSupervisorError>(),
            Some(ContactSupervisorError::Resource(
                ResourceBudgetError::Capacity("descriptors")
            ))
        ));
        let snapshot = supervisor.resource_snapshot().unwrap();
        assert_eq!(snapshot.current, NodeResourceClaim::default());
        assert_eq!(snapshot.high_water, NodeResourceClaim::default());
        assert_eq!(snapshot.rejections.descriptors, 1);
        drop(supervisor);

        let mut limits = native_node_resource_limits(&config).unwrap();
        limits.inbound_bytes = NATIVE_PROVIDER_RECEIVE_SCRATCH_BYTES - 1;
        let (_, supervisor) = open_native_test_supervisor(&config, Some(limits));
        let bind_probed = AtomicBool::new(false);
        let error = match initialize_native_provider(&supervisor, || {
            bind_probed.store(true, Ordering::Relaxed);
            Ok(())
        }) {
            Ok(_) => panic!("under-reserved provider initialization unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(!bind_probed.load(Ordering::Relaxed));
        assert!(matches!(
            error.downcast_ref::<ContactSupervisorError>(),
            Some(ContactSupervisorError::Resource(
                ResourceBudgetError::Capacity("inbound bytes")
            ))
        ));
        let snapshot = supervisor.resource_snapshot().unwrap();
        assert_eq!(snapshot.current, NodeResourceClaim::default());
        assert_eq!(snapshot.high_water, NodeResourceClaim::default());
        assert_eq!(snapshot.rejections.inbound_bytes, 1);
        drop(supervisor);

        let (_, supervisor) = open_native_test_supervisor(&config, None);
        let bind_probed = AtomicBool::new(false);
        let (provider, ()) = initialize_native_provider(&supervisor, || {
            bind_probed.store(true, Ordering::Relaxed);
            Ok(())
        })
        .unwrap();
        assert!(bind_probed.load(Ordering::Relaxed));
        assert_eq!(
            provider.base_resources.claim(),
            native_provider_resource_claim()
        );
        let snapshot = supervisor.resource_snapshot().unwrap();
        assert_eq!(snapshot.current, native_provider_resource_claim());
        assert_eq!(snapshot.high_water, native_provider_resource_claim());
        drop(provider);
        assert_eq!(
            supervisor.resource_snapshot().unwrap().current,
            NodeResourceClaim::default()
        );

        drop(supervisor);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_carrier_cleanup_tolerates_common_terminal_retirement() {
        let root = native_test_root("terminal-retirement");
        let prepared = prepare_ip_mesh(&MeshPrepareConfig {
            root: root.clone(),
            seed: 0x7713,
            payload_bytes: 64,
        })
        .unwrap();
        let config = native_test_config(&root, "a", &prepared, BTreeSet::new(), 1);
        let (_, mut supervisor) = open_native_test_supervisor(&config, None);
        let peer = [0x34; 32];
        let (link, _, _, _) = NativeTestLink::pair();
        open_native_test_contact(
            &mut supervisor,
            ContactId(1),
            14,
            peer,
            ContactSessionRole::Responder {
                peer_hint: Some(peer),
            },
            link,
        );
        let route = [0x44; 32];
        let mut provider = native_test_provider(&supervisor);
        provider.route_contacts.insert(route, ContactId(1));
        provider.contacts.insert(
            ContactId(1),
            NativeContact {
                contact: ContactId(1),
                address: "127.0.0.1:40014".parse().unwrap(),
                route,
                inbound: Arc::new(Mutex::new(ContactQueue::default())),
                admitted_peer: None,
                remote_instance: NativeCarrierHello {
                    carrier_id: [0x71; CARRIER_ID_BYTES],
                    instance_nonce: [0x72; CARRIER_INSTANCE_NONCE_BYTES],
                },
                sent: Arc::new(Mutex::new(NativeAsterSendCounters::default())),
            },
        );

        let expired = Instant::now()
            .checked_add(NATIVE_PRE_AUTHENTICATION_TIMEOUT)
            .and_then(|deadline| deadline.checked_add(Duration::from_millis(1)))
            .unwrap();
        assert!(matches!(
            supervisor.drive_contact(ContactId(1), expired),
            Err(ContactSupervisorError::PreAuthenticationExpired(ContactId(
                1
            )))
        ));
        assert!(supervisor.contact_status().is_empty());
        assert_eq!(
            supervisor
                .resource_snapshot()
                .unwrap()
                .current
                .pre_authentication_contacts,
            0
        );
        close_native_contact(
            &mut supervisor,
            &mut provider,
            ContactId(1),
            true,
            None,
            &root.join("terminal-retirement-events.jsonl"),
        )
        .unwrap();
        assert!(provider.contacts.is_empty());
        assert!(provider.route_contacts.is_empty());

        drop(supervisor);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_host_owns_refresh_backoff_expiry_and_provider_pruning() {
        let root = native_test_root("candidate-lifecycle");
        let prepared = prepare_ip_mesh(&MeshPrepareConfig {
            root: root.clone(),
            seed: 0x9914,
            payload_bytes: 64,
        })
        .unwrap();
        let normal = native_test_config(&root, "a", &prepared, BTreeSet::new(), 1);
        let (_, mut backoff) = open_native_test_supervisor(&normal, None);
        let now = Instant::now();
        let candidate = CandidateId::new("refresh-backoff").unwrap();
        let locator = CandidateLocator::new("127.0.0.1:48001").unwrap();
        backoff
            .observe_candidate(
                candidate.clone(),
                locator.clone(),
                CandidateProvenance::Automatic,
                ContactPath::Direct,
                None,
                now,
            )
            .unwrap();
        assert!(backoff.plan(now).unwrap().actions.iter().any(|action| {
            matches!(action, HostAction::Dial { candidate: planned, locator: target }
                if planned == &candidate && target == &locator)
        }));
        backoff
            .dial_failed(candidate.clone(), locator.clone(), now)
            .unwrap();
        let before_refresh = backoff.next_wakeup(now).unwrap();
        let refreshed = now.checked_add(Duration::from_millis(10)).unwrap();
        backoff
            .refresh_candidate(candidate, locator, refreshed)
            .unwrap();
        assert_eq!(backoff.next_wakeup(refreshed), Some(before_refresh));

        let expiry_config = native_test_config(&root, "c", &prepared, BTreeSet::new(), 1);
        let (_, mut expiry) = open_native_test_supervisor(&expiry_config, None);
        let mut provider = native_test_provider(&expiry);
        let candidate = CandidateId::new("expiry-owner").unwrap();
        let locator = CandidateLocator::new("127.0.0.1:48002").unwrap();
        let address = "127.0.0.1:48002".parse().unwrap();
        let route = [0x48; 32];
        let observed = Instant::now();
        expiry
            .observe_candidate(
                candidate.clone(),
                locator.clone(),
                CandidateProvenance::Automatic,
                ContactPath::Direct,
                None,
                observed,
            )
            .unwrap();
        provider.route_to_locator.insert(route, locator.clone());
        provider.endpoints.insert(
            locator.clone(),
            NativeEndpoint {
                candidate: candidate.clone(),
                provenance: CandidateProvenance::Automatic,
                address,
                route,
                last_hello_sent: None,
                retired_instances: VecDeque::new(),
            },
        );
        let refreshed = observed.checked_add(Duration::from_secs(1)).unwrap();
        expiry
            .refresh_candidate(candidate.clone(), locator.clone(), refreshed)
            .unwrap();
        let before_expiry = observed.checked_add(NATIVE_CANDIDATE_TTL).unwrap();
        let before_expiry_actions = expiry.plan(before_expiry).unwrap().actions;
        assert!(
            !before_expiry_actions
                .iter()
                .any(|action| matches!(action, HostAction::ForgetCandidateLocator { .. }))
        );
        for action in before_expiry_actions {
            if let HostAction::Dial { candidate, locator } = action {
                expiry
                    .dial_failed(candidate, locator, before_expiry)
                    .unwrap();
            }
        }
        let actions = expiry
            .plan(refreshed.checked_add(NATIVE_CANDIDATE_TTL).unwrap())
            .unwrap()
            .actions;
        let forgets = actions
            .iter()
            .filter_map(|action| match action {
                HostAction::ForgetCandidateLocator { candidate, locator } => {
                    Some((candidate.clone(), locator.clone()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(forgets, vec![(candidate.clone(), locator.clone())]);
        for (candidate, locator) in forgets {
            assert_eq!(
                forget_native_endpoint(&mut provider, &candidate, &locator),
                Some(route)
            );
        }
        assert!(provider.endpoints.is_empty());
        assert!(provider.route_to_locator.is_empty());
        assert_eq!(expiry.resource_snapshot().unwrap().current.candidates, 0);

        drop(backoff);
        drop(expiry);
        fs::remove_dir_all(root).unwrap();
    }
}
