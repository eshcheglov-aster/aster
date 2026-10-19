//! Real selected-stack Blob benchmark; production defaults, synthetic identities.
//! See docs/validation/blob-benchmark.md for timing boundaries and reproduction.
use aster_iroh::{EndpointId, ExpectedPeer};
use aster_mesh::{ProvisioningAccess, ReferenceProvisioner};
use aster_node::{
    BlobDepotLimits, MissionExpectedPeer, MutableSourceInterests, NodeConfig, NodeIdentity,
    SelectedForwardingConfig, SourceInterestSelector,
    application::{
        ApplicationErrorKind, BlobPublishOptions, BlobPublishRequest, BlobPublishStreamRequest,
        BlobReadPageRequest, BlobReadRequest, MAX_SELECTED_BLOB_PAGE_BYTES,
        MAX_SELECTED_LIVE_BLOB_BYTES, Priority, Scope, Topic,
    },
    mission::UnprotectedReferenceMission,
    start_node, start_node_with_forwarding,
};
use aster_redb_store::Store;
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    error::Error,
    fs::{self, File},
    io::{Read, Write},
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::time::{sleep, timeout};
use zeroize::Zeroizing;
type E = Box<dyn Error + Send + Sync>;
struct Participant {
    state: PathBuf,
    mission: UnprotectedReferenceMission,
    carrier: EndpointId,
}
fn participant(root: &Path, name: &str, bytes: Vec<u8>) -> Result<Participant, E> {
    let dir = root.join(name);
    fs::create_dir(&dir)?;
    let state = dir.join("state");
    fs::create_dir(&state)?;
    #[cfg(unix)]
    {
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
    }
    let mission = UnprotectedReferenceMission::persist(dir.join("mission.bundle"), bytes)?;
    let carrier = NodeIdentity::load_or_create(&state)?.id();
    Ok(Participant {
        state,
        mission,
        carrier,
    })
}
fn config(
    p: &Participant,
    bind: SocketAddr,
    peer: Option<(&Participant, SocketAddr)>,
    topic: &Topic,
    scope: &Scope,
) -> NodeConfig {
    let mut c = NodeConfig::new(p.state.clone(), bind, p.mission.clone());
    if let Some((r, address)) = peer {
        c.peers = vec![MissionExpectedPeer {
            carrier: ExpectedPeer {
                id: r.carrier,
                address,
            },
            mission: r.mission.identity(),
        }];
        c.mutable_interests =
            MutableSourceInterests::default().with_blob(vec![SourceInterestSelector::new(
                topic.clone(),
                scope.clone(),
                false,
            )]);
    }
    assert_eq!(c.sync_interval, Duration::from_millis(500));
    c
}
fn receipt(name: &str, r: &aster_node::NodeReceipt) {
    println!(
        "BENCH_RECEIPT {{\"node\":\"{name}\",\"contacts\":{},\"direct_contacts\":{},\"relay_contacts\":{},\"unknown_path_contacts\":{},\"contact_errors\":{},\"blobs\":{},\"pending_blobs\":{},\"blob_ranges_fetched\":{},\"blob_bytes_fetched\":{},\"committed_chunks\":{},\"network_staging_bytes\":{}}}",
        r.contacts,
        r.direct_contacts,
        r.relay_contacts,
        r.unknown_path_contacts,
        r.contact_errors,
        r.blobs,
        r.pending_blobs,
        r.blob_ranges_fetched,
        r.blob_bytes_fetched,
        r.blob_committed_chunks,
        r.blob_network_staging_bytes
    );
}
fn fixture_bytes(offset: u64, len: usize) -> Vec<u8> {
    // SplitMix64's bijective output permutation over a counter, not randomness
    // for credentials. Distinct aligned words/chunks avoid a repetitive Blob
    // workload while keeping the source reproducible and seek-independent.
    (offset..offset + len as u64)
        .map(|position| {
            let mut word = (position / 8).wrapping_add(0x9e3779b97f4a7c15);
            word = (word ^ (word >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            word = (word ^ (word >> 27)).wrapping_mul(0x94d049bb133111eb);
            word ^= word >> 31;
            (word >> ((position % 8) * 8)) as u8
        })
        .collect()
}

fn retryable_probe_error(kind: ApplicationErrorKind) -> bool {
    matches!(
        kind,
        ApplicationErrorKind::NotFound
            | ApplicationErrorKind::RequestRejected
            | ApplicationErrorKind::UnauthorizedOrRevoked
            | ApplicationErrorKind::PolicyUnsettled
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_live_size_chunks_are_distinct_and_generation_is_seek_independent() {
        let words: std::collections::BTreeSet<_> = (0..1024)
            .map(|chunk| fixture_bytes(chunk * 65536, 8))
            .collect();
        assert_eq!(words.len(), 1024);
        assert_eq!(fixture_bytes(3, 29), fixture_bytes(0, 32)[3..]);
    }

    #[test]
    fn source_chunks_do_not_repeat_at_the_old_pattern_period() {
        assert!(
            fixture_bytes(0, 65536) != fixture_bytes(251 * 65536, 65536),
            "large-size fixture must not repeat chunks"
        );
    }

    #[test]
    fn pre_admission_not_found_is_a_retryable_benchmark_probe() {
        assert!(retryable_probe_error(ApplicationErrorKind::NotFound));
        assert!(retryable_probe_error(ApplicationErrorKind::RequestRejected));
        assert!(!retryable_probe_error(ApplicationErrorKind::Integrity));
    }
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), E> {
    let args: Vec<_> = std::env::args().collect();
    let root = PathBuf::from(&args[1]);
    let len: u64 = args[2].parse()?;
    let deadline: u64 = args[3].parse()?;
    let mode = args.get(4).map(String::as_str).unwrap_or("legacy");
    fs::create_dir(&root)?;
    let topic = Topic::new("benchmark.blob")?;
    let scope = Scope::new("test/blob-benchmark")?;
    let access = ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()])?;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)?;
    let mut prov = ReferenceProvisioner::from_seed(seed)?;
    let publisher = participant(
        &root,
        "publisher",
        prov.issue_node(1, std::slice::from_ref(&access))?
            .to_bytes()?,
    )?;
    let receiver = participant(
        &root,
        "receiver",
        prov.issue_node(2, std::slice::from_ref(&access))?
            .to_bytes()?,
    )?;
    let source = root.join("source.bin");
    let mut file = File::create(&source)?;
    let mut hash = Sha256::new();
    let mut offset = 0u64;
    let generation = Instant::now();
    while offset < len {
        let n = (len - offset).min(1024 * 1024) as usize;
        let bytes = fixture_bytes(offset, n);
        file.write_all(&bytes)?;
        hash.update(&bytes);
        offset += n as u64;
    }
    file.sync_all()?;
    drop(file);
    let expected: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "BENCH_SOURCE {{\"bytes\":{len},\"sha256\":\"{expected}\",\"generation_ns\":{},\"max_live_blob_bytes\":{MAX_SELECTED_LIVE_BLOB_BYTES},\"sync_interval_ms\":500,\"tokio_workers\":2}}",
        generation.elapsed().as_nanos()
    );
    let local = SocketAddr::from(([127, 0, 0, 1], 0));
    let peerless_config = config(&publisher, local, None, &topic, &scope);
    let peerless = if mode == "stream-local" {
        let max_bytes = len
            .checked_add(64 * 1024 * 1024)
            .ok_or("stream benchmark depot byte limit overflow")?;
        let max_chunks = len.div_ceil(64 * 1024).max(1);
        let forwarding = SelectedForwardingConfig::default()
            .with_blob_depot_limits(BlobDepotLimits::new(max_bytes, max_chunks, 8)?);
        start_node_with_forwarding(peerless_config, forwarding).await?
    } else {
        start_node(peerless_config).await?
    };
    let total = Instant::now();
    let publication_start = Instant::now();
    if mode == "stream-local" {
        let handle = peerless.selected_blobs();
        let mut stream = handle
            .open_publish_stream(BlobPublishStreamRequest {
                publication: BlobPublishRequest {
                    operation_key: b"benchmark-stream-once".to_vec(),
                    topic: topic.clone(),
                    scope: scope.clone(),
                    priority: Priority::Priority,
                    media_type: Some("application/octet-stream".into()),
                    schema_id: b"benchmark-stream-v1".to_vec(),
                },
                options: BlobPublishOptions::durable(),
                total_len: len,
            })
            .await?;
        let mut input = File::open(&source)?;
        let mut offset = 0_u64;
        while offset < len {
            let segment_len = usize::try_from((len - offset).min(1024 * 1024))?;
            let mut segment = Zeroizing::new(vec![0_u8; segment_len]);
            input.read_exact(&mut segment)?;
            let progress = stream.write(offset, segment).await?;
            offset = progress.accepted_offset;
        }
        let published = stream.finish().await?;
        let publication_ns = publication_start.elapsed().as_nanos();
        assert_eq!(published.total_len, len);
        assert!(published.inserted);
        println!(
            "BENCH_STREAM_PUBLICATION {{\"bytes\":{len},\"publication_ns\":{publication_ns},\"bytes_per_second\":{},\"blob_id\":\"{}\"}}",
            u128::from(len) * 1_000_000_000 / publication_ns.max(1),
            published.id
        );
        let read_start = Instant::now();
        let mut output_hash = Sha256::new();
        let mut read_bytes = 0_u64;
        let mut reader = handle
            .open_read_stream(BlobReadRequest {
                id: published.id,
                topic: topic.clone(),
                scope: scope.clone(),
            })
            .await?;
        while let Some(frame) = reader.next(MAX_SELECTED_BLOB_PAGE_BYTES).await? {
            if frame.offset != read_bytes {
                return Err("stream benchmark read offset mismatch".into());
            }
            output_hash.update(&frame.bytes);
            read_bytes = read_bytes
                .checked_add(frame.bytes.len() as u64)
                .ok_or("stream benchmark read length overflow")?;
        }
        let read_ns = read_start.elapsed().as_nanos();
        let actual: String = output_hash
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(read_bytes, len);
        assert_eq!(actual, expected);
        println!(
            "BENCH_STREAM_READ {{\"bytes\":{len},\"read_ns\":{read_ns},\"bytes_per_second\":{}}}",
            u128::from(len) * 1_000_000_000 / read_ns.max(1),
        );
        drop(reader);
        let shutdown_receipt = peerless.shutdown().await?;
        receipt("publisher_stream_local", &shutdown_receipt);
        println!(
            "BENCH_RESULT {{\"status\":\"stream_local_complete\",\"bytes\":{len},\"source_sha256\":\"{expected}\",\"publication_ns\":{publication_ns},\"total_ns\":{}}}",
            total.elapsed().as_nanos()
        );
        return Ok(());
    }
    let result = peerless
        .selected_blobs()
        .publish(
            BlobPublishRequest {
                operation_key: b"benchmark-once".to_vec(),
                topic: topic.clone(),
                scope: scope.clone(),
                priority: Priority::Priority,
                media_type: Some("application/octet-stream".into()),
                schema_id: b"benchmark-v1".to_vec(),
            },
            File::open(&source)?,
        )
        .await;
    let publication_ns = publication_start.elapsed().as_nanos();
    if len > MAX_SELECTED_LIVE_BLOB_BYTES {
        let error = result.expect_err("oversized publication must reject");
        assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
        let r = peerless.shutdown().await?;
        assert_eq!(r.blobs, 0);
        receipt("publisher_rejected", &r);
        println!(
            "BENCH_RESULT {{\"status\":\"rejected_resource_limit\",\"bytes\":{len},\"source_sha256\":\"{expected}\",\"publication_attempt_ns\":{publication_ns},\"publication_ns\":null,\"transfer_ns\":null,\"verification_ns\":null,\"total_ns\":{},\"max_live_blob_bytes\":{MAX_SELECTED_LIVE_BLOB_BYTES}}}",
            total.elapsed().as_nanos()
        );
        return Ok(());
    }
    let published = result?;
    assert_eq!(published.total_len, len);
    assert!(published.inserted);
    println!(
        "BENCH_PUBLICATION {{\"bytes\":{len},\"publication_ns\":{publication_ns},\"blob_id\":\"{}\"}}",
        published.id
    );
    let r = peerless.shutdown().await?;
    assert_eq!(r.blobs, 1);
    receipt("publisher_peerless", &r);
    let a = UdpSocket::bind(local)?;
    let b = UdpSocket::bind(local)?;
    let pa = a.local_addr()?;
    let ra = b.local_addr()?;
    drop((a, b));
    println!(
        "BENCH_PATH {{\"publisher_bind\":\"{pa}\",\"receiver_bind\":\"{ra}\",\"transport\":\"direct Iroh QUIC\"}}"
    );
    let transfer = Instant::now();
    let pc = config(&publisher, pa, Some((&receiver, ra)), &topic, &scope);
    let rc = config(&receiver, ra, Some((&publisher, pa)), &topic, &scope);
    let (p, r) = if publisher.carrier > receiver.carrier {
        let p = start_node(pc).await?;
        let r = start_node(rc).await?;
        (p, r)
    } else {
        let r = start_node(rc).await?;
        let p = start_node(pc).await?;
        (p, r)
    };
    let request = BlobReadRequest {
        id: published.id,
        topic: topic.clone(),
        scope: scope.clone(),
    };
    let h = r.selected_blobs();
    let mut last = Instant::now();
    let completed=timeout(Duration::from_secs(deadline),async {
  loop {match h.read_page(BlobReadPageRequest{blob:request.clone(),offset:0,max_bytes:1}).await {
   Ok(page)=>{assert_eq!(page.total_len,len);assert_eq!(page.id,published.id);break Ok::<(),E>(());},
   Err(e) if retryable_probe_error(e.kind())=>{},
   Err(e)=>break Err(Box::new(e) as E),
  }
  if last.elapsed()>=Duration::from_secs(10){let s=r.selected_events().status().await?;println!("BENCH_PROGRESS {{\"elapsed_ns\":{},\"authenticated_contacts\":{},\"failed_contacts\":{}}}",transfer.elapsed().as_nanos(),s.authenticated_contacts,s.failed_contact_attempts);last=Instant::now();}
  sleep(Duration::from_millis(20)).await;
 }
 }).await;
    let ready_ns = transfer.elapsed().as_nanos();
    if let Ok(outcome) = &completed {
        assert!(outcome.is_ok(), "transfer failed: {outcome:?}");
    }
    // Finish and fold the last contact into receipts before opening stores.
    sleep(Duration::from_millis(600)).await;
    let (pr, rr) = tokio::join!(p.shutdown(), r.shutdown());
    let pr = pr?;
    let rr = rr?;
    drop(h);
    receipt("publisher_connected", &pr);
    receipt("receiver_connected", &rr);
    for rec in [&pr, &rr] {
        assert!(rec.direct_contacts > 0);
        assert_eq!(rec.direct_contacts, rec.contacts);
        assert_eq!(rec.relay_contacts, 0);
        assert_eq!(rec.unknown_path_contacts, 0);
        assert_eq!(rec.contact_errors, 0);
    }
    let store = Store::open_for_mission(
        receiver.state.join("mesh.redb"),
        receiver.mission.mission_authority_id(),
    )?;
    let stats = store.blob_stats()?;
    println!(
        "BENCH_DURABLE {{\"publications\":{},\"pending_sources\":{},\"committed_chunks\":{},\"network_staging_bytes\":{},\"carrier_prefixes\":{}}}",
        stats.publications,
        stats.pending_sources,
        stats.committed_chunks,
        stats.network_staging_bytes,
        stats.carrier_prefixes
    );
    if completed.is_err() {
        drop(store);
        println!(
            "BENCH_RESULT {{\"status\":\"transfer_timeout\",\"bytes\":{len},\"source_sha256\":\"{expected}\",\"publication_ns\":{publication_ns},\"transfer_ns\":null,\"transfer_observed_ns\":{ready_ns},\"verification_ns\":null,\"total_ns\":{},\"fetched_carrier_bytes\":{},\"pending_sources\":{}}}",
            total.elapsed().as_nanos(),
            rr.blob_bytes_fetched,
            stats.pending_sources
        );
        return Ok(());
    }
    assert_eq!(stats.publications, 1);
    assert_eq!(stats.pending_sources, 0);
    assert_eq!(stats.carrier_prefixes, 0);
    assert_eq!(stats.network_staging_bytes, 0);
    drop(store);
    let transfer_ns = transfer.elapsed().as_nanos();
    let verification = Instant::now();
    let reopened = start_node(config(&receiver, local, None, &topic, &scope)).await?;
    let handle = reopened.selected_blobs();
    let mut offset = 0;
    let mut digest = Sha256::new();
    let mut pages = 0;
    loop {
        let page = handle
            .read_page(BlobReadPageRequest {
                blob: request.clone(),
                offset,
                max_bytes: MAX_SELECTED_BLOB_PAGE_BYTES,
            })
            .await?;
        assert_eq!(page.id, published.id);
        assert_eq!(page.total_len, len);
        assert_eq!(page.publisher, published.publisher);
        assert_eq!(page.offset, offset);
        assert!(!page.is_empty());
        assert!(page.len() <= MAX_SELECTED_BLOB_PAGE_BYTES);
        digest.update(page.as_bytes());
        offset = page.next_offset();
        pages += 1;
        if page.complete {
            break;
        }
    }
    let actual: String = digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(offset, len);
    assert_eq!(actual, expected);
    let verification_ns = verification.elapsed().as_nanos();
    let total_ns = total.elapsed().as_nanos();
    let final_receipt = reopened.shutdown().await?;
    receipt("receiver_reopened", &final_receipt);
    assert_eq!(final_receipt.blobs, 1);
    assert_eq!(final_receipt.contacts, 0);
    println!(
        "BENCH_RESULT {{\"status\":\"complete\",\"bytes\":{len},\"verified_bytes\":{offset},\"pages\":{pages},\"source_sha256\":\"{expected}\",\"receiver_sha256\":\"{actual}\",\"publication_ns\":{publication_ns},\"transfer_until_ready_ns\":{ready_ns},\"transfer_ns\":{transfer_ns},\"verification_ns\":{verification_ns},\"total_ns\":{total_ns}}}"
    );
    Ok(())
}
