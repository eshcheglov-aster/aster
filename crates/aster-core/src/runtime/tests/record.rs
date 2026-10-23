use super::*;
use crate::api::{ApplicationNodeRef, Query};

#[test]
fn record_conflicts_preserve_siblings_and_history_across_recontact() {
    let root = runtime_directory("record-recontact");
    let topic = Topic::new("alpha").unwrap();
    let scope = Scope::new("mission/team").unwrap();
    let access = ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()]).unwrap();
    let mut provisioner = ReferenceProvisioner::from_seed([0x7a; 32]).unwrap();
    let left_bundle = provisioner
        .issue_node(1, std::slice::from_ref(&access))
        .unwrap()
        .to_bytes()
        .unwrap();
    let right_bundle = provisioner
        .issue_node(2, &[access])
        .unwrap()
        .to_bytes()
        .unwrap();
    let open = |name: &str, bundle: &[u8]| {
        ReferenceSemanticRuntimeBackend::new(
            open_reference_node(
                root.join(format!("{name}.sqlite")),
                restored_bundle(bundle),
                NodeConfig::default(),
            )
            .unwrap(),
            BlobTransferStore::open_with_config(
                root.join(format!("{name}-blobs")),
                BlobStoreConfig::default(),
            )
            .unwrap(),
        )
        .unwrap()
    };
    let mut left = open("left", &left_bundle);
    let mut right = open("right", &right_bundle);
    let left_id = left.node().identity();
    let right_id = right.node().identity();
    let record = |payload: &[u8]| PublishRequest {
        class: DataClass::Record,
        topic: topic.clone(),
        scope: scope.clone(),
        priority: Priority::Priority,
        ttl_ms: None,
        logical_key: b"plan-red".to_vec(),
        payload: payload.to_vec(),
        tombstone: false,
    };
    let query = Query {
        topic: Some(topic.clone()),
        scope: Some(scope.clone()),
        class: Some(DataClass::Record),
        logical_key: Some(b"plan-red".to_vec()),
        ..Query::default()
    };
    for (round, left_payload, right_payload) in [
        (
            1_u64,
            b"left revision".as_slice(),
            b"right revision".as_slice(),
        ),
        (
            2,
            b"left recontact revision".as_slice(),
            b"right recontact revision".as_slice(),
        ),
    ] {
        let left_revision = ApplicationNodeRef::new(left.node_mut())
            .publish(record(left_payload))
            .unwrap();
        let right_revision = ApplicationNodeRef::new(right.node_mut())
            .publish(record(right_payload))
            .unwrap();
        for backend in [&mut left, &mut right] {
            assert_eq!(
                ApplicationNodeRef::new(backend.node_mut())
                    .quota_usage(Some(&scope))
                    .unwrap()
                    .items,
                round * 2 - 1
            );
        }
        let mut expected = vec![left_revision.id, right_revision.id];
        expected.sort_unstable();
        let mut initiator = RuntimeDriver::initiator(
            restored_bundle(&left_bundle),
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            left,
            blob_start(400 + round),
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder_with_start(
            restored_bundle(&right_bundle),
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            right,
            blob_start(400 + round),
            None,
        )
        .unwrap();
        let (left_link, right_link) = MemoryLink::pair(768);
        let now = Instant::now();
        for tick in 0..5_000 {
            let now = now + Duration::from_millis(tick);
            initiator.pump_at(&left_link, now).unwrap();
            responder.pump_at(&right_link, now).unwrap();
            if [initiator.backend_mut(), responder.backend_mut()]
                .into_iter()
                .all(|backend| {
                    ApplicationNodeRef::new(backend.node_mut())
                        .conflicts(query.clone())
                        .is_ok_and(|conflicts| {
                            conflicts.len() == 1 && conflicts[0].siblings == expected
                        })
                })
            {
                break;
            }
        }
        assert_eq!(initiator.authenticated_peer(), Some(right_id));
        assert_eq!(responder.authenticated_peer(), Some(left_id));
        for backend in [initiator.backend_mut(), responder.backend_mut()] {
            let mut app = ApplicationNodeRef::new(backend.node_mut());
            let conflicts = app.conflicts(query.clone()).unwrap();
            assert_eq!(conflicts.len(), 1);
            assert_eq!(conflicts[0].siblings, expected);
            assert_eq!(app.quota_usage(Some(&scope)).unwrap().items, round * 2);
        }
        // End both contacts but retain the durable authorities. The next round
        // publishes independently and authenticates fresh sessions, as before.
        left = initiator.into_backend();
        right = responder.into_backend();
    }
    drop(left);
    drop(right);
    fs::remove_dir_all(root).unwrap();
}
