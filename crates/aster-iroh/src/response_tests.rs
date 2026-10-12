use super::*;

async fn pair() -> (Endpoint, Endpoint, Connection, Connection) {
    let mut config = EndpointConfig::direct("127.0.0.1:0".parse().unwrap());
    config.exchange_timeout = Duration::from_secs(2);
    let server = Endpoint::bind(SecretKey::generate(), config).await.unwrap();
    let client = Endpoint::bind(SecretKey::generate(), config).await.unwrap();
    let allowed = BTreeSet::from([client.id()]);
    let (responder, initiator) = tokio::join!(
        server.accept(&allowed),
        client.connect(ExpectedPeer {
            id: server.id(),
            address: server
                .bound_sockets()
                .into_iter()
                .find(SocketAddr::is_ipv4)
                .unwrap()
        })
    );
    (server, client, responder.unwrap(), initiator.unwrap())
}

#[tokio::test]
async fn cancelling_response_closes_connection_instead_of_losing_delivery_state() {
    let (server, client, responder, _initiator) = pair().await;
    {
        let response = responder.respond_once(|_| Ok((vec![], false)));
        tokio::pin!(response);
        assert!(response.as_mut().now_or_never().is_none());
    }
    assert!(
        responder.inner.close_reason().is_some(),
        "cancelled responder must fail closed"
    );
    server.close().await;
    client.close().await;
}

#[tokio::test]
async fn sequential_responses_and_final_consumed_marker_are_preserved() {
    let (server, client, responder, initiator) = pair().await;
    for i in 0..80u8 {
        let request = [i];
        let (sent, received) = tokio::join!(
            responder.respond_once(|request| Ok((request.to_vec(), i == 79))),
            initiator.request(&request)
        );
        assert_eq!(sent.unwrap(), i == 79);
        assert_eq!(received.unwrap(), [i]);
    }
    // Even fully ACKed data is not proof of application consumption.
    responder
        .response_delivery
        .lock()
        .await
        .drain()
        .await
        .unwrap();
    let finish = responder.finish_as_responder();
    tokio::pin!(finish);
    assert!(finish.as_mut().now_or_never().is_none());
    assert!(responder.inner.close_reason().is_none());
    let (sent, consumed) = tokio::join!(finish, initiator.finish_as_initiator());
    sent.unwrap();
    consumed.unwrap();
    server.close().await;
    client.close().await;
}

#[tokio::test]
async fn stop_sending_is_not_reported_as_successful_session_completion() {
    let (server, client, responder, initiator) = pair().await;
    let response = async {
        let sent = responder
            .respond_once(|_| Ok((vec![0x55; 1024 * 1024], true)))
            .await;
        if sent.is_ok() {
            responder.finish_as_responder().await
        } else {
            sent.map(|_| ())
        }
    };
    let reset = async {
        let (mut send, mut receive) = initiator.inner.open_bi().await.unwrap();
        send.write_all(b"request").await.unwrap();
        send.finish().unwrap();
        receive.stop(7u8.into()).unwrap();
    };
    let (result, ()) = tokio::join!(response, reset);
    assert!(result.is_err());
    server.close().await;
    client.close().await;
}

#[tokio::test]
async fn missing_consumed_marker_times_out_and_closes() {
    let (server, client, mut responder, initiator) = pair().await;
    responder.exchange_timeout = Duration::from_millis(20);
    assert!(matches!(
        responder.finish_as_responder().await,
        Err(CarrierError::Timeout("responder session completion"))
    ));
    assert!(responder.inner.close_reason().is_some());
    assert!(initiator.request(b"after close").await.is_err());
    server.close().await;
    client.close().await;
}
