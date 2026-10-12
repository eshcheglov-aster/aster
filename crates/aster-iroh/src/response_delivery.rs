//! Transport completion tracking for finished response streams.
use futures::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};

use crate::CarrierError;

// Bounds retained completion handles, not exchanges over the session lifetime.
// One additional response may be in submit while backpressured. No waiter tasks
// are spawned; QUIC retains its existing flow control and retransmission bounds.
const MAX_PENDING_RESPONSES: usize = 16;

#[derive(Default)]
pub(super) struct ResponseDelivery {
    pending: FuturesUnordered<BoxFuture<'static, Result<(), CarrierError>>>,
}

impl ResponseDelivery {
    pub(super) async fn drain(&mut self) -> Result<(), CarrierError> {
        while let Some(result) = self.pending.next().await {
            result?;
        }
        Ok(())
    }

    pub(super) async fn submit(
        &mut self,
        completion: BoxFuture<'static, Result<(), CarrierError>>,
    ) -> Result<(), CarrierError> {
        while let Some(Some(result)) = self.pending.next().now_or_never() {
            result?;
        }
        if self.pending.len() == MAX_PENDING_RESPONSES {
            self.pending
                .next()
                .await
                .expect("nonempty completion queue")?;
        }
        self.pending.push(completion);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;

    #[tokio::test]
    async fn final_completion_waits_for_delivery_and_preserves_stop_errors() {
        let mut delivery = ResponseDelivery::default();
        let (ack, acknowledged) = tokio::sync::oneshot::channel::<()>();
        delivery
            .submit(
                async move {
                    acknowledged.await.unwrap();
                    Err(CarrierError::Transport(
                        "peer stopped response stream with code 7".into(),
                    ))
                }
                .boxed(),
            )
            .await
            .unwrap();
        let drain = delivery.drain();
        tokio::pin!(drain);
        assert!(
            drain.as_mut().now_or_never().is_none(),
            "final completion cannot discard pending delivery"
        );
        ack.send(()).unwrap();
        assert!(
            matches!(drain.await, Err(CarrierError::Transport(message)) if message.contains("code 7"))
        );
    }

    #[tokio::test]
    async fn acknowledgement_backpressure_is_bounded_and_reusable() {
        let mut delivery = ResponseDelivery::default();
        let (ack, acknowledged) = tokio::sync::oneshot::channel::<()>();
        delivery
            .submit(
                async move {
                    acknowledged.await.unwrap();
                    Ok(())
                }
                .boxed(),
            )
            .await
            .unwrap();
        for _ in 1..16 {
            delivery
                .submit(futures::future::pending().boxed())
                .await
                .unwrap();
        }
        let extra = delivery.submit(futures::future::pending().boxed());
        tokio::pin!(extra);
        assert!(
            extra.as_mut().now_or_never().is_none(),
            "full queue must apply backpressure"
        );
        ack.send(()).unwrap();
        extra.await.unwrap();
    }

    #[tokio::test]
    async fn next_response_is_not_gated_on_previous_transport_ack() {
        let mut delivery = ResponseDelivery::default();
        let (_ack, acknowledged) = tokio::sync::oneshot::channel::<()>();
        let completion = async move {
            acknowledged.await.expect("ACK sender retained");
            Ok(())
        }
        .boxed();
        assert!(
            matches!(delivery.submit(completion).now_or_never(), Some(Ok(()))),
            "finished response must release the serial responder before its ACK"
        );
    }
}
