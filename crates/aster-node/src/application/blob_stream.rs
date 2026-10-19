//! Bounded application-owned Blob publication streams.

use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use aster_mesh::{NodeId, Priority, Scope, Topic};

use super::blob::{
    BlobId, BlobPublishOptions, BlobPublishRequest, BlobPublishResult, SelectedBlobCommand,
};
use super::{ApplicationError, SelectedApplicationCommand, actor_unavailable};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPublishStreamRequest {
    pub publication: BlobPublishRequest,
    pub options: BlobPublishOptions,
    pub total_len: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobPublishProgress {
    pub accepted_offset: u64,
    pub durable_offset: u64,
}

pub struct SelectedBlobPublishStream {
    commands: mpsc::Sender<SelectedApplicationCommand>,
    token: [u8; 32],
    accepted_offset: u64,
    durable_offset: u64,
    closed: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct BlobReadFrame {
    pub offset: u64,
    pub bytes: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobReadStreamMetadata {
    pub id: BlobId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub ttl_ms: Option<u64>,
    pub total_len: u64,
    pub media_type: Option<String>,
    pub schema_id: Vec<u8>,
    pub acceptance_marker: u64,
}

pub struct SelectedBlobReadStream {
    commands: mpsc::Sender<SelectedApplicationCommand>,
    token: [u8; 32],
    metadata: BlobReadStreamMetadata,
    closed: bool,
}

impl SelectedBlobReadStream {
    pub(crate) fn new(
        commands: mpsc::Sender<SelectedApplicationCommand>,
        token: [u8; 32],
        metadata: BlobReadStreamMetadata,
    ) -> Self {
        Self {
            commands,
            token,
            metadata,
            closed: false,
        }
    }

    pub const fn metadata(&self) -> &BlobReadStreamMetadata {
        &self.metadata
    }

    pub async fn next(
        &mut self,
        max_bytes: usize,
    ) -> Result<Option<BlobReadFrame>, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.commands
            .send(SelectedApplicationCommand::Blob(
                SelectedBlobCommand::NextReadStream {
                    token: self.token,
                    max_bytes,
                    response,
                },
            ))
            .await
            .map_err(|_| actor_unavailable("blob stream read"))?;
        let frame = received
            .await
            .map_err(|_| actor_unavailable("blob stream read"))??;
        if frame.is_none() {
            self.closed = true;
        }
        Ok(frame)
    }
}

impl Drop for SelectedBlobReadStream {
    fn drop(&mut self) {
        if !self.closed {
            _ = self.commands.try_send(SelectedApplicationCommand::Blob(
                SelectedBlobCommand::CloseReadStream { token: self.token },
            ));
        }
    }
}

impl SelectedBlobPublishStream {
    pub(crate) fn new(
        commands: mpsc::Sender<SelectedApplicationCommand>,
        token: [u8; 32],
        progress: BlobPublishProgress,
    ) -> Self {
        Self {
            commands,
            token,
            accepted_offset: progress.accepted_offset,
            durable_offset: progress.durable_offset,
            closed: false,
        }
    }

    pub const fn durable_offset(&self) -> u64 {
        self.durable_offset
    }

    /// Transfers cleanup to the actor after the open reply was not delivered.
    pub(crate) fn into_closed_token(mut self) -> [u8; 32] {
        self.closed = true;
        self.token
    }

    pub async fn write(
        &mut self,
        offset: u64,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<BlobPublishProgress, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.commands
            .send(SelectedApplicationCommand::Blob(
                SelectedBlobCommand::AppendPublishStream {
                    token: self.token,
                    offset,
                    bytes,
                    response,
                },
            ))
            .await
            .map_err(|_| actor_unavailable("blob stream write"))?;
        let progress = received
            .await
            .map_err(|_| actor_unavailable("blob stream write"))??;
        self.accepted_offset = progress.accepted_offset;
        self.durable_offset = progress.durable_offset;
        Ok(progress)
    }

    pub async fn finish(mut self) -> Result<BlobPublishResult, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.commands
            .send(SelectedApplicationCommand::Blob(
                SelectedBlobCommand::FinishPublishStream {
                    token: self.token,
                    response,
                },
            ))
            .await
            .map_err(|_| actor_unavailable("blob stream finish"))?;
        // Finish consumes this handle. Once queued, the actor owns cleanup,
        // even if this future is cancelled before consuming its reply.
        self.closed = true;
        received
            .await
            .map_err(|_| actor_unavailable("blob stream finish"))?
    }
}

impl Drop for SelectedBlobPublishStream {
    fn drop(&mut self) {
        if !self.closed {
            let command =
                SelectedApplicationCommand::Blob(SelectedBlobCommand::ClosePublishStream {
                    token: self.token,
                });
            if let Err(mpsc::error::TrySendError::Full(command)) = self.commands.try_send(command) {
                let commands = self.commands.clone();
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    runtime.spawn(async move {
                        _ = commands.send(command).await;
                    });
                } else {
                    _ = commands.blocking_send(command);
                }
            }
        }
    }
}

pub(crate) struct OpenedBlobPublishStream {
    pub token: [u8; 32],
    pub progress: BlobPublishProgress,
}

pub(crate) struct OpenedBlobReadStream {
    pub token: [u8; 32],
    pub metadata: BlobReadStreamMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dropped_publish_stream_eventually_closes_when_command_lane_is_full() {
        let token = [0x5a; 32];
        let (commands, mut received) = mpsc::channel(1);
        commands
            .send(SelectedApplicationCommand::Blob(
                SelectedBlobCommand::CloseReadStream { token: [0x11; 32] },
            ))
            .await
            .expect("fill command lane");
        let stream = SelectedBlobPublishStream::new(
            commands,
            token,
            BlobPublishProgress {
                accepted_offset: 0,
                durable_offset: 0,
            },
        );

        drop(stream);
        _ = received.recv().await.expect("receive lane filler");
        let close = tokio::time::timeout(std::time::Duration::from_secs(1), received.recv())
            .await
            .expect("close enqueue deadline")
            .expect("receive close command");
        assert!(matches!(
            close,
            SelectedApplicationCommand::Blob(SelectedBlobCommand::ClosePublishStream {
                token: actual
            }) if actual == token
        ));
    }
}
