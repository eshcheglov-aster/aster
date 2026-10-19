use std::{
    future::Future,
    io::{Seek as _, SeekFrom, Write as _},
    path::Path,
    sync::Arc,
};

use aster_mesh::{MAX_BLOB_MEDIA_TYPE_BYTES, MAX_BLOB_SCHEMA_ID_BYTES};
use aster_node::application::{
    ApplicationErrorKind, BlobId, BlobPublishOptions, BlobPublishRequest as NodeBlobPublishRequest,
    BlobPublishResult, BlobPublishStreamRequest, BlobReadPage, BlobReadPageRequest,
    BlobReadRequest as NodeBlobReadRequest, BlobReadStreamMetadata, MAX_SELECTED_LIVE_BLOB_BYTES,
    Priority, Scope, SelectedBlobHandle, SelectedBlobReadStream, Topic,
};
use aster_redb_store::MAX_BLOB_OPERATION_KEY_BYTES;
use connectrpc::{ConnectError, ErrorCode, RequestContext, Response, ServiceResult, ServiceStream};
use futures::StreamExt as _;
use tokio::sync::OwnedSemaphorePermit;
use zeroize::Zeroizing;

use crate::{
    BLOB_RPC_FRAME_BYTES, BLOB_RPC_READ_FRAME_BYTES, api,
    error::{PublicOperation, connect_blob_application_error, public_error},
};

const UPLOAD_PERMITS: usize = 1;

#[derive(Clone)]
pub(crate) struct BlobConnectService {
    blobs: SelectedBlobHandle,
    max_publish_bytes: u64,
    staging: Option<Arc<PinnedStagingDirectory>>,
    uploads: Arc<tokio::sync::Semaphore>,
}

impl BlobConnectService {
    pub(crate) fn new(blobs: SelectedBlobHandle, state_root: &Path) -> std::io::Result<Self> {
        let staging = open_optional_staging(state_root)?.map(Arc::new);
        let max_publish_bytes = blobs.max_publish_bytes();
        Ok(Self {
            blobs,
            max_publish_bytes,
            staging,
            uploads: Arc::new(tokio::sync::Semaphore::new(UPLOAD_PERMITS)),
        })
    }

    pub(crate) async fn publish(
        &self,
        ctx: RequestContext,
        mut requests: connectrpc::InboundStream<api::PublishBlobRequest>,
    ) -> ServiceResult<ServiceStream<api::PublishBlobResponse>> {
        let operation = PublicOperation::PublishBlob;
        if ctx.protocol() == Some(connectrpc::Protocol::GrpcWeb) {
            return Err(unsupported_transport(operation));
        }
        let first = requests
            .next()
            .await
            .ok_or_else(|| malformed(operation))?
            .map_err(|_| malformed(operation))?
            .to_owned_message();
        let (parsed, grammar) = UploadGrammar::start(first, self.max_publish_bytes)?;
        let permit = Arc::clone(&self.uploads)
            .try_acquire_owned()
            .map_err(|_| resource_exhausted(operation))?;
        if parsed.options.ttl_ms().is_some() {
            // Finite publications need the retained path's receiver-local custody
            // authority. Their private staging file is replayed from zero on retry.
            let staging = self
                .staging
                .as_ref()
                .cloned()
                .ok_or_else(|| unsupported_transport(operation))?;
            let writer = BlockingUploadWriter::start(staging, grammar.total_len, permit).await?;
            let state = FinitePublishStreamState {
                blobs: self.blobs.clone(),
                requests,
                parsed: Some(parsed),
                writer: Some(writer),
                grammar: Some(grammar),
                accepted_pending: true,
                complete: false,
            };
            return Response::stream_ok(futures::stream::try_unfold(
                state,
                next_finite_publish_response,
            ));
        }
        let stream = self
            .blobs
            .open_publish_stream(BlobPublishStreamRequest {
                publication: parsed.request,
                options: parsed.options,
                total_len: grammar.total_len,
            })
            .await
            .map_err(|error| connect_blob_application_error(error, operation))?;
        let durable_offset = stream.durable_offset();
        let grammar = grammar.resume(durable_offset)?;
        let state = PublishStreamState {
            requests,
            stream: Some(stream),
            grammar: Some(grammar),
            durable_offset,
            accepted_pending: true,
            complete: false,
            _permit: permit,
        };
        Response::stream_ok(futures::stream::try_unfold(state, next_publish_response))
    }

    pub(crate) async fn read(
        &self,
        request: api::ReadBlobRequest,
    ) -> ServiceResult<ServiceStream<api::ReadBlobResponse>> {
        let operation = PublicOperation::ReadBlob;
        let (request, topic, scope) = parse_read_request(request)?;
        let mut stream = match self.blobs.open_read_stream(request.clone()).await {
            Ok(stream) => stream,
            Err(error) if error.kind() == ApplicationErrorKind::NotFound => {
                return legacy_read_stream(self.blobs.clone(), request, topic, scope);
            }
            Err(error) => return Err(connect_blob_application_error(error, operation)),
        };
        let metadata = ReadMetadata::from_stream(stream.metadata());
        let pending = stream
            .next(BLOB_RPC_READ_FRAME_BYTES)
            .await
            .map_err(|error| connect_blob_application_error(error, operation))?
            .ok_or_else(|| internal(operation))?;
        if pending.offset != 0 || pending.bytes.is_empty() {
            return Err(internal(operation));
        }
        let state = ReadStreamState {
            stream,
            pending,
            metadata,
            complete: false,
        };
        let responses = futures::stream::try_unfold(state, move |mut state| async move {
            if state.complete {
                return Ok(None);
            }
            let next = state
                .stream
                .next(BLOB_RPC_READ_FRAME_BYTES)
                .await
                .map_err(|error| connect_blob_application_error(error, operation))?;
            let complete = next.is_none();
            let following_offset = next.as_ref().map(|frame| frame.offset);
            let frame = std::mem::replace(
                &mut state.pending,
                next.unwrap_or_else(|| aster_node::application::BlobReadFrame {
                    offset: state.metadata.total_len,
                    bytes: Zeroizing::new(Vec::new()),
                }),
            );
            let end = frame
                .offset
                .checked_add(frame.bytes.len() as u64)
                .ok_or_else(|| internal(operation))?;
            if frame.bytes.is_empty()
                || end > state.metadata.total_len
                || complete != (end == state.metadata.total_len)
                || following_offset.is_some_and(|offset| offset != end)
            {
                return Err(internal(operation));
            }
            state.complete = complete;
            let response = read_response(
                &state.metadata,
                frame.offset,
                frame.bytes.to_vec(),
                complete,
            );
            Ok(Some((response, state)))
        });
        Response::stream_ok(responses)
    }
}

fn open_optional_staging(state_root: &Path) -> std::io::Result<Option<PinnedStagingDirectory>> {
    match PinnedStagingDirectory::open(state_root) {
        Ok(staging) => Ok(Some(staging)),
        Err(error) if error.kind() == std::io::ErrorKind::Unsupported => Ok(None),
        Err(error) => Err(error),
    }
}

struct PinnedStagingDirectory {
    #[cfg(target_os = "linux")]
    descriptor: rustix::fd::OwnedFd,
}

impl PinnedStagingDirectory {
    fn open(state_root: &Path) -> std::io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{Mode, OFlags};

            let descriptor = rustix::fs::open(
                state_root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(std::io::Error::from)?;
            Ok(Self { descriptor })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = state_root;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "private allocated Blob staging requires Linux",
            ))
        }
    }
}

enum WriterCommand {
    Write(
        Zeroizing<Vec<u8>>,
        tokio::sync::oneshot::Sender<std::io::Result<()>>,
    ),
    Finish(tokio::sync::oneshot::Sender<std::io::Result<PreparedUpload>>),
}

struct PreparedUpload {
    file: Option<std::fs::File>,
    permit: Option<OwnedSemaphorePermit>,
}

impl PreparedUpload {
    fn new(file: std::fs::File, permit: OwnedSemaphorePermit) -> Self {
        Self {
            file: Some(file),
            permit: Some(permit),
        }
    }

    fn into_parts(mut self) -> (std::fs::File, OwnedSemaphorePermit) {
        let file = self.file.take().expect("prepared upload owns its file");
        let permit = self.permit.take().expect("prepared upload owns its permit");
        (file, permit)
    }
}

impl Drop for PreparedUpload {
    fn drop(&mut self) {
        // Capacity becomes reusable only after the staging descriptor is gone.
        drop(self.file.take());
        drop(self.permit.take());
    }
}

struct BlockingUploadWriter {
    commands: tokio::sync::mpsc::Sender<WriterCommand>,
    task: tokio::task::JoinHandle<()>,
}

impl BlockingUploadWriter {
    async fn start(
        staging: Arc<PinnedStagingDirectory>,
        total_len: u64,
        permit: OwnedSemaphorePermit,
    ) -> Result<Self, ConnectError> {
        let (commands, receiver) = tokio::sync::mpsc::channel(1);
        let (ready_send, ready_receive) = tokio::sync::oneshot::channel();
        let task = tokio::task::spawn_blocking(move || {
            let mut permit = Some(permit);
            let file = open_private_staging(&staging, total_len);
            match file {
                Ok(file) => {
                    if ready_send.send(Ok(())).is_ok() {
                        run_blocking_writer(
                            file,
                            permit.take().expect("starting writer owns upload permit"),
                            receiver,
                        );
                    } else {
                        drop(file);
                        drop(permit.take());
                    }
                }
                Err(error) => {
                    let _ = ready_send.send(Err(error));
                    drop(permit.take());
                }
            }
        });
        ready_receive
            .await
            .map_err(|_| state_unavailable(PublicOperation::PublishBlob))??;
        Ok(Self { commands, task })
    }

    async fn write(&mut self, bytes: Zeroizing<Vec<u8>>) -> Result<(), ConnectError> {
        let (send, receive) = tokio::sync::oneshot::channel();
        self.commands
            .send(WriterCommand::Write(bytes, send))
            .await
            .map_err(|_| state_unavailable(PublicOperation::PublishBlob))?;
        receive
            .await
            .map_err(|_| state_unavailable(PublicOperation::PublishBlob))?
            .map_err(|_| state_unavailable(PublicOperation::PublishBlob))
    }

    async fn finish(self) -> Result<(std::fs::File, OwnedSemaphorePermit), ConnectError> {
        let (send, receive) = tokio::sync::oneshot::channel();
        self.commands
            .send(WriterCommand::Finish(send))
            .await
            .map_err(|_| state_unavailable(PublicOperation::PublishBlob))?;
        let result = receive
            .await
            .map_err(|_| state_unavailable(PublicOperation::PublishBlob))?
            .map_err(|_| state_unavailable(PublicOperation::PublishBlob))?;
        self.task
            .await
            .map_err(|_| state_unavailable(PublicOperation::PublishBlob))?;
        Ok(result.into_parts())
    }
}

fn run_blocking_writer(
    file: std::fs::File,
    permit: OwnedSemaphorePermit,
    mut commands: tokio::sync::mpsc::Receiver<WriterCommand>,
) {
    let mut file = Some(file);
    let mut permit = Some(permit);
    while let Some(command) = commands.blocking_recv() {
        match command {
            WriterCommand::Write(bytes, completed) => {
                let result = file
                    .as_mut()
                    .expect("writer owns its file until finish")
                    .write_all(&bytes);
                let _ = completed.send(result);
            }
            WriterCommand::Finish(completed) => {
                let result = match file
                    .as_mut()
                    .expect("writer owns its file until finish")
                    .seek(SeekFrom::Start(0))
                {
                    Ok(_) => Ok(PreparedUpload::new(
                        file.take().expect("rewound writer file"),
                        permit.take().expect("writer permit is owned until finish"),
                    )),
                    Err(error) => Err(error),
                };
                let _ = completed.send(result);
                break;
            }
        }
    }
    drop(file.take());
    drop(permit);
}

async fn await_upload_with_permit<T, F>(
    permit: OwnedSemaphorePermit,
    operation: F,
) -> Result<T, tokio::task::JoinError>
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
{
    tokio::spawn(async move {
        let _permit = permit;
        operation.await
    })
    .await
}

#[derive(Debug)]
struct ParsedPublish {
    request: NodeBlobPublishRequest,
    options: BlobPublishOptions,
}

#[derive(Debug)]
struct UploadGrammar {
    total_len: u64,
    received: u64,
    frames: u64,
    maximum_frames: u64,
}

impl UploadGrammar {
    fn start(
        first: api::PublishBlobRequest,
        max_publish_bytes: u64,
    ) -> Result<(ParsedPublish, Self), ConnectError> {
        let operation = PublicOperation::PublishBlob;
        let api::publish_blob_request::Frame::Metadata(metadata) =
            first.frame.ok_or_else(|| malformed(operation))?
        else {
            return Err(malformed(operation));
        };
        if metadata.total_len == 0 {
            return Err(malformed(operation));
        }
        if metadata.total_len > max_publish_bytes {
            return Err(resource_exhausted(operation));
        }
        if metadata.operation_key.is_empty()
            || metadata.operation_key.len() > MAX_BLOB_OPERATION_KEY_BYTES
            || metadata
                .media_type
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_BLOB_MEDIA_TYPE_BYTES)
            || metadata.schema_id.len() > MAX_BLOB_SCHEMA_ID_BYTES
        {
            return Err(malformed(operation));
        }
        let priority = parse_priority(metadata.priority, operation)?;
        let topic = Topic::new(metadata.topic).map_err(|_| malformed(operation))?;
        let scope = Scope::new(metadata.scope).map_err(|_| malformed(operation))?;
        let options = match metadata.ttl_ms {
            None => BlobPublishOptions::durable(),
            Some(0) => return Err(malformed(operation)),
            Some(ttl_ms) => {
                BlobPublishOptions::finite_ttl_ms(ttl_ms).map_err(|_| malformed(operation))?
            }
        };
        if options.ttl_ms().is_some() && metadata.total_len > MAX_SELECTED_LIVE_BLOB_BYTES {
            return Err(resource_exhausted(operation));
        }
        let maximum_frames = maximum_chunk_frames_for_len(metadata.total_len)?;
        Ok((
            ParsedPublish {
                request: NodeBlobPublishRequest {
                    operation_key: metadata.operation_key,
                    topic,
                    scope,
                    priority,
                    media_type: metadata.media_type,
                    schema_id: metadata.schema_id,
                },
                options,
            },
            Self {
                total_len: metadata.total_len,
                received: 0,
                frames: 0,
                maximum_frames,
            },
        ))
    }

    fn resume(mut self, durable_offset: u64) -> Result<Self, ConnectError> {
        if durable_offset > self.total_len
            || (durable_offset != self.total_len
                && !durable_offset.is_multiple_of(BLOB_RPC_FRAME_BYTES as u64))
        {
            return Err(internal(PublicOperation::PublishBlob));
        }
        self.received = durable_offset;
        self.frames = chunk_frames_for_len(durable_offset)?;
        Ok(self)
    }

    fn accept(&mut self, frame: api::PublishBlobRequest) -> Result<Vec<u8>, ConnectError> {
        let operation = PublicOperation::PublishBlob;
        let api::publish_blob_request::Frame::Data(chunk) =
            frame.frame.ok_or_else(|| malformed(operation))?
        else {
            return Err(malformed(operation));
        };
        if chunk.offset != self.received
            || chunk.bytes.is_empty()
            || chunk.bytes.len() > BLOB_RPC_FRAME_BYTES
        {
            return Err(malformed(operation));
        }
        let chunk_len = u64::try_from(chunk.bytes.len()).map_err(|_| malformed(operation))?;
        let remaining = self
            .total_len
            .checked_sub(self.received)
            .ok_or_else(|| malformed(operation))?;
        let canonical_len = remaining.min(BLOB_RPC_FRAME_BYTES as u64);
        if chunk_len != canonical_len {
            return Err(malformed(operation));
        }
        self.received = self
            .received
            .checked_add(chunk_len)
            .ok_or_else(|| malformed(operation))?;
        self.frames = self
            .frames
            .checked_add(1)
            .ok_or_else(|| malformed(operation))?;
        if self.frames > self.maximum_frames {
            return Err(malformed(operation));
        }
        Ok(chunk.bytes)
    }

    fn finish(self) -> Result<(), ConnectError> {
        if self.received == self.total_len && self.frames == self.maximum_frames {
            Ok(())
        } else {
            Err(malformed(PublicOperation::PublishBlob))
        }
    }
}

fn chunk_frames_for_len(len: u64) -> Result<u64, ConnectError> {
    if len == 0 {
        return Ok(0);
    }
    maximum_chunk_frames_for_len(len)
}

struct FinitePublishStreamState {
    blobs: SelectedBlobHandle,
    requests: connectrpc::InboundStream<api::PublishBlobRequest>,
    parsed: Option<ParsedPublish>,
    writer: Option<BlockingUploadWriter>,
    grammar: Option<UploadGrammar>,
    accepted_pending: bool,
    complete: bool,
}

async fn next_finite_publish_response(
    mut state: FinitePublishStreamState,
) -> Result<Option<(api::PublishBlobResponse, FinitePublishStreamState)>, ConnectError> {
    let operation = PublicOperation::PublishBlob;
    if state.complete {
        return Ok(None);
    }
    if state.accepted_pending {
        state.accepted_pending = false;
        return Ok(Some((publish_accepted(0), state)));
    }
    let frame = state
        .requests
        .next()
        .await
        .ok_or_else(|| malformed(operation))?
        .map_err(|_| malformed(operation))?
        .to_owned_message();
    if matches!(
        frame.frame,
        Some(api::publish_blob_request::Frame::Finish(_))
    ) {
        state
            .grammar
            .take()
            .ok_or_else(|| internal(operation))?
            .finish()?;
        if state.requests.next().await.is_some() {
            return Err(malformed(operation));
        }
        let writer = state.writer.take().ok_or_else(|| internal(operation))?;
        let (file, permit) = writer.finish().await?;
        let parsed = state.parsed.take().ok_or_else(|| internal(operation))?;
        let blobs = state.blobs.clone();
        let result = await_upload_with_permit(permit, async move {
            blobs
                .publish_with_options(parsed.request, parsed.options, file)
                .await
        })
        .await
        .map_err(|_| state_unavailable(operation))?
        .map_err(|error| connect_blob_application_error(error, operation))?;
        state.complete = true;
        return Ok(Some((publish_complete(result), state)));
    }
    let grammar = state.grammar.as_mut().ok_or_else(|| internal(operation))?;
    let chunk = Zeroizing::new(grammar.accept(frame)?);
    state
        .writer
        .as_mut()
        .ok_or_else(|| internal(operation))?
        .write(chunk)
        .await?;
    // Staging progress keeps the response stream active without claiming
    // resumable custody of this private, unlinked file.
    let progress = aster_node::application::BlobPublishProgress {
        accepted_offset: grammar.received,
        durable_offset: 0,
    };
    Ok(Some((publish_checkpoint(progress), state)))
}

struct PublishStreamState {
    requests: connectrpc::InboundStream<api::PublishBlobRequest>,
    stream: Option<aster_node::application::SelectedBlobPublishStream>,
    grammar: Option<UploadGrammar>,
    durable_offset: u64,
    accepted_pending: bool,
    complete: bool,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

async fn next_publish_response(
    mut state: PublishStreamState,
) -> Result<Option<(api::PublishBlobResponse, PublishStreamState)>, ConnectError> {
    let operation = PublicOperation::PublishBlob;
    if state.complete {
        return Ok(None);
    }
    if state.accepted_pending {
        state.accepted_pending = false;
        return Ok(Some((publish_accepted(state.durable_offset), state)));
    }
    loop {
        let Some(frame) = state.requests.next().await else {
            return Err(malformed(operation));
        };
        let frame = frame.map_err(|_| malformed(operation))?.to_owned_message();
        if matches!(
            frame.frame,
            Some(api::publish_blob_request::Frame::Finish(_))
        ) {
            let grammar = state.grammar.take().ok_or_else(|| internal(operation))?;
            grammar.finish()?;
            if state.requests.next().await.is_some() {
                return Err(malformed(operation));
            }
            let stream = state.stream.take().ok_or_else(|| internal(operation))?;
            let result = stream
                .finish()
                .await
                .map_err(|error| connect_blob_application_error(error, operation))?;
            state.complete = true;
            return Ok(Some((publish_complete(result), state)));
        }
        let grammar = state.grammar.as_mut().ok_or_else(|| internal(operation))?;
        let offset = grammar.received;
        let chunk = Zeroizing::new(grammar.accept(frame)?);
        let stream = state.stream.as_mut().ok_or_else(|| internal(operation))?;
        let progress = stream
            .write(offset, chunk)
            .await
            .map_err(|error| connect_blob_application_error(error, operation))?;
        if progress.accepted_offset != grammar.received
            || progress.durable_offset < state.durable_offset
            || progress.durable_offset > progress.accepted_offset
        {
            return Err(internal(operation));
        }
        if progress.durable_offset > state.durable_offset {
            state.durable_offset = progress.durable_offset;
            return Ok(Some((publish_checkpoint(progress), state)));
        }
    }
}

fn maximum_chunk_frames_for_len(total_len: u64) -> Result<u64, ConnectError> {
    let operation = PublicOperation::PublishBlob;
    let chunk_bytes = u64::try_from(BLOB_RPC_FRAME_BYTES).map_err(|_| internal(operation))?;
    total_len
        .checked_sub(1)
        .and_then(|value| value.checked_div(chunk_bytes))
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| malformed(operation))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReadMetadata {
    id: [u8; 32],
    publisher: [u8; 32],
    publisher_counter: u64,
    topic: String,
    scope: String,
    priority: Priority,
    ttl_ms: Option<u64>,
    total_len: u64,
    media_type: Option<String>,
    schema_id: Vec<u8>,
    acceptance_marker: u64,
}

impl ReadMetadata {
    fn from_page(page: &BlobReadPage, topic: &str, scope: &str) -> Self {
        Self {
            id: *page.id.as_bytes(),
            publisher: page.publisher,
            publisher_counter: page.publisher_counter,
            topic: topic.to_owned(),
            scope: scope.to_owned(),
            priority: page.priority,
            ttl_ms: page.ttl_ms,
            total_len: page.total_len,
            media_type: page.media_type.clone(),
            schema_id: page.schema_id.clone(),
            acceptance_marker: page.acceptance_marker,
        }
    }

    fn from_stream(metadata: &BlobReadStreamMetadata) -> Self {
        Self {
            id: *metadata.id.as_bytes(),
            publisher: metadata.publisher,
            publisher_counter: metadata.publisher_counter,
            topic: metadata.topic.as_str().to_owned(),
            scope: metadata.scope.as_str().to_owned(),
            priority: metadata.priority,
            ttl_ms: metadata.ttl_ms,
            total_len: metadata.total_len,
            media_type: metadata.media_type.clone(),
            schema_id: metadata.schema_id.clone(),
            acceptance_marker: metadata.acceptance_marker,
        }
    }
}

struct ReadStreamState {
    stream: SelectedBlobReadStream,
    pending: aster_node::application::BlobReadFrame,
    metadata: ReadMetadata,
    complete: bool,
}

struct LegacyReadStreamState {
    blobs: SelectedBlobHandle,
    request: NodeBlobReadRequest,
    topic: String,
    scope: String,
    offset: u64,
    metadata: Option<ReadMetadata>,
    complete: bool,
}

fn legacy_read_stream(
    blobs: SelectedBlobHandle,
    request: NodeBlobReadRequest,
    topic: String,
    scope: String,
) -> ServiceResult<ServiceStream<api::ReadBlobResponse>> {
    let operation = PublicOperation::ReadBlob;
    let state = LegacyReadStreamState {
        blobs,
        request,
        topic,
        scope,
        offset: 0,
        metadata: None,
        complete: false,
    };
    let responses = futures::stream::try_unfold(state, move |mut state| async move {
        if state.complete {
            return Ok(None);
        }
        let page = state
            .blobs
            .read_page(BlobReadPageRequest {
                blob: state.request.clone(),
                offset: state.offset,
                max_bytes: BLOB_RPC_READ_FRAME_BYTES,
            })
            .await
            .map_err(|error| connect_blob_application_error(error, operation))?;
        if page.offset != state.offset || page.is_empty() {
            return Err(internal(operation));
        }
        let observed = ReadMetadata::from_page(&page, &state.topic, &state.scope);
        if let Some(expected) = &state.metadata {
            ensure_stable_read_metadata(expected, &observed)?;
        } else {
            state.metadata = Some(observed.clone());
        }
        let next_offset = page.next_offset();
        let complete = page.complete;
        let page_len = u64::try_from(page.len()).map_err(|_| internal(operation))?;
        if page.offset.checked_add(page_len) != Some(next_offset)
            || page.len() > BLOB_RPC_READ_FRAME_BYTES
            || complete != (next_offset == observed.total_len)
        {
            return Err(internal(operation));
        }
        let metadata = state.metadata.as_ref().ok_or_else(|| internal(operation))?;
        let response = read_response(metadata, page.offset, page.as_bytes().to_vec(), complete);
        if next_offset <= state.offset || next_offset > observed.total_len {
            return Err(internal(operation));
        }
        state.offset = next_offset;
        state.complete = complete;
        Ok(Some((response, state)))
    });
    Response::stream_ok(responses)
}

fn ensure_stable_read_metadata(
    expected: &ReadMetadata,
    observed: &ReadMetadata,
) -> Result<(), ConnectError> {
    if expected == observed {
        Ok(())
    } else {
        Err(internal(PublicOperation::ReadBlob))
    }
}

fn parse_read_request(
    request: api::ReadBlobRequest,
) -> Result<(NodeBlobReadRequest, String, String), ConnectError> {
    let operation = PublicOperation::ReadBlob;
    let id: [u8; 32] = request
        .id
        .as_slice()
        .try_into()
        .map_err(|_| malformed(operation))?;
    let topic = Topic::new(request.topic).map_err(|_| malformed(operation))?;
    let scope = Scope::new(request.scope).map_err(|_| malformed(operation))?;
    let topic_name = topic.as_str().to_owned();
    let scope_name = scope.as_str().to_owned();
    Ok((
        NodeBlobReadRequest {
            id: BlobId::from_bytes(id),
            topic,
            scope,
        },
        topic_name,
        scope_name,
    ))
}

fn publish_accepted(offset: u64) -> api::PublishBlobResponse {
    api::PublishBlobResponse {
        frame: Some(api::publish_blob_response::Frame::Accepted(Box::new(
            api::PublishBlobAccepted {
                accepted_offset: offset,
                durable_offset: offset,
                canonical_frame_bytes: BLOB_RPC_FRAME_BYTES as u32,
                ..Default::default()
            },
        ))),
        ..Default::default()
    }
}

fn publish_checkpoint(
    progress: aster_node::application::BlobPublishProgress,
) -> api::PublishBlobResponse {
    api::PublishBlobResponse {
        frame: Some(api::publish_blob_response::Frame::Checkpoint(Box::new(
            api::PublishBlobCheckpoint {
                accepted_offset: progress.accepted_offset,
                durable_offset: progress.durable_offset,
                ..Default::default()
            },
        ))),
        ..Default::default()
    }
}

fn publish_complete(result: BlobPublishResult) -> api::PublishBlobResponse {
    api::PublishBlobResponse {
        frame: Some(api::publish_blob_response::Frame::Complete(Box::new(
            publish_receipt(result),
        ))),
        ..Default::default()
    }
}

fn publish_receipt(result: BlobPublishResult) -> api::PublishBlobReceipt {
    api::PublishBlobReceipt {
        id: result.id.as_bytes().to_vec(),
        publisher: result.publisher.to_vec(),
        publisher_counter: result.publisher_counter,
        priority: priority_message(result.priority).into(),
        ttl_ms: result.ttl_ms,
        total_len: result.total_len,
        media_type: result.media_type,
        schema_id: result.schema_id,
        acceptance_marker: result.acceptance_marker,
        inserted: result.inserted,
        ..Default::default()
    }
}

fn read_response(
    metadata: &ReadMetadata,
    offset: u64,
    data: Vec<u8>,
    complete: bool,
) -> api::ReadBlobResponse {
    api::ReadBlobResponse {
        id: metadata.id.to_vec(),
        publisher: metadata.publisher.to_vec(),
        publisher_counter: metadata.publisher_counter,
        topic: metadata.topic.clone(),
        scope: metadata.scope.clone(),
        priority: priority_message(metadata.priority).into(),
        ttl_ms: metadata.ttl_ms,
        total_len: metadata.total_len,
        media_type: metadata.media_type.clone(),
        schema_id: metadata.schema_id.clone(),
        acceptance_marker: metadata.acceptance_marker,
        offset,
        chunk: data,
        complete,
        ..Default::default()
    }
}

fn parse_priority(
    value: buffa::EnumValue<api::Priority>,
    operation: PublicOperation,
) -> Result<Priority, ConnectError> {
    match value.as_known() {
        Some(api::Priority::Routine) => Ok(Priority::Routine),
        Some(api::Priority::Priority) => Ok(Priority::Priority),
        Some(api::Priority::Immediate) => Ok(Priority::Immediate),
        Some(api::Priority::Flash) => Ok(Priority::Flash),
        Some(api::Priority::Unspecified) | None => Err(unsupported_value(operation)),
    }
}

const fn priority_message(priority: Priority) -> api::Priority {
    match priority {
        Priority::Routine => api::Priority::Routine,
        Priority::Priority => api::Priority::Priority,
        Priority::Immediate => api::Priority::Immediate,
        Priority::Flash => api::Priority::Flash,
    }
}

fn open_private_staging(
    staging: &PinnedStagingDirectory,
    total_len: u64,
) -> Result<std::fs::File, ConnectError> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{AtFlags, FallocateFlags, Mode, OFlags};

        let operation = PublicOperation::PublishBlob;
        match rustix::fs::openat(
            &staging.descriptor,
            ".",
            OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(descriptor) => {
                rustix::fs::fallocate(&descriptor, FallocateFlags::empty(), 0, total_len)
                    .map_err(classify_fallocate_error)?;
                return Ok(std::fs::File::from(descriptor));
            }
            Err(
                rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL,
            ) => {}
            Err(_) => return Err(state_unavailable(operation)),
        }
        for _ in 0..16 {
            let mut nonce = [0_u8; 16];
            getrandom::fill(&mut nonce).map_err(|_| internal(operation))?;
            let mut name = String::from(".aster-agent-blob-upload-");
            for byte in nonce {
                use std::fmt::Write as _;
                write!(&mut name, "{byte:02x}").map_err(|_| internal(operation))?;
            }
            let descriptor = match rustix::fs::openat(
                &staging.descriptor,
                name.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(descriptor) => descriptor,
                Err(rustix::io::Errno::EXIST) => continue,
                Err(_) => return Err(state_unavailable(operation)),
            };
            if rustix::fs::unlinkat(&staging.descriptor, name.as_str(), AtFlags::empty()).is_err() {
                drop(descriptor);
                return Err(state_unavailable(operation));
            }
            rustix::fs::fallocate(&descriptor, FallocateFlags::empty(), 0, total_len)
                .map_err(classify_fallocate_error)?;
            return Ok(std::fs::File::from(descriptor));
        }
        Err(state_unavailable(operation))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (staging, total_len);
        Err(state_unavailable(PublicOperation::PublishBlob))
    }
}

#[cfg(target_os = "linux")]
fn classify_fallocate_error(error: rustix::io::Errno) -> ConnectError {
    match error {
        rustix::io::Errno::NOSPC | rustix::io::Errno::DQUOT => {
            resource_exhausted(PublicOperation::PublishBlob)
        }
        rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL => {
            public_error(
                ErrorCode::FailedPrecondition,
                api::PublicErrorReason::UnsupportedValue,
                PublicOperation::PublishBlob,
                false,
                None,
            )
        }
        _ => state_unavailable(PublicOperation::PublishBlob),
    }
}

fn malformed(operation: PublicOperation) -> ConnectError {
    public_error(
        ErrorCode::InvalidArgument,
        api::PublicErrorReason::MalformedInput,
        operation,
        false,
        None,
    )
}

fn unsupported_value(operation: PublicOperation) -> ConnectError {
    public_error(
        ErrorCode::InvalidArgument,
        api::PublicErrorReason::UnsupportedValue,
        operation,
        false,
        None,
    )
}

fn unsupported_transport(operation: PublicOperation) -> ConnectError {
    public_error(
        ErrorCode::Unimplemented,
        api::PublicErrorReason::UnsupportedValue,
        operation,
        false,
        None,
    )
}

fn resource_exhausted(operation: PublicOperation) -> ConnectError {
    public_error(
        ErrorCode::ResourceExhausted,
        api::PublicErrorReason::ResourceExhaustion,
        operation,
        true,
        None,
    )
}

fn state_unavailable(operation: PublicOperation) -> ConnectError {
    public_error(
        ErrorCode::Unavailable,
        api::PublicErrorReason::StateUnavailable,
        operation,
        true,
        None,
    )
}

fn internal(operation: PublicOperation) -> ConnectError {
    public_error(
        ErrorCode::DataLoss,
        api::PublicErrorReason::Internal,
        operation,
        false,
        None,
    )
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(target_os = "linux")]
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    #[cfg(target_os = "linux")]
    use aster_mesh::{ProvisioningAccess, ReferenceProvisioner};
    use aster_node::application::{MAX_SELECTED_BLOB_PAGE_BYTES, MAX_SELECTED_LIVE_BLOB_BYTES};
    #[cfg(target_os = "linux")]
    use aster_node::mission::UnprotectedReferenceMission;
    #[cfg(target_os = "linux")]
    use aster_node::{MutableSourceInterests, NodeApplication, NodeConfig, start_node};
    use buffa::Message as _;
    use connectrpc::ErrorCode;
    use tokio::sync::{Notify, Semaphore};

    use super::*;
    use crate::api;

    #[cfg(target_os = "linux")]
    static NEXT_STAGING_TEST: AtomicU64 = AtomicU64::new(0);

    #[cfg(target_os = "linux")]
    struct StagingTestRoot(PathBuf);

    #[cfg(target_os = "linux")]
    impl StagingTestRoot {
        fn new() -> Self {
            let sequence = NEXT_STAGING_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aster-agent-staging-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for StagingTestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn metadata(total_len: u64, ttl_ms: Option<u64>) -> api::PublishBlobMetadata {
        api::PublishBlobMetadata {
            operation_key: b"blob-operation".to_vec(),
            topic: "imagery.maps".to_owned(),
            scope: "mission/team/alpha".to_owned(),
            priority: api::Priority::Immediate.into(),
            media_type: Some("image/octet-stream".to_owned()),
            schema_id: b"schema-v1".to_vec(),
            total_len,
            ttl_ms,
            ..Default::default()
        }
    }

    fn metadata_frame(total_len: u64, ttl_ms: Option<u64>) -> api::PublishBlobRequest {
        api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                metadata(total_len, ttl_ms),
            ))),
            ..Default::default()
        }
    }

    fn start_upload(
        first: api::PublishBlobRequest,
    ) -> Result<(ParsedPublish, UploadGrammar), ConnectError> {
        UploadGrammar::start(first, MAX_SELECTED_LIVE_BLOB_BYTES)
    }

    fn chunk(offset: u64, bytes: Vec<u8>) -> api::PublishBlobRequest {
        api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Data(Box::new(
                api::PublishBlobData {
                    offset,
                    bytes,
                    ..Default::default()
                },
            ))),
            ..Default::default()
        }
    }

    #[test]
    fn blob_ttl_wire_presence_round_trips_and_zero_is_rejected() {
        let durable = metadata_frame(1, None);
        let durable = api::PublishBlobRequest::decode_from_slice(&durable.encode_to_vec()).unwrap();
        let (durable, _) = start_upload(durable).unwrap();
        assert_eq!(durable.options.ttl_ms(), None);

        let finite = metadata_frame(1, Some(u64::MAX));
        let finite = api::PublishBlobRequest::decode_from_slice(&finite.encode_to_vec()).unwrap();
        let (finite, _) = start_upload(finite).unwrap();
        assert_eq!(finite.options.ttl_ms(), Some(u64::MAX));

        let error = start_upload(metadata_frame(1, Some(0))).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn blob_upload_requires_one_metadata_frame_before_chunks() {
        assert_eq!(
            start_upload(api::PublishBlobRequest::default())
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            start_upload(chunk(0, vec![1])).unwrap_err().code,
            ErrorCode::InvalidArgument
        );

        let (_, mut grammar) = start_upload(metadata_frame(1, None)).unwrap();
        assert_eq!(
            grammar.accept(metadata_frame(1, None)).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn blob_upload_rejects_empty_oversized_and_length_mismatched_streams() {
        assert_eq!(
            start_upload(metadata_frame(0, None)).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            start_upload(metadata_frame(MAX_SELECTED_LIVE_BLOB_BYTES + 1, None))
                .unwrap_err()
                .code,
            ErrorCode::ResourceExhausted
        );

        let (_, mut empty_chunk) = start_upload(metadata_frame(1, None)).unwrap();
        assert_eq!(
            empty_chunk.accept(chunk(0, Vec::new())).unwrap_err().code,
            ErrorCode::InvalidArgument
        );

        let (_, mut oversized_chunk) = start_upload(metadata_frame(
            (MAX_SELECTED_BLOB_PAGE_BYTES + 1) as u64,
            None,
        ))
        .unwrap();
        assert_eq!(
            oversized_chunk
                .accept(chunk(0, vec![0; MAX_SELECTED_BLOB_PAGE_BYTES + 1]))
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );

        let (_, short) = start_upload(metadata_frame(2, None)).unwrap();
        assert_eq!(short.finish().unwrap_err().code, ErrorCode::InvalidArgument);

        let (_, mut long) = start_upload(metadata_frame(1, None)).unwrap();
        assert_eq!(
            long.accept(chunk(0, vec![1, 2])).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn blob_upload_resumes_only_from_canonical_durable_offsets() {
        let total = BLOB_RPC_FRAME_BYTES as u64 * 2 + 1;
        let (_, grammar) = start_upload(metadata_frame(total, None)).unwrap();
        let mut grammar = grammar.resume(BLOB_RPC_FRAME_BYTES as u64).unwrap();
        assert_eq!(grammar.received, BLOB_RPC_FRAME_BYTES as u64);
        assert_eq!(grammar.frames, 1);
        assert_eq!(
            grammar
                .accept(chunk(0, vec![0; BLOB_RPC_FRAME_BYTES]))
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        grammar
            .accept(chunk(
                BLOB_RPC_FRAME_BYTES as u64,
                vec![0; BLOB_RPC_FRAME_BYTES],
            ))
            .unwrap();
        grammar
            .accept(chunk(BLOB_RPC_FRAME_BYTES as u64 * 2, vec![0]))
            .unwrap();
        grammar.finish().unwrap();

        let (_, grammar) = start_upload(metadata_frame(total, None)).unwrap();
        assert_eq!(grammar.resume(1).unwrap_err().code, ErrorCode::DataLoss);
    }

    #[test]
    fn blob_upload_admission_uses_the_live_profile_capacity() {
        let configured_max = 2 * 1024 * 1024 * 1024;
        let declared = 800 * 1024 * 1024;

        UploadGrammar::start(metadata_frame(declared, None), configured_max)
            .expect("profile-5 upload below the configured live capacity");
        assert_eq!(
            UploadGrammar::start(metadata_frame(configured_max + 1, None), configured_max)
                .unwrap_err()
                .code,
            ErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn finite_upload_admission_preserves_retained_and_configured_limits() {
        let configured_max = MAX_SELECTED_LIVE_BLOB_BYTES + 1;
        UploadGrammar::start(metadata_frame(configured_max, None), configured_max)
            .expect("durable stream may use the larger configured capacity");
        assert_eq!(
            UploadGrammar::start(metadata_frame(configured_max, Some(1_000)), configured_max)
                .unwrap_err()
                .code,
            ErrorCode::ResourceExhausted,
        );
        assert_eq!(
            UploadGrammar::start(metadata_frame(2, Some(1_000)), 1)
                .unwrap_err()
                .code,
            ErrorCode::ResourceExhausted,
        );
        UploadGrammar::start(metadata_frame(1, Some(1_000)), 1)
            .expect("finite upload respects both bounds");
    }

    #[test]
    fn blob_upload_derives_frame_bound_from_declared_u64_length() {
        let declared = BLOB_RPC_FRAME_BYTES as u64 * 1_025;
        assert_eq!(maximum_chunk_frames_for_len(declared).unwrap(), 1_025);
    }

    #[test]
    fn read_page_response_carries_complete_stable_publication_metadata() {
        let metadata = ReadMetadata {
            id: [0x11; 32],
            publisher: [0x22; 32],
            publisher_counter: 7,
            topic: "imagery.maps".to_owned(),
            scope: "mission/team/alpha".to_owned(),
            priority: aster_node::application::Priority::Immediate,
            ttl_ms: Some(u64::MAX),
            total_len: 3,
            media_type: Some("image/octet-stream".to_owned()),
            schema_id: b"schema-v1".to_vec(),
            acceptance_marker: 9,
        };
        let response = read_response(&metadata, 1, vec![0xbb, 0xcc], true);
        assert_eq!(response.id, vec![0x11; 32]);
        assert_eq!(response.publisher, vec![0x22; 32]);
        assert_eq!(response.publisher_counter, 7);
        assert_eq!(response.topic, "imagery.maps");
        assert_eq!(response.scope, "mission/team/alpha");
        assert_eq!(response.priority, api::Priority::Immediate);
        assert_eq!(response.ttl_ms, Some(u64::MAX));
        assert_eq!(response.total_len, 3);
        assert_eq!(response.media_type.as_deref(), Some("image/octet-stream"));
        assert_eq!(response.schema_id, b"schema-v1");
        assert_eq!(response.acceptance_marker, 9);
        assert_eq!(response.offset, 1);
        assert_eq!(response.chunk, [0xbb, 0xcc]);
        assert!(response.complete);

        let mut changed = metadata.clone();
        changed.acceptance_marker = 10;
        assert_eq!(
            ensure_stable_read_metadata(&metadata, &changed)
                .unwrap_err()
                .code,
            ErrorCode::DataLoss
        );
    }

    #[tokio::test]
    async fn cancelled_handler_keeps_upload_permit_until_node_operation_finishes() {
        let uploads = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&uploads).try_acquire_owned().unwrap();
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let operation_entered = Arc::clone(&entered);
        let operation_release = Arc::clone(&release);
        let handler = tokio::spawn(await_upload_with_permit(permit, async move {
            operation_entered.notify_one();
            operation_release.notified().await;
        }));

        entered.notified().await;
        handler.abort();
        assert!(handler.await.unwrap_err().is_cancelled());
        assert!(
            Arc::clone(&uploads).try_acquire_owned().is_err(),
            "a cancelled handler must not release capacity while the node operation is live"
        );

        release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if Arc::clone(&uploads).try_acquire_owned().is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("node completion releases upload capacity");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_writer_reports_the_final_write_failure_before_releasing_capacity() {
        let uploads = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&uploads).try_acquire_owned().unwrap();
        let file = fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        let (commands, receiver) = tokio::sync::mpsc::channel(1);
        let task = tokio::task::spawn_blocking(move || run_blocking_writer(file, permit, receiver));
        let (completed, result) = tokio::sync::oneshot::channel();
        commands
            .send(WriterCommand::Write(Zeroizing::new(vec![0x5a]), completed))
            .await
            .unwrap();

        assert!(result.await.unwrap().is_err());
        assert!(Arc::clone(&uploads).try_acquire_owned().is_err());
        drop(commands);
        task.await.unwrap();
        assert!(Arc::clone(&uploads).try_acquire_owned().is_ok());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_blocking_write_keeps_capacity_until_current_io_and_cleanup_finish() {
        use std::os::fd::AsRawFd as _;

        let uploads = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&uploads).try_acquire_owned().unwrap();
        let fixture = StagingTestRoot::new();
        let file_path = fixture.0.join("writer-cleanup");
        let file = fs::File::create(&file_path).unwrap();
        let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        let (commands, receiver) = tokio::sync::mpsc::channel(1);
        let task = tokio::task::spawn_blocking(move || run_blocking_writer(file, permit, receiver));
        let (completed, _result) = tokio::sync::oneshot::channel();
        commands
            .send(WriterCommand::Write(Zeroizing::new(vec![0x7b]), completed))
            .await
            .unwrap();

        assert!(Arc::clone(&uploads).try_acquire_owned().is_err());
        assert!(descriptor_path.exists());
        drop(commands);
        let reacquired = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if descriptor_path.exists() {
                    assert!(Arc::clone(&uploads).try_acquire_owned().is_err());
                    tokio::task::yield_now().await;
                    continue;
                }
                if let Ok(permit) = Arc::clone(&uploads).try_acquire_owned() {
                    break permit;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("writer cleanup deadline");
        task.await.unwrap();
        drop(reacquired);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fallocate_failures_distinguish_capacity_from_unsupported_filesystems() {
        assert_eq!(
            classify_fallocate_error(rustix::io::Errno::NOSPC).code,
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            classify_fallocate_error(rustix::io::Errno::DQUOT).code,
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            classify_fallocate_error(rustix::io::Errno::OPNOTSUPP).code,
            ErrorCode::FailedPrecondition
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn staging_uses_pinned_directory_after_configured_path_is_replaced() {
        use std::os::fd::AsRawFd as _;

        let fixture = StagingTestRoot::new();
        let configured = fixture.0.join("configured");
        let pinned_location = fixture.0.join("pinned");
        let redirect = fixture.0.join("redirect");
        fs::create_dir(&configured).unwrap();
        fs::create_dir(&redirect).unwrap();
        let staging = PinnedStagingDirectory::open(&configured).unwrap();

        fs::rename(&configured, &pinned_location).unwrap();
        symlink(&redirect, &configured).unwrap();

        let file = open_private_staging(&staging, 4096).unwrap();
        let metadata = file.metadata().unwrap();
        let descriptor_target =
            fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
        assert_eq!(metadata.len(), 4096);
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert!(
            descriptor_target.starts_with(&pinned_location),
            "the anonymous staging inode must belong to the pinned directory"
        );
        assert!(
            fs::read_dir(&pinned_location).unwrap().next().is_none(),
            "the pinned directory must not retain a linked staging name"
        );
        assert!(
            fs::read_dir(&redirect).unwrap().next().is_none(),
            "path replacement must not redirect staging"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn staging_accepts_a_configured_symlink_but_pins_its_exact_target() {
        let fixture = StagingTestRoot::new();
        let target = fixture.0.join("target");
        let configured = fixture.0.join("configured");
        let replacement = fixture.0.join("replacement");
        fs::create_dir(&target).unwrap();
        fs::create_dir(&replacement).unwrap();
        symlink(&target, &configured).unwrap();

        let staging = PinnedStagingDirectory::open(&configured).unwrap();
        fs::remove_file(&configured).unwrap();
        symlink(&replacement, &configured).unwrap();

        let file = open_private_staging(&staging, 4096).unwrap();
        assert_eq!(
            file.metadata().unwrap().dev(),
            fs::metadata(&target).unwrap().dev()
        );
        assert!(fs::read_dir(&replacement).unwrap().next().is_none());
    }

    #[test]
    fn rpc_blob_frame_size_is_a_stable_agent_contract() {
        assert_eq!(crate::BLOB_RPC_FRAME_BYTES, 64 * 1024);
        assert_eq!(crate::BLOB_RPC_READ_FRAME_BYTES, 1024 * 1024);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn staging_reserves_real_blocks_before_upload_bytes_are_accepted() {
        let fixture = StagingTestRoot::new();
        let staging = PinnedStagingDirectory::open(&fixture.0).unwrap();
        let total_len = 1024 * 1024;
        let file = open_private_staging(&staging, total_len).unwrap();
        let metadata = file.metadata().unwrap();
        assert_eq!(metadata.len(), total_len);
        assert!(
            metadata.blocks() * 512 >= total_len,
            "staging reservation must allocate blocks rather than create a sparse extent"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lazy_read_reauthenticates_expiry_between_pages() {
        let fixture = StagingTestRoot::new();
        let state_root = fixture.0.join("state");
        fs::create_dir(&state_root).unwrap();
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).unwrap();
        let access = ProvisioningAccess::member(
            Scope::new("mission/team/alpha").unwrap(),
            vec![1],
            vec![Topic::new("imagery.maps").unwrap()],
        )
        .unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0xb8; 32]).unwrap();
        let mission = UnprotectedReferenceMission::from_bytes(
            provisioner
                .issue_node(1, &[access])
                .unwrap()
                .to_bytes()
                .unwrap(),
        )
        .unwrap();
        let node = start_node(NodeConfig {
            state: state_root.clone(),
            bind: "127.0.0.1:0".parse().unwrap(),
            mission,
            peers: Vec::new(),
            mutable_interests: MutableSourceInterests::default(),
            sync_interval: std::time::Duration::from_millis(50),
            run_for: None,
            application: NodeApplication::Relay,
        })
        .await
        .unwrap();
        let blobs = node.selected_blobs();
        let source_path = fixture.0.join("source.bin");
        fs::write(&source_path, vec![0x5c; MAX_SELECTED_BLOB_PAGE_BYTES + 1]).unwrap();
        let publication = blobs
            .publish_with_options(
                NodeBlobPublishRequest {
                    operation_key: b"lazy-expiry".to_vec(),
                    topic: Topic::new("imagery.maps").unwrap(),
                    scope: Scope::new("mission/team/alpha").unwrap(),
                    priority: Priority::Routine,
                    media_type: None,
                    schema_id: Vec::new(),
                },
                BlobPublishOptions::finite_ttl_ms(10_000).unwrap(),
                fs::File::open(source_path).unwrap(),
            )
            .await
            .unwrap();
        let service = BlobConnectService::new(blobs, &state_root).unwrap();
        let mut stream = service
            .read(api::ReadBlobRequest {
                id: publication.id.as_bytes().to_vec(),
                topic: "imagery.maps".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                ..Default::default()
            })
            .await
            .unwrap()
            .body;
        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.offset, 0);
        assert_eq!(first.chunk.len(), MAX_SELECTED_BLOB_PAGE_BYTES);
        assert!(!first.complete);

        tokio::time::sleep(std::time::Duration::from_millis(10_100)).await;
        let expired = stream.next().await.unwrap().unwrap_err();
        assert_eq!(expired.code, ErrorCode::NotFound);
        assert_eq!(
            expired.message.as_deref(),
            Some("durable object expired or was retired")
        );

        node.shutdown().await.unwrap();
    }
}
