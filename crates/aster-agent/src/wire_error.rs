//! Sanitizes framework error messages at the encoded response boundary.
//!
//! ConnectRPC 0.9 emits terminal envelopes as complete, separate body frames.
//! Message payloads may span frames; count their bytes without inspecting or
//! buffering them. Only terminal metadata and unary error JSON are rewritten.

use bytes::Bytes;
use connectrpc::ConnectRpcBody;
use http::{HeaderMap, Response};
use hyper::body::Frame;

#[derive(Default)]
pub(crate) struct WireErrors {
    unary_error: bool,
    terminal_flag: Option<u8>,
    payload_remaining: usize,
}

impl WireErrors {
    pub(crate) fn for_response(response: &mut Response<ConnectRpcBody>) -> Self {
        sanitize_grpc_headers(response.headers_mut());
        let protocol = connectrpc::Protocol::detect(response.headers());
        if protocol
            .as_ref()
            .is_some_and(|p| p.protocol == connectrpc::Protocol::Grpc)
            && matches!(
                response.body(),
                ConnectRpcBody::GrpcUnary(_) | ConnectRpcBody::Streaming(_)
            )
        {
            // ConnectRPC 0.9.1 emits authoritative terminal trailers for both
            // native gRPC body variants, but duplicates early errors' status
            // and message in initial headers without their typed details.
            // Its streaming client stops at those headers and loses details.
            // Keep terminal metadata together in the trailer. Full/unknown
            // bodies may have only headers, so retain their status unchanged.
            response.headers_mut().remove("grpc-status");
            response.headers_mut().remove("grpc-message");
            response.headers_mut().remove("grpc-status-details-bin");
        }
        Self {
            unary_error: !response.status().is_success(),
            terminal_flag: protocol.and_then(|p| match (p.protocol, p.is_streaming) {
                (connectrpc::Protocol::Connect, true) => Some(0x02),
                (connectrpc::Protocol::GrpcWeb, _) => Some(0x80),
                _ => None,
            }),
            payload_remaining: 0,
        }
    }

    pub(crate) fn frame(&mut self, mut frame: Frame<Bytes>) -> Frame<Bytes> {
        if let Some(headers) = frame.trailers_mut() {
            sanitize_grpc_headers(headers);
        }
        let Some(bytes) = frame.data_mut() else {
            return frame;
        };
        if self.unary_error {
            *bytes = sanitize_json(bytes, false);
        } else if let Some(flag) = self.terminal_flag {
            let mut offset = 0;
            while offset < bytes.len() {
                let skip = self.payload_remaining.min(bytes.len() - offset);
                self.payload_remaining -= skip;
                offset += skip;
                if offset == bytes.len() {
                    break;
                }
                // Only our pinned framework's output is inspected here. Its
                // encoder never splits the five-byte envelope header.
                if bytes.len() - offset < 5 {
                    break;
                }
                let length =
                    u32::from_be_bytes(bytes[offset + 1..offset + 5].try_into().unwrap()) as usize;
                if bytes[offset] == flag && length == bytes.len() - offset - 5 {
                    let terminal = &bytes[offset + 5..];
                    let sanitized = if flag == 0x02 {
                        sanitize_json(terminal, true)
                    } else {
                        sanitize_grpc_web(terminal)
                    };
                    let mut output = Vec::with_capacity(offset + 5 + sanitized.len());
                    output.extend_from_slice(&bytes[..offset]);
                    output.push(flag);
                    output.extend_from_slice(&(sanitized.len() as u32).to_be_bytes());
                    output.extend_from_slice(&sanitized);
                    *bytes = output.into();
                    break;
                }
                self.payload_remaining = length;
                offset += 5;
            }
        }
        frame
    }
}

fn sanitize_json(bytes: &[u8], streaming: bool) -> Bytes {
    let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        // Unknown framework error representation must fail closed.
        return if streaming {
            Bytes::from_static(
                br#"{"error":{"code":"internal","message":"internal service error"}}"#,
            )
        } else {
            Bytes::from_static(br#"{"code":"internal","message":"internal service error"}"#)
        };
    };
    let error = if streaming {
        json.get_mut("error")
    } else {
        Some(&mut json)
    };
    if let Some(error) = error
        && !error
            .get("message")
            .and_then(serde_json::Value::as_str)
            .is_some_and(crate::error::is_public_error_message)
    {
        error["message"] = "request failed".into();
        if let Some(object) = error.as_object_mut() {
            object.remove("details");
        }
    }
    serde_json::to_vec(&json)
        .expect("JSON value serialization")
        .into()
}

fn sanitize_grpc_headers(headers: &mut HeaderMap) {
    if headers.get("grpc-message").is_some_and(|value| {
        !value
            .to_str()
            .is_ok_and(crate::error::is_public_error_message)
    }) {
        headers.insert(
            "grpc-message",
            http::HeaderValue::from_static("request%20failed"),
        );
        // The framework also embeds its message in google.rpc.Status, even
        // without typed details. Remove that duplicate raw error chain.
        headers.remove("grpc-status-details-bin");
    }
}

fn sanitize_grpc_web(bytes: &[u8]) -> Bytes {
    let trailers = String::from_utf8_lossy(bytes);
    if trailers.lines().any(|line| {
        line.strip_prefix("grpc-message: ")
            .is_some_and(crate::error::is_public_error_message)
    }) {
        return Bytes::copy_from_slice(bytes);
    }
    let mut output = String::new();
    for line in trailers.lines() {
        if line.starts_with("grpc-status-details-bin:") {
            continue;
        }
        output.push_str(if line.starts_with("grpc-message:") {
            "grpc-message: request%20failed"
        } else {
            line
        });
        output.push_str("\r\n");
    }
    output.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use connectrpc::{ErrorCode, Router, ServiceStream};
    use http::Request;
    use http_body_util::{BodyExt as _, Full};
    use tower::ServiceExt as _;

    use crate::{
        api,
        error::{PublicOperation, public_error},
    };

    #[tokio::test]
    async fn early_grpc_router_errors_keep_typed_details_in_terminal_trailers() {
        let router = Router::new()
            .route(
                api::ASTER_APPLICATION_SERVICE_SERVICE_NAME,
                "GetStatus",
                connectrpc::handler_fn(|_ctx, _request: api::GetStatusRequest| async {
                    Err::<connectrpc::Response<api::GetStatusResponse>, _>(public_error(
                        ErrorCode::InvalidArgument,
                        api::PublicErrorReason::MalformedInput,
                        PublicOperation::Unspecified,
                        false,
                        None,
                    ))
                }),
            )
            .route_server_stream(
                api::ASTER_APPLICATION_SERVICE_SERVICE_NAME,
                "ReadBlob",
                connectrpc::streaming_handler_fn(|_ctx, _request: api::ReadBlobRequest| async {
                    Err::<connectrpc::Response<ServiceStream<api::ReadBlobResponse>>, _>(
                        public_error(
                            ErrorCode::NotFound,
                            api::PublicErrorReason::MissingDurableObject,
                            PublicOperation::ReadBlob,
                            false,
                            None,
                        ),
                    )
                }),
            );
        let service = crate::event_service::configured_service(router);
        for (method, status, message) in [
            ("GetStatus", "3", "request is malformed"),
            ("ReadBlob", "5", "durable object is unavailable"),
        ] {
            let mut response = service
                .clone()
                .oneshot(
                    Request::post(format!(
                        "/aster.application.v1alpha1.AsterApplicationService/{method}"
                    ))
                    .header(http::header::CONTENT_TYPE, "application/grpc+proto")
                    .body(Full::new(Bytes::from_static(&[0, 0, 0, 0, 0])))
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.headers()["grpc-status"], status);
            assert!(!response.headers().contains_key("grpc-status-details-bin"));
            let mut errors = WireErrors::for_response(&mut response);
            assert!(!response.headers().contains_key("grpc-status"));
            assert!(!response.headers().contains_key("grpc-message"));
            let collected = response.into_body().collect().await.unwrap();
            let trailers = collected.trailers().expect("authoritative status trailer");
            let frame = errors.frame(Frame::trailers(trailers.clone()));
            let sanitized = frame.trailers_ref().unwrap();
            assert_eq!(sanitized["grpc-status"], status);
            assert_eq!(sanitized["grpc-message"], message);
            assert!(sanitized.contains_key("grpc-status-details-bin"));
            assert_eq!(sanitized, trailers);
            assert!(collected.to_bytes().is_empty());
        }
    }

    #[test]
    fn header_only_grpc_errors_retain_their_only_status_source() {
        let mut response = Response::builder()
            .header(http::header::CONTENT_TYPE, "application/grpc+proto")
            .header("grpc-status", "3")
            .header("grpc-message", "request is malformed")
            .header("grpc-status-details-bin", "public-detail")
            .body(ConnectRpcBody::Full(Full::new(Bytes::new())))
            .unwrap();
        WireErrors::for_response(&mut response);
        assert_eq!(response.headers()["grpc-status"], "3");
        assert_eq!(response.headers()["grpc-message"], "request is malformed");
        assert_eq!(
            response.headers()["grpc-status-details-bin"],
            "public-detail"
        );
    }
}
