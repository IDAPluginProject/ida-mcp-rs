//! MCP framing and save-first stdio shutdown safeguards.

mod public_stdio;

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rmcp::model::{
    CallToolResult, ContentBlock, ErrorData, GetExtensions, JsonRpcMessage, RequestId,
    ServerJsonRpcMessage, ServerResult,
};
use rmcp::service::{RoleServer, RxJsonRpcMessage, TxJsonRpcMessage};
use rmcp::transport::async_rw::{AsyncRwTransport, DEFAULT_MAX_LINE_LENGTH};
use rmcp::transport::{stdio_pipes, Transport};
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use tokio_util::task::task_tracker::TaskTrackerToken;
use tokio_util::task::TaskTracker;

pub(crate) const MAX_MESSAGE_BYTES: usize = DEFAULT_MAX_LINE_LENGTH;

pub(crate) fn message_limit_label() -> String {
    const MIB: usize = 1024 * 1024;
    if MAX_MESSAGE_BYTES.is_multiple_of(MIB) {
        format!("{} MiB", MAX_MESSAGE_BYTES / MIB)
    } else {
        format!("{MAX_MESSAGE_BYTES} bytes")
    }
}

fn large_reply_message() -> String {
    format!(
        "The reply exceeds the {} MCP message limit. \
         The operation may already have changed the database. Request less data, or inspect \
         the database before retrying an edit.",
        message_limit_label()
    )
}

const COMPACT_LARGE_REPLY: &str = "Reply too large; the operation may have changed the database";

fn compact_reply_error(id: Option<RequestId>) -> ServerJsonRpcMessage {
    ServerJsonRpcMessage::error(ErrorData::internal_error(COMPACT_LARGE_REPLY, None), id)
}

fn response_id_fits(id: &RequestId, max_line_length: usize) -> Result<bool, serde_json::Error> {
    frame_fits_with_limit(&compact_reply_error(Some(id.clone())), max_line_length)
}

struct FrameBudget {
    remaining: usize,
    exceeded: bool,
}

impl Write for FrameBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(remaining) = self.remaining.checked_sub(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("MCP frame exceeds its size limit"));
        };
        self.remaining = remaining;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Count the actual JSON representation, including the terminating newline,
/// without allocating another copy of an externally sized message.
pub(crate) fn frame_fits(value: &impl Serialize) -> Result<bool, serde_json::Error> {
    frame_fits_with_limit(value, MAX_MESSAGE_BYTES)
}

fn frame_fits_with_limit(
    value: &impl Serialize,
    max_line_length: usize,
) -> Result<bool, serde_json::Error> {
    let Some(remaining) = max_line_length.checked_sub(1) else {
        return Ok(false);
    };
    let mut budget = FrameBudget {
        remaining,
        exceeded: false,
    };
    match serde_json::to_writer(&mut budget, value) {
        Ok(()) => Ok(true),
        Err(_) if budget.exceeded => Ok(false),
        Err(error) => Err(error),
    }
}

fn bounded_reply(message: ServerJsonRpcMessage) -> io::Result<ServerJsonRpcMessage> {
    if frame_fits(&message).map_err(io::Error::other)? {
        return Ok(message);
    }
    let explanation = large_reply_message();
    let replacement = match message {
        JsonRpcMessage::Response(response) => {
            if let ServerResult::CallToolResult(original) = response.result {
                let mut result = CallToolResult::error(vec![ContentBlock::text(explanation)]);
                // A real native crash must still retire the worker even if its original
                // error result was too large. Ordinary script text cannot set this marker.
                if crate::ida::remote::is_sdk_crash(&original) {
                    crate::ida::remote::mark_sdk_crashed(&mut result);
                }
                ServerJsonRpcMessage::response(ServerResult::CallToolResult(result), response.id)
            } else {
                ServerJsonRpcMessage::error(
                    ErrorData::internal_error(explanation, None),
                    Some(response.id),
                )
            }
        }
        JsonRpcMessage::Error(mut original) => {
            // Dropping diagnostic data often suffices. A protocol error is
            // already a settled outcome; preserve its code and explanation.
            original.error.data = None;
            if frame_fits(&original).map_err(io::Error::other)? {
                return Ok(JsonRpcMessage::Error(original));
            }
            original.error.message = "Error response too large".into();
            if frame_fits(&original).map_err(io::Error::other)? {
                return Ok(JsonRpcMessage::Error(original));
            }
            return Err(io::Error::other("Response ID exceeds the MCP size limit"));
        }
        // rmcp reports these send errors to the local caller without closing
        // the service. Neither message is a reply to a parent request.
        JsonRpcMessage::Request(_) | JsonRpcMessage::Notification(_) => {
            return Err(io::Error::other(
                "IDA worker message exceeds the MCP size limit",
            ));
        }
    };
    if frame_fits(&replacement).map_err(io::Error::other)? {
        return Ok(replacement);
    }
    let id = match replacement {
        JsonRpcMessage::Response(response) => Some(response.id),
        JsonRpcMessage::Error(error) => error.id,
        JsonRpcMessage::Request(_) | JsonRpcMessage::Notification(_) => {
            return Err(io::Error::other("invalid oversized-reply replacement"));
        }
    };
    let compact = compact_reply_error(id);
    if frame_fits(&compact).map_err(io::Error::other)? {
        Ok(compact)
    } else {
        Err(io::Error::other("Response ID exceeds the MCP size limit"))
    }
}

struct BoundedTransport<T>(T);

impl<T> Transport<RoleServer> for BoundedTransport<T>
where
    T: Transport<RoleServer, Error = io::Error>,
{
    type Error = io::Error;

    fn send(
        &mut self,
        message: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = io::Result<()>> + Send + 'static {
        let send = bounded_reply(message).map(|message| self.0.send(message));
        async move {
            match send {
                Ok(send) => send.await,
                Err(error) => Err(error),
            }
        }
    }

    fn receive(&mut self) -> impl Future<Output = Option<RxJsonRpcMessage<RoleServer>>> + Send {
        self.0.receive()
    }

    fn close(&mut self) -> impl Future<Output = io::Result<()>> + Send {
        self.0.close()
    }
}

/// Use rmcp's bounded reader and replace oversized private replies before
/// the parent can discard them and mistake a healthy worker for a stuck one.
pub fn worker_stdio() -> impl Transport<RoleServer, Error = io::Error> + 'static {
    let (read, write) = stdio_pipes();
    BoundedTransport(AsyncRwTransport::new(read, write))
}

/// Coordinates public stdio termination with save-first database shutdown.
#[derive(Clone)]
pub struct StdioShutdown {
    armed: Arc<AtomicBool>,
    closed: CancellationToken,
    saved: CancellationToken,
    requests: TaskTracker,
}

/// Travels in rmcp's non-serialized request extensions and then its handler
/// context, so cancellation/rejection also settles the received request.
#[derive(Clone)]
pub(crate) struct PendingStdioRequest {
    _token: TaskTrackerToken,
    shutdown: CancellationToken,
}

impl PendingStdioRequest {
    pub(crate) fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }
}

impl StdioShutdown {
    fn new() -> Self {
        Self {
            armed: Arc::new(AtomicBool::new(false)),
            closed: CancellationToken::new(),
            saved: CancellationToken::new(),
            requests: TaskTracker::new(),
        }
    }

    /// Arm immediately after successful negotiation, before another await.
    /// The public current-thread runtimes cannot poll rmcp's newly spawned
    /// service task before this call.
    pub fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }

    /// Wait for stdin EOF or a failed write to the client.
    pub async fn closed(&self) {
        self.closed.cancelled().await;
    }

    /// Allow rmcp to observe termination after database shutdown has settled.
    pub fn release(&self) {
        self.saved.cancel();
    }

    /// Stop accepting input and wait for requests already handed to rmcp.
    /// Main includes this wait in the overall supervised-shutdown deadline.
    pub async fn drain(&self) {
        self.closed.cancel();
        self.requests.close();
        self.requests.wait().await;
    }

    async fn after_terminal_event(&self) {
        self.closed.cancel();
        if self.armed.load(Ordering::Acquire) {
            self.saved.cancelled().await;
        }
    }
}

struct SaveFirstTransport<T> {
    inner: T,
    shutdown: StdioShutdown,
}

impl<T> SaveFirstTransport<T> {
    fn new(inner: T) -> (Self, StdioShutdown) {
        let shutdown = StdioShutdown::new();
        (
            Self {
                inner,
                shutdown: shutdown.clone(),
            },
            shutdown,
        )
    }
}

impl<T> Transport<RoleServer> for SaveFirstTransport<T>
where
    T: Transport<RoleServer, Error = io::Error>,
{
    type Error = io::Error;

    fn send(
        &mut self,
        message: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = io::Result<()>> + Send + 'static {
        let send = self.inner.send(message);
        let shutdown = self.shutdown.clone();
        async move {
            let result = send.await;
            if result.is_err() {
                shutdown.after_terminal_event().await;
            }
            result
        }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        let message = tokio::select! {
            biased;
            () = self.shutdown.closed() => None,
            message = self.inner.receive() => message,
        };
        let Some(mut message) = message else {
            self.shutdown.after_terminal_event().await;
            return None;
        };
        // Acquire the token before checking the terminal flag. If drain races
        // this poll, it either sees the token or this request is never handed
        // to rmcp. No await may separate this check from returning the message.
        let guard = PendingStdioRequest {
            _token: self.shutdown.requests.token(),
            shutdown: self.shutdown.closed.clone(),
        };
        if self.shutdown.closed.is_cancelled() {
            drop(guard);
            self.shutdown.after_terminal_event().await;
            return None;
        }
        if let JsonRpcMessage::Request(request) = &mut message {
            request.request.extensions_mut().insert(guard);
        }
        Some(message)
    }

    fn close(&mut self) -> impl Future<Output = io::Result<()>> + Send {
        self.inner.close()
    }
}

/// Give main a chance to save before rmcp's terminal-event handling cancels
/// in-flight request contexts.
pub fn supervised_stdio() -> (
    impl Transport<RoleServer, Error = io::Error> + 'static,
    StdioShutdown,
) {
    let (read, write) = stdio_pipes();
    supervise(public_stdio::transport(read, write))
}

fn supervise<T>(inner: T) -> (BoundedTransport<SaveFirstTransport<T>>, StdioShutdown) {
    let (transport, shutdown) = SaveFirstTransport::new(inner);
    // Size rejection is local validation. Only actual writes reach the
    // save-first wrapper and can signal that the client connection failed.
    (BoundedTransport(transport), shutdown)
}

#[cfg(test)]
mod tests {
    use crate::transport::{
        bounded_reply, compact_reply_error, frame_fits, frame_fits_with_limit, response_id_fits,
        supervise, SaveFirstTransport,
    };
    use rmcp::model::{
        CallToolResult, ContentBlock, ErrorCode, ErrorData, JsonRpcMessage, RequestId,
        ServerJsonRpcMessage, ServerResult,
    };
    use rmcp::transport::async_rw::{AsyncRwTransport, DEFAULT_MAX_LINE_LENGTH};
    use rmcp::transport::Transport;
    use serde_json::json;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn frame_budget_counts_json_escaping_and_the_newline() {
        let value = json!({"text": "\0\"\\é", "id": i64::MIN});
        let length = serde_json::to_vec(&value).expect("JSON").len() + 1;
        assert!(frame_fits_with_limit(&value, length).expect("fits"));
        assert!(!frame_fits_with_limit(&value, length - 1).expect("too large"));
        assert!(!frame_fits_with_limit(&value, 0).expect("empty budget"));
    }

    #[test]
    fn oversized_reply_preserves_correlation_and_native_crash_status() {
        let mut result = CallToolResult::error(vec![ContentBlock::text(
            "\0".repeat(DEFAULT_MAX_LINE_LENGTH / 6),
        )]);
        crate::ida::remote::mark_sdk_crashed(&mut result);
        let message = ServerJsonRpcMessage::response(
            ServerResult::CallToolResult(result),
            RequestId::Number(i64::MIN),
        );
        assert!(!frame_fits(&message).expect("count original"));
        let bounded = bounded_reply(message).expect("bounded reply");
        assert!(frame_fits(&bounded).expect("count replacement"));
        let JsonRpcMessage::Response(response) = bounded else {
            panic!("expected a correlated response");
        };
        assert_eq!(response.id, RequestId::Number(i64::MIN));
        let ServerResult::CallToolResult(result) = response.result else {
            panic!("expected an in-band tool error");
        };
        assert_eq!(result.is_error, Some(true));
        assert!(crate::ida::remote::sdk_crash(&result, "test").is_some());
    }

    #[test]
    fn oversized_protocol_error_preserves_correlation() {
        let message = ServerJsonRpcMessage::error(
            ErrorData::invalid_params(
                "invalid argument",
                Some(json!("\0".repeat(DEFAULT_MAX_LINE_LENGTH / 6))),
            ),
            Some(RequestId::Number(i64::MIN)),
        );
        assert!(!frame_fits(&message).expect("count original"));
        let bounded = bounded_reply(message).expect("bounded error");
        assert!(frame_fits(&bounded).expect("count replacement"));
        let JsonRpcMessage::Error(error) = bounded else {
            panic!("expected a correlated protocol error");
        };
        assert_eq!(error.id, Some(RequestId::Number(i64::MIN)));
        assert_eq!(error.error.code, ErrorCode::INVALID_PARAMS);
        assert_eq!(error.error.message, "invalid argument");
        assert!(error.error.data.is_none());
    }

    #[test]
    fn compact_protocol_error_keeps_its_original_code() {
        let message = ServerJsonRpcMessage::error(
            ErrorData::invalid_params("x".repeat(DEFAULT_MAX_LINE_LENGTH), None),
            Some(RequestId::Number(7)),
        );
        let JsonRpcMessage::Error(error) = bounded_reply(message).expect("compact error") else {
            panic!("expected protocol error");
        };
        assert_eq!(error.id, Some(RequestId::Number(7)));
        assert_eq!(error.error.code, ErrorCode::INVALID_PARAMS);
        assert_eq!(error.error.message, "Error response too large");
    }

    #[tokio::test]
    async fn local_outgoing_rejections_do_not_close_public_stdio() {
        let (mut input, read) = tokio::io::duplex(1024);
        let (mut transport, shutdown) = supervise(AsyncRwTransport::new(read, tokio::io::sink()));
        shutdown.arm();
        for message in [
            json!({"jsonrpc":"2.0","method":"notifications/message",
                "params":{"level":"info","data":"x".repeat(DEFAULT_MAX_LINE_LENGTH)}}),
            json!({"jsonrpc":"2.0","id":7,"method":"elicitation/create",
                "params":{"mode":"form","message":"x".repeat(DEFAULT_MAX_LINE_LENGTH),
                    "requestedSchema":{"type":"object","properties":{}}}}),
        ] {
            let message = serde_json::from_value(message).expect("server message");
            assert!(
                tokio::time::timeout(Duration::from_secs(1), transport.send(message))
                    .await
                    .expect("local rejection must not wait for shutdown")
                    .is_err()
            );
            assert!(!shutdown.closed.is_cancelled());
        }
        input
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"ping\"}\n")
            .await
            .expect("next request");
        let Some(JsonRpcMessage::Request(next)) = transport.receive().await else {
            panic!("session remains open");
        };
        assert_eq!(next.id, RequestId::Number(8));
    }

    #[test]
    fn long_response_id_uses_the_compact_correlated_error() {
        let empty = RequestId::String("".into());
        let overhead = serde_json::to_vec(&compact_reply_error(Some(empty)))
            .expect("compact error")
            .len()
            + 1;
        let id = RequestId::String("x".repeat(DEFAULT_MAX_LINE_LENGTH - overhead).into());
        assert!(response_id_fits(&id, DEFAULT_MAX_LINE_LENGTH).expect("ID fits"));
        let message = ServerJsonRpcMessage::response(
            ServerResult::CallToolResult(CallToolResult::success(vec![ContentBlock::text(
                "x".repeat(1024),
            )])),
            id.clone(),
        );
        let bounded = bounded_reply(message).expect("compact fallback");
        assert!(frame_fits(&bounded).expect("bounded fallback"));
        let JsonRpcMessage::Error(error) = bounded else {
            panic!("expected compact error")
        };
        assert_eq!(error.id, Some(id));
    }

    #[tokio::test]
    async fn terminal_events_wait_for_save_only_after_negotiation() {
        let (mut early, _) =
            SaveFirstTransport::new(AsyncRwTransport::new(tokio::io::empty(), tokio::io::sink()));
        assert!(early.receive().await.is_none());

        let (mut transport, shutdown) =
            SaveFirstTransport::new(AsyncRwTransport::new(tokio::io::empty(), tokio::io::sink()));
        shutdown.arm();
        let receive = tokio::spawn(async move { transport.receive().await });
        tokio::time::timeout(Duration::from_secs(1), shutdown.closed())
            .await
            .expect("EOF reported to main");
        assert!(!receive.is_finished());
        shutdown.release();
        assert!(receive.await.expect("receive task").is_none());
    }

    #[tokio::test]
    async fn failed_client_write_waits_for_save() {
        let (write, peer) = tokio::io::duplex(64);
        drop(peer);
        let (mut transport, shutdown) =
            SaveFirstTransport::new(AsyncRwTransport::new(tokio::io::empty(), write));
        shutdown.arm();
        let send = tokio::spawn(transport.send(ServerJsonRpcMessage::response(
            ServerResult::CallToolResult(CallToolResult::success(vec![])),
            RequestId::Number(1),
        )));
        tokio::time::timeout(Duration::from_secs(1), shutdown.closed())
            .await
            .expect("write failure reported to main");
        assert!(!send.is_finished());
        shutdown.release();
        assert!(send.await.expect("send task").is_err());
    }

    #[tokio::test]
    async fn shutdown_drains_requests_already_handed_to_rmcp() {
        let (mut peer, read) = tokio::io::duplex(1024);
        let (mut transport, shutdown) =
            SaveFirstTransport::new(AsyncRwTransport::new(read, tokio::io::sink()));
        shutdown.arm();
        peer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
            .await
            .expect("write request");
        let request = transport.receive().await.expect("receive request");
        let retained = request.clone();
        let drain = tokio::spawn({
            let shutdown = shutdown.clone();
            async move { shutdown.drain().await }
        });
        tokio::task::yield_now().await;
        assert!(!drain.is_finished());
        drop(request);
        assert!(!drain.is_finished());
        drop(retained);
        tokio::time::timeout(Duration::from_secs(1), drain)
            .await
            .expect("drain completed")
            .expect("drain task");
        shutdown.release();
        assert!(transport.receive().await.is_none());
    }
}
