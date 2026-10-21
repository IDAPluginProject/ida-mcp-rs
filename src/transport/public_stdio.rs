//! Bounded public input that rejects oversized requests instead of dropping them.

use crate::transport::{frame_fits, message_limit_label, response_id_fits, MAX_MESSAGE_BYTES};
use bytes::BytesMut;
use rmcp::model::{ClientJsonRpcMessage, ErrorData, RequestId, ServerJsonRpcMessage};
use rmcp::service::{RoleServer, RxJsonRpcMessage, TxJsonRpcMessage};
use rmcp::transport::async_rw::{AsyncRwTransport, JsonRpcMessageCodec, JsonRpcMessageCodecError};
use rmcp::transport::Transport;
use serde::de::{Error as _, IgnoredAny, MapAccess, Visitor};
use serde::Deserializer as _;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader};
use tokio_util::codec::Decoder;

type PendingWrite = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
const ERROR_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct RequestHeader {
    id: Option<RequestId>,
    has_method: bool,
}

struct HeaderVisitor<'a>(&'a mut RequestHeader);

impl<'de> Visitor<'de> for HeaderVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON-RPC request object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "id" => self.0.id = Some(map.next_value()?),
                "method" => {
                    let _: String = map.next_value()?;
                    self.0.has_method = true;
                }
                _ => {
                    let _: IgnoredAny = map.next_value()?;
                }
            }
            if self.0.id.is_some() && self.0.has_method {
                // The remainder may be an intentionally truncated large value.
                return Err(A::Error::custom("request header complete"));
            }
        }
        Ok(())
    }
}

fn request_id_from_prefix(prefix: &[u8]) -> Option<RequestId> {
    let prefix = prefix.strip_prefix(b"\xef\xbb\xbf").unwrap_or(prefix);
    let mut header = RequestHeader::default();
    let mut decoder = serde_json::Deserializer::from_slice(prefix);
    let _ = decoder.deserialize_map(HeaderVisitor(&mut header));
    if header.has_method {
        header.id
    } else {
        None
    }
}

enum LineRead {
    Complete,
    Oversized(Option<RequestId>),
    Eof,
}

enum ReadStep {
    More,
    Complete,
    Oversized { ended: bool },
    EndDiscard,
}

struct PublicTransport<R: AsyncRead, W: AsyncWrite> {
    read: BufReader<R>,
    line: BytesMut,
    max_line_length: usize,
    discarding: bool,
    decoder: JsonRpcMessageCodec<ClientJsonRpcMessage>,
    // Reuse rmcp's writer and codec; its empty reader is never polled.
    output: AsyncRwTransport<RoleServer, tokio::io::Empty, W>,
    pending_write: Option<PendingWrite>,
}

impl<R, W> PublicTransport<R, W>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin + 'static,
{
    fn new(read: R, write: W, max_line_length: usize) -> Self {
        Self {
            read: BufReader::new(read),
            line: BytesMut::new(),
            max_line_length,
            discarding: false,
            decoder: JsonRpcMessageCodec::new(),
            output: AsyncRwTransport::new(tokio::io::empty(), write),
            pending_write: None,
        }
    }

    async fn read_line(&mut self) -> io::Result<LineRead> {
        loop {
            let (consumed, step) = {
                let available = self.read.fill_buf().await?;
                if available.is_empty() {
                    return Ok(LineRead::Eof);
                }
                let newline = available.iter().position(|byte| *byte == b'\n');
                let take = newline
                    .and_then(|index| index.checked_add(1))
                    .unwrap_or(available.len());
                if self.discarding {
                    (
                        take,
                        if newline.is_some() {
                            ReadStep::EndDiscard
                        } else {
                            ReadStep::More
                        },
                    )
                } else if self
                    .line
                    .len()
                    .checked_add(take)
                    .is_none_or(|length| length > self.max_line_length)
                {
                    let append = self
                        .max_line_length
                        .saturating_sub(self.line.len())
                        .min(take);
                    let prefix = available
                        .get(..append)
                        .ok_or_else(|| io::Error::other("invalid input prefix bound"))?;
                    self.line.extend_from_slice(prefix);
                    (
                        take,
                        ReadStep::Oversized {
                            ended: newline.is_some(),
                        },
                    )
                } else {
                    let bytes = available
                        .get(..take)
                        .ok_or_else(|| io::Error::other("invalid input line bound"))?;
                    self.line.extend_from_slice(bytes);
                    (
                        take,
                        if newline.is_some() {
                            ReadStep::Complete
                        } else {
                            ReadStep::More
                        },
                    )
                }
            };
            self.read.consume(consumed);
            match step {
                ReadStep::More => {}
                ReadStep::Complete => return Ok(LineRead::Complete),
                ReadStep::EndDiscard => self.discarding = false,
                ReadStep::Oversized { ended } => {
                    self.discarding = !ended;
                    let id = request_id_from_prefix(&self.line);
                    self.line.clear();
                    return Ok(LineRead::Oversized(id));
                }
            }
        }
    }

    fn reject(&mut self, id: RequestId) -> io::Result<()> {
        let message = ServerJsonRpcMessage::error(
            ErrorData::invalid_request(
                format!(
                    "Request exceeds the {} MCP message limit",
                    message_limit_label()
                ),
                None,
            ),
            Some(id),
        );
        if !frame_fits(&message).map_err(io::Error::other)? {
            tracing::warn!("discarding oversized MCP request whose ID cannot be echoed safely");
            return Ok(());
        }
        self.pending_write = Some(self.error_write(message));
        Ok(())
    }

    fn error_write(&mut self, message: ServerJsonRpcMessage) -> PendingWrite {
        // Construct the timeout now so cancelled receive polls cannot restart
        // it. An unread stdout must not prevent us from reporting termination.
        let write = tokio::time::timeout(ERROR_WRITE_TIMEOUT, self.output.send(message));
        Box::pin(async move {
            match write.await {
                Ok(result) => result,
                Err(_) => {
                    // The writer may only be waiting behind a large response.
                    // FramedWrite retains any partially flushed bytes, so a
                    // later send can finish them without corrupting the stream.
                    tracing::warn!("MCP rejection write did not finish before its deadline");
                    Ok(())
                }
            }
        })
    }
}

impl<R, W> Transport<RoleServer> for PublicTransport<R, W>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin + 'static,
{
    type Error = io::Error;

    fn send(
        &mut self,
        message: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = io::Result<()>> + Send + 'static {
        self.output.send(message)
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        loop {
            if let Some(write) = self.pending_write.as_mut() {
                // Keep this future in the transport: rmcp can cancel receive
                // while an unrelated outgoing response becomes ready.
                let result = write.await;
                self.pending_write = None;
                if result.is_err() {
                    return None;
                }
            }
            match self.read_line().await {
                Ok(LineRead::Complete) => {}
                Ok(LineRead::Oversized(Some(id))) => {
                    if self.reject(id).is_err() {
                        return None;
                    }
                    continue;
                }
                Ok(LineRead::Oversized(None)) => {
                    // A trailing ID may be outside the bounded prefix. Do not
                    // guess at it, reply to a notification, or close a healthy
                    // session because one frame could not be correlated.
                    tracing::warn!(
                        "discarding oversized MCP input without a recoverable request ID"
                    );
                    continue;
                }
                Ok(LineRead::Eof) => return None,
                Err(error) => {
                    tracing::error!(%error, "failed to read public MCP input");
                    return None;
                }
            }
            if self.line.as_ref() == b"\n" || self.line.as_ref() == b"\r\n" {
                self.line.clear();
                continue;
            }
            // Keep the complete line available for error correlation. The
            // codec consumes its input, so invoke its compatibility handling
            // only if direct deserialization fails.
            let bytes = self
                .line
                .strip_prefix(b"\xef\xbb\xbf")
                .unwrap_or(&self.line);
            let (parsed, rejected_id) = match serde_json::from_slice(bytes) {
                Ok(message) => (Ok(Some(message)), None),
                Err(_) => {
                    let id = request_id_from_prefix(&self.line);
                    (self.decoder.decode(&mut self.line), id)
                }
            };
            self.line.clear();
            match parsed {
                Ok(Some(message)) => {
                    if let rmcp::model::JsonRpcMessage::Request(request) = &message {
                        match response_id_fits(&request.id, self.max_line_length) {
                            Ok(true) => {}
                            Ok(false) => {
                                tracing::warn!(
                                    "discarding MCP request whose ID leaves no room \
                                     for a bounded response"
                                );
                                continue;
                            }
                            Err(error) => {
                                tracing::error!(%error, "failed to validate public MCP request ID");
                                return None;
                            }
                        }
                    }
                    return Some(message);
                }
                Ok(None) => {}
                Err(JsonRpcMessageCodecError::Serde(error)) => match error.classify() {
                    serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                        tracing::debug!(%error, "ignoring unparsable public MCP input");
                    }
                    serde_json::error::Category::Data | serde_json::error::Category::Io => {
                        if let Some(id) = rejected_id
                            && response_id_fits(&id, self.max_line_length).unwrap_or(false)
                        {
                            self.pending_write =
                                Some(self.error_write(ServerJsonRpcMessage::error(
                                    ErrorData::invalid_request("Invalid request", None),
                                    Some(id),
                                )));
                        } else {
                            tracing::debug!(
                                %error, "ignoring invalid MCP input without a request ID"
                            );
                        }
                    }
                },
                Err(error) => {
                    tracing::error!(%error, "failed to decode public MCP input");
                    return None;
                }
            }
        }
    }

    fn close(&mut self) -> impl Future<Output = io::Result<()>> + Send {
        self.pending_write = None;
        self.output.close()
    }
}

pub(crate) fn transport<R, W>(
    read: R,
    write: W,
) -> impl Transport<RoleServer, Error = io::Error> + 'static
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    PublicTransport::new(read, write, MAX_MESSAGE_BYTES)
}

#[cfg(test)]
mod tests {
    use crate::transport::public_stdio::{request_id_from_prefix, transport, PublicTransport};
    use crate::transport::{frame_fits, supervise, SaveFirstTransport, MAX_MESSAGE_BYTES};
    use rmcp::model::{
        CallToolResult, ContentBlock, JsonRpcMessage, RequestId, ServerJsonRpcMessage, ServerResult,
    };
    use rmcp::service::RoleClient;
    use rmcp::transport::async_rw::AsyncRwTransport;
    use rmcp::transport::Transport;
    use serde_json::{json, Value};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[test]
    fn truncated_header_uses_only_top_level_request_fields() {
        assert_eq!(
            request_id_from_prefix(
                br#"{"id":3.0,"method":"tools/call","params":{"code":"unfinished"#
            ),
            Some(RequestId::Number(3))
        );
        assert_eq!(
            request_id_from_prefix(br#"{"params":{"id":9},"method":"ping","id":"own"}"#),
            Some(RequestId::String("own".into()))
        );
        assert_eq!(
            request_id_from_prefix(br#"{"params":{"id":9,"method":"ping","code":"unfinished"#),
            None
        );
    }

    #[tokio::test]
    async fn oversized_request_is_correlated_and_the_next_line_survives() {
        let (mut client_write, read) = tokio::io::duplex(4096);
        let (write, client_read) = tokio::io::duplex(8);
        let mut transport = PublicTransport::new(read, write, 128);
        let input = format!(
            "{}\n{}\n",
            json!({"jsonrpc":"2.0","id":7,"method":"tools/call",
                "params":{"padding":"x".repeat(256)}}),
            json!({"jsonrpc":"2.0","id":8,"method":"ping"})
        );
        client_write
            .write_all(input.as_bytes())
            .await
            .expect("write requests");
        let mut receive = Box::pin(transport.receive());
        assert!(futures_util::poll!(receive.as_mut()).is_pending());
        drop(receive);
        let reply = tokio::spawn(async move {
            let mut reply = String::new();
            BufReader::new(client_read)
                .read_line(&mut reply)
                .await
                .expect("rejection");
            reply
        });
        let JsonRpcMessage::Request(next) = transport.receive().await.expect("next request") else {
            panic!("expected request")
        };
        assert_eq!(next.id, RequestId::Number(8));
        let reply = reply.await.expect("reply reader");
        let reply: Value = serde_json::from_str(&reply).expect("JSON error");
        assert_eq!(reply["id"], 7);
        assert_eq!(reply["error"]["code"], -32600);
    }

    #[tokio::test]
    async fn cancelled_receive_preserves_an_incomplete_line() {
        let (mut client, read) = tokio::io::duplex(128);
        let mut transport = PublicTransport::new(read, tokio::io::sink(), 128);
        client
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":3,")
            .await
            .expect("first half");
        let mut receive = Box::pin(transport.receive());
        assert!(futures_util::poll!(receive.as_mut()).is_pending());
        drop(receive);
        client
            .write_all(b"\"method\":\"ping\"}\n")
            .await
            .expect("second half");
        let JsonRpcMessage::Request(request) = transport.receive().await.expect("whole request")
        else {
            panic!("expected request");
        };
        assert_eq!(request.id, RequestId::Number(3));
    }

    #[tokio::test(start_paused = true)]
    async fn unread_rejection_does_not_hide_input_eof() {
        let (mut client_write, read) = tokio::io::duplex(4096);
        let (write, _unread_output) = tokio::io::duplex(8);
        let (mut transport, shutdown) =
            SaveFirstTransport::new(PublicTransport::new(read, write, 128));
        shutdown.arm();
        let input = format!(
            "{}\n",
            json!({"jsonrpc":"2.0","id":7,"method":"tools/call",
                "params":{"padding":"x".repeat(256)}})
        );
        client_write
            .write_all(input.as_bytes())
            .await
            .expect("request");
        drop(client_write);
        let started = tokio::time::Instant::now();
        let receive = tokio::spawn(async move { transport.receive().await });
        shutdown.closed().await;
        assert_eq!(started.elapsed(), Duration::from_secs(5));
        assert!(!receive.is_finished(), "save-first gate must remain armed");
        shutdown.release();
        assert!(receive.await.expect("receiver").is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn rejection_waiting_for_a_slow_response_does_not_end_the_session() {
        let (mut input, read) = tokio::io::duplex(4096);
        let (write, output) = tokio::io::duplex(8);
        let mut transport = PublicTransport::new(read, write, 128);
        let sending = tokio::spawn(transport.send(ServerJsonRpcMessage::response(
            ServerResult::CallToolResult(CallToolResult::success(vec![ContentBlock::text(
                "slow response".repeat(128),
            )])),
            RequestId::Number(1),
        )));
        tokio::task::yield_now().await;
        let requests = format!(
            "{}\n{}\n",
            json!({"jsonrpc":"2.0","id":7,"method":"tools/call",
                "params":{"padding":"x".repeat(256)}}),
            json!({"jsonrpc":"2.0","id":8,"method":"ping"})
        );
        input
            .write_all(requests.as_bytes())
            .await
            .expect("requests");
        let mut receive = Box::pin(transport.receive());
        assert!(futures_util::poll!(receive.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(6)).await;
        let Some(JsonRpcMessage::Request(next)) = receive.await else {
            panic!("writer contention must not close the session");
        };
        assert_eq!(next.id, RequestId::Number(8));
        let mut reader = BufReader::new(output);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("slow response");
        let response: Value = serde_json::from_str(&line).expect("intact JSON frame");
        assert_eq!(response["id"], 1);
        sending
            .await
            .expect("send task")
            .expect("response delivered");
    }

    #[tokio::test]
    async fn uncorrelatable_oversized_messages_are_discarded_without_a_reply() {
        let (client, server) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(server);
        let (client_read, mut client_write) = tokio::io::split(client);
        let mut transport = PublicTransport::new(read, write, 128);
        let input = format!(
            "{{\"jsonrpc\":\"2.0\",\"params\":{{\"padding\":\"{}\"}},\
             \"method\":\"ping\",\"id\":9}}\n{}\n{}\n{}\n",
            "x".repeat(256),
            json!({"jsonrpc":"2.0","method":"notifications/progress",
                "params":{"padding":"x".repeat(256)}}),
            json!({"jsonrpc":"2.0","id":10,"result":{"padding":"x".repeat(256)}}),
            json!({"jsonrpc":"2.0","id":11,"method":"ping"}),
        );
        client_write
            .write_all(input.as_bytes())
            .await
            .expect("write request");
        let Some(JsonRpcMessage::Request(next)) = transport.receive().await else {
            panic!("next request must survive");
        };
        assert_eq!(next.id, RequestId::Number(11));
        let mut reader = BufReader::new(client_read);
        let mut reply = String::new();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), reader.read_line(&mut reply))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn valid_request_id_must_leave_room_for_a_response() {
        let (client, server) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(server);
        let (client_read, mut client_write) = tokio::io::split(client);
        let mut transport = PublicTransport::new(read, write, 128);
        let mut request = json!({"jsonrpc":"2.0","id":"","method":"ping"});
        let overhead = serde_json::to_vec(&request).expect("request").len() + 1;
        request["id"] = Value::String("x".repeat(128 - overhead));
        let mut input = format!("{request}\n");
        assert_eq!(input.len(), 128);
        input.push_str("{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}\n");
        client_write
            .write_all(input.as_bytes())
            .await
            .expect("write request");
        let Some(JsonRpcMessage::Request(next)) = transport.receive().await else {
            panic!("next request must survive");
        };
        assert_eq!(next.id, RequestId::Number(9));
        let mut reader = BufReader::new(client_read);
        let mut reply = String::new();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), reader.read_line(&mut reply))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn malformed_request_keeps_its_trailing_id() {
        let (client, server) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(server);
        let (client_read, mut client_write) = tokio::io::split(client);
        let mut transport = PublicTransport::new(read, write, 256);
        client_write
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":false,\"id\":7}\n\
              {\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"ping\"}\n",
            )
            .await
            .expect("requests");
        let Some(JsonRpcMessage::Request(next)) = transport.receive().await else {
            panic!("next request must survive");
        };
        assert_eq!(next.id, RequestId::Number(8));
        let mut reply = String::new();
        BufReader::new(client_read)
            .read_line(&mut reply)
            .await
            .expect("rejection");
        let reply: Value = serde_json::from_str(&reply).expect("JSON error");
        assert_eq!(reply["id"], 7);
        assert_eq!(reply["error"]["code"], -32600);
    }

    #[tokio::test]
    async fn public_writer_bounds_the_final_id_and_result_together() {
        let result =
            CallToolResult::success(vec![ContentBlock::text("\0".repeat(MAX_MESSAGE_BYTES / 8))]);
        let private = ServerJsonRpcMessage::response(
            ServerResult::CallToolResult(result.clone()),
            RequestId::Number(1),
        );
        assert!(frame_fits(&private).expect("private frame fits"));
        let id = RequestId::String("p".repeat(MAX_MESSAGE_BYTES / 3).into());
        let public =
            ServerJsonRpcMessage::response(ServerResult::CallToolResult(result), id.clone());
        assert!(!frame_fits(&public).expect("public frame exceeds limit"));

        let (client, server) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(server);
        let (client_read, client_write) = tokio::io::split(client);
        let (mut server, _) = supervise(transport(read, write));
        let mut client = AsyncRwTransport::<RoleClient, _, _>::new(client_read, client_write);
        let sending = tokio::spawn(server.send(public));
        let JsonRpcMessage::Response(response) =
            client.receive().await.expect("bounded public reply")
        else {
            panic!("expected correlated tool error");
        };
        sending.await.expect("send task").expect("send reply");
        assert_eq!(response.id, id);
        let ServerResult::CallToolResult(result) = response.result else {
            panic!("expected tool result")
        };
        assert_eq!(result.is_error, Some(true));
    }
}
