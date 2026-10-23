use crate::{api, journal, validation};
use buffa::Message;
use std::io::Read;

pub const HELP: &str = "Usage: asterctl (--token TOKEN | --token-file PATH) [OPTIONS] publish
                --topic TOPIC --scope SCOPE --journal PATH --client-id ID [PUBLISH-OPTIONS] [MSG]

Publish an Event through a running Aster agent.
Use MSG as the payload, or read standard input until EOF.
Payloads are limited to 65536 bytes.
Terminal input shows instructions on stderr before reading.

PUBLISH OPTIONS:
      --topic TOPIC             Event topic (required)
      --scope SCOPE             Propagation and authorization scope (required)
      --priority PRIORITY       routine, priority, immediate, or flash (default: routine)
      --logical-key KEY         UTF-8 logical key, up to 4096 bytes (default: empty)
      --predecessor ID          Predecessor Event ID in Base64
      --ttl-ms MILLISECONDS     Positive Event lifetime (default: no expiry)
      --tombstone               Publish a tombstone; requires an empty payload
      --journal PATH           Existing publication journal (required)
      --client-id ID           Stable UTF-8 application identity, 1–64 bytes (required)
      --help                    Show this help

See asterctl --help for global options.
Initialize once with publication-init. Assigned sequences are printed before sending.
Use publication-recover after an uncertain outcome; acknowledge results explicitly.
";

const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const SIZE_ERROR: &str = "publication request exceeds 1 MiB";
const MAX_PAYLOAD_BYTES: usize = aster_agent::sdk::MAX_PUBLICATION_JOURNAL_PAYLOAD_BYTES;
const PAYLOAD_SIZE_ERROR: &str = "publication payload exceeds 65536 bytes";

#[derive(Debug, PartialEq)]
pub struct Publication {
    pub request: api::PublishNumberedEventRequest,
    message: Option<String>,
    pub identity: journal::Identity,
}

impl Default for Publication {
    fn default() -> Self {
        Self {
            request: api::PublishNumberedEventRequest {
                priority: api::Priority::PRIORITY_ROUTINE.into(),
                ..Default::default()
            },
            message: None,
            identity: journal::Identity::default(),
        }
    }
}

impl Publication {
    pub fn reads_stdin(&self) -> bool {
        self.message.is_none() && !self.request.tombstone
    }

    pub fn set_message(&mut self, message: &str) -> Result<(), &'static str> {
        if self.message.is_some() {
            return Err("publish accepts only one MSG argument");
        }
        self.message = Some(message.to_owned());
        Ok(())
    }

    pub fn set_option(&mut self, name: &str, value: String) -> Result<(), &'static str> {
        match name {
            "--topic" => {
                validation::topic(&value)?;
                self.request.topic = value;
            }
            "--scope" => {
                validation::scope(&value)?;
                self.request.scope = value;
            }
            "--logical-key" => self.request.logical_key = value.into_bytes(),
            "--journal" | "--client-id" => self.identity.set_option(name, value)?,
            "--priority" => {
                self.request.priority = match value.as_str() {
                    "routine" => api::Priority::PRIORITY_ROUTINE,
                    "priority" => api::Priority::PRIORITY_PRIORITY,
                    "immediate" => api::Priority::PRIORITY_IMMEDIATE,
                    "flash" => api::Priority::PRIORITY_FLASH,
                    _ => return Err("priority must be routine, priority, immediate, or flash"),
                }
                .into();
            }
            "--ttl-ms" => {
                self.request.ttl_ms = Some(
                    value
                        .parse::<u64>()
                        .ok()
                        .filter(|v| *v > 0 && value.bytes().all(|b| b.is_ascii_digit()))
                        .ok_or(
                            "TTL must be an integer from 1 to 18446744073709551615 milliseconds",
                        )?,
                );
            }
            "--predecessor" => {
                self.request.predecessor_id = Some(
                    validation::identity(&value)
                        .ok_or("predecessor must be a Base64-encoded 32-byte Event ID")?,
                );
            }
            _ => unreachable!("publish option"),
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        let r = &self.request;
        if r.topic.is_empty() {
            return Err("--topic is required; see publish --help");
        }
        if r.scope.is_empty() {
            return Err("--scope is required; see publish --help");
        }
        if r.logical_key.len() > 4096 {
            return Err("logical key must not exceed 4096 UTF-8 bytes");
        }
        if r.tombstone
            && (r.ttl_ms.is_some() || self.message.as_ref().is_some_and(|m| !m.is_empty()))
        {
            return Err(
                "--tombstone requires an empty payload and cannot be combined with --ttl-ms",
            );
        }
        self.identity.validate()?;
        Ok(())
    }

    pub fn into_request(
        mut self,
        input: impl Read,
    ) -> Result<(api::PublishNumberedEventRequest, journal::Identity), &'static str> {
        if let Some(message) = self.message {
            self.request.payload = message.into_bytes();
        } else if !self.request.tombstone {
            input
                .take((MAX_PAYLOAD_BYTES + 1) as u64)
                .read_to_end(&mut self.request.payload)
                .map_err(|_| "cannot read payload from standard input")?;
        }
        if self.request.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(PAYLOAD_SIZE_ERROR);
        }
        // Reserve enough wire space for the stable identity and any future
        // positive session/sequence before assigning or sending the intent.
        self.request.client_id.clone_from(&self.identity.client_id);
        self.request.session = u64::MAX;
        self.request.operation_sequence = u64::MAX;
        if self.request.encoded_len() as usize > MAX_REQUEST_BYTES {
            return Err(SIZE_ERROR);
        }
        self.request.session = 0;
        self.request.operation_sequence = 0;
        Ok((self.request, self.identity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_limit_includes_metadata_and_payload() {
        let max_request_bytes = 1024 * 1024;
        // Valid CLI metadata plus a 64 KiB payload cannot reach 1 MiB.
        // Construct oversized metadata directly to exercise the independent
        // encoded-request guard without weakening argument or payload limits.
        let publication = |metadata_bytes| Publication {
            request: api::PublishNumberedEventRequest {
                client_id: vec![b'c'; 64],
                session: u64::MAX,
                operation_sequence: u64::MAX,
                topic: "x".to_owned(),
                scope: "x".to_owned(),
                priority: api::Priority::Routine.into(),
                logical_key: vec![b'x'; metadata_bytes],
                payload: vec![42; MAX_PAYLOAD_BYTES],
                ..Default::default()
            },
            identity: journal::Identity {
                path: "unused-test-journal.redb".into(),
                client_id: vec![b'c'; 64],
            },
            ..Default::default()
        };
        let template = publication(max_request_bytes);
        let overhead = template.request.encoded_len() as usize - max_request_bytes;
        let metadata_bytes = max_request_bytes - overhead;
        let exact = publication(metadata_bytes);
        assert_eq!(exact.request.encoded_len() as usize, max_request_bytes);
        let (mut accepted, _) = exact.into_request(std::io::empty()).unwrap();
        assert_eq!(accepted.payload.len(), MAX_PAYLOAD_BYTES);
        assert_eq!(accepted.logical_key.len(), metadata_bytes);
        assert_eq!(accepted.session, 0);
        assert_eq!(accepted.operation_sequence, 0);
        accepted.session = u64::MAX;
        accepted.operation_sequence = u64::MAX;
        assert_eq!(accepted.encoded_len() as usize, max_request_bytes);

        let over = publication(metadata_bytes + 1);
        assert_eq!(over.request.payload.len(), MAX_PAYLOAD_BYTES);
        assert_eq!(over.request.encoded_len() as usize, max_request_bytes + 1);
        assert_eq!(over.into_request(std::io::empty()).unwrap_err(), SIZE_ERROR);
    }
}
