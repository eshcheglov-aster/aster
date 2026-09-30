use crate::{api, operation_key, validation};
use buffa::Message;
use std::io::Read;

pub const HELP: &str = "Usage: asterctl (--token TOKEN | --token-file PATH) [OPTIONS] publish
                --topic TOPIC --scope SCOPE --operation-key KEY|auto [PUBLISH-OPTIONS] [MSG]

Publish an Event through a running Aster agent.
Use MSG as the payload, or read standard input until EOF.
Terminal input shows instructions on stderr before reading.

PUBLISH OPTIONS:
      --topic TOPIC             Event topic (required)
      --scope SCOPE             Propagation and authorization scope (required)
      --priority PRIORITY       routine, priority, immediate, or flash (default: routine)
      --logical-key KEY         UTF-8 logical key, up to 4096 bytes (default: empty)
      --predecessor ID          Predecessor Event ID in Base64
      --ttl-ms MILLISECONDS     Positive Event lifetime (default: no expiry)
      --tombstone               Publish a tombstone; requires an empty payload
      --operation-key KEY|auto  Required UTF-8 key, 1–256 bytes; auto generates a key
      --help                    Show this help

See asterctl --help for global options.
Generated keys are printed to stderr before sending and included in JSON output.
";

const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const SIZE_ERROR: &str = "publication request exceeds 1 MiB";

#[derive(Debug, PartialEq)]
pub struct Publication {
    pub request: api::PublishEventRequest,
    message: Option<String>,
    operation_key: Option<operation_key::Selection>,
}

impl Default for Publication {
    fn default() -> Self {
        Self {
            request: api::PublishEventRequest {
                priority: api::Priority::PRIORITY_ROUTINE.into(),
                ..Default::default()
            },
            message: None,
            operation_key: None,
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
            "--operation-key" => {
                self.operation_key = Some(operation_key::Selection::parse(value)?);
            }
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
        if self.operation_key.is_none() {
            return Err(operation_key::REQUIRED);
        }
        Ok(())
    }

    pub fn into_request(
        mut self,
        input: impl Read,
    ) -> Result<(api::PublishEventRequest, operation_key::Key), &'static str> {
        let key = self
            .operation_key
            .ok_or(operation_key::REQUIRED)?
            .resolve()?;
        self.request.operation_key = key.value.as_bytes().to_vec();
        if let Some(message) = self.message {
            self.request.payload = message.into_bytes();
        } else if !self.request.tombstone {
            input
                .take((MAX_REQUEST_BYTES + 1) as u64)
                .read_to_end(&mut self.request.payload)
                .map_err(|_| "cannot read payload from standard input")?;
        }
        if self.request.payload.len() > MAX_REQUEST_BYTES
            || self.request.encoded_len() as usize > MAX_REQUEST_BYTES
        {
            return Err(SIZE_ERROR);
        }
        Ok((self.request, key))
    }
}
