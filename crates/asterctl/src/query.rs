use crate::{api, auth::Token, client, output, validation};
use std::{io, net::SocketAddr, time::Duration};

pub const HELP: &str =
    "Usage: asterctl (--token TOKEN | --token-file PATH) [OPTIONS] query [QUERY-OPTIONS]

Query locally stored Events through a running Aster agent.

QUERY OPTIONS:
      --topic TOPIC      Filter by exact Event topic
      --scope SCOPE      Filter by scope; append '/*' to include all sub-scopes
      --publisher ID     Filter by Base64-encoded 32-byte publisher identity
      --logical-key KEY  Filter by exact UTF-8 logical key
      --limit NUMBER     Maximum number of Events to display (default: unlimited)
      --help             Show this help

See asterctl --help for global options.
";

#[derive(Debug, Default, PartialEq)]
pub struct Query {
    pub request: api::QueryEventsRequest,
    pub limit: Option<u64>,
}

impl Query {
    pub fn set_option(&mut self, name: &str, value: String) -> Result<(), &'static str> {
        match name {
            "--topic" => {
                validation::topic(&value)?;
                self.request.topic = Some(value);
            }
            "--scope" => {
                let (scope, descendants) = value
                    .strip_suffix("/*")
                    .map_or((value.as_str(), false), |s| (s, true));
                validation::scope(scope)?;
                self.request.scope = Some(scope.to_owned());
                self.request.include_descendant_scopes = descendants;
            }
            "--publisher" => {
                self.request.publisher = Some(
                    validation::identity(&value)
                        .ok_or("publisher must be a Base64-encoded 32-byte node identity")?,
                );
            }
            "--logical-key" => self.request.logical_key = Some(value.into_bytes()),
            "--limit" => {
                self.limit = Some(
                    value
                        .parse::<u64>()
                        .ok()
                        .filter(|_| value.bytes().all(|b| b.is_ascii_digit()))
                        .ok_or("limit must be an integer from 0 to 18446744073709551615")?,
                );
            }
            _ => unreachable!("query option"),
        }
        Ok(())
    }
}

pub enum Error {
    Rpc(String),
    Output(io::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Output(error)
    }
}

pub async fn run(
    address: SocketAddr,
    token: &Token,
    mut query: Query,
    timeout: Duration,
    json: bool,
    writer: impl io::Write,
) -> Result<(), Error> {
    let mut output = output::QueryWriter::new(writer, json);
    let client = client::query_client(address, token, timeout);
    let mut remaining = query.limit.unwrap_or(u64::MAX);
    let mut scan_limit = 1024;
    while remaining > 0 {
        query.request.limit = scan_limit.min(remaining.min(1024) as u32);
        let response = match client::query(&client, &query.request, timeout).await {
            Ok(response) => response,
            Err(connectrpc::ErrorCode::ResourceExhausted) if query.request.limit > 1 => {
                // Large payloads may exceed the agent's response bound. Retry
                // this read from the same cursor with a smaller scan budget.
                scan_limit = query.request.limit / 2;
                continue;
            }
            Err(code) => return Err(Error::Rpc(client::describe_rpc_error("QueryEvents", code))),
        };
        validate_response(&query.request, &response).map_err(|e| Error::Rpc(e.to_owned()))?;
        for event in &response.events {
            output.event(event)?;
            remaining -= 1;
        }
        if !response.has_more {
            break;
        }
        query.request.after_acceptance_marker = response.scanned_through;
    }
    output.finish()?;
    Ok(())
}

fn validate_response(
    request: &api::QueryEventsRequest,
    response: &api::QueryEventsResponse,
) -> Result<(), &'static str> {
    let mut previous = request.after_acceptance_marker;
    if response.events.len() > request.limit as usize
        || response.scanned_through < previous
        || (response.has_more && response.scanned_through == previous)
    {
        return Err("QueryEvents failed: invalid continuation response");
    }
    for event in &response.events {
        if event.acceptance_marker <= previous || event.acceptance_marker > response.scanned_through
        {
            return Err("QueryEvents failed: invalid Event order");
        }
        previous = event.acceptance_marker;
    }
    Ok(())
}
