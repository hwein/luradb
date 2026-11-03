//! Read-only resources: the domain list and the schema of one domain, read
//! through the same routes as the tools.

use super::internal::{encode, Call, Reply};
use super::tools;
use axum::http::StatusCode;
use rmcp::model::{ErrorData, ReadResourceResult, Resource, ResourceContents, ResourceTemplate};
use serde_json::{json, Map, Value};

pub(crate) const DOMAINS_URI: &str = "luradb://domains";
const SCHEMA_TEMPLATE: &str = "luradb://{engine}/{name}/schema";

pub(crate) fn listed() -> Vec<Resource> {
    vec![Resource::new(DOMAINS_URI, "domains")
        .with_description("Domains of all engines the caller may access; each entry names its engine.")
        .with_mime_type("application/json")]
}

pub(crate) fn templates() -> Vec<ResourceTemplate> {
    vec![ResourceTemplate::new(SCHEMA_TEMPLATE, "schema")
        .with_description(
            "Schema of a domain: tables and views of a relational domain, indexes of a JSON domain, the details of a key-value domain.",
        )
        .with_mime_type("application/json")]
}

/// How a resource is read: its requests and the field each answer goes to.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Read {
    Domains(tools::Plan),
    Schema(Vec<(&'static str, Call)>),
}

impl Read {
    pub(crate) fn calls(&self) -> Vec<Call> {
        match self {
            Read::Domains(plan) => plan.calls.clone(),
            Read::Schema(parts) => parts.iter().map(|(_, call)| call.clone()).collect(),
        }
    }

    /// The resource from the answers to [`Self::calls`], in order.
    pub(crate) fn result(&self, uri: &str, replies: &[Reply]) -> Result<ReadResourceResult, ErrorData> {
        let value = match self {
            Read::Domains(plan) => {
                let result = plan.result(replies);
                match (result.is_error, result.structured_content) {
                    (Some(false), Some(value)) => value,
                    _ => {
                        let message = result.content.first().and_then(|c| c.as_text()).map(|t| t.text.clone());
                        return Err(ErrorData::invalid_request(message.unwrap_or_default(), None));
                    }
                }
            }
            Read::Schema(parts) => {
                let mut fields = Map::new();
                for ((field, _), reply) in parts.iter().zip(replies) {
                    fields.insert(field.to_string(), answer(reply)?);
                }
                Value::Object(fields)
            }
        };
        Ok(ReadResourceResult::new(vec![ResourceContents::text(value.to_string(), uri).with_mime_type("application/json")]))
    }
}

fn answer(reply: &Reply) -> Result<Value, ErrorData> {
    let Some(_) = &reply.body else {
        return Err(ErrorData::invalid_request("the resource is larger than 1 MiB", None));
    };
    if !reply.status.is_success() {
        let message = format!("HTTP {}: {}", reply.status, reply.text());
        return Err(if reply.status == StatusCode::NOT_FOUND {
            ErrorData::resource_not_found(message, None)
        } else {
            ErrorData::invalid_request(message, None)
        });
    }
    reply.json().ok_or_else(|| ErrorData::internal_error("the route did not answer with JSON", None))
}

/// The reads behind `uri`.
pub(crate) fn read(uri: &str) -> Result<Read, ErrorData> {
    if uri == DOMAINS_URI {
        let spec = tools::find("list_domains").expect("list_domains is in the catalog");
        let plan = tools::plan(spec, &Map::new(), 0).map_err(|refusal| ErrorData::internal_error(refusal.0, None))?;
        return Ok(Read::Domains(plan));
    }
    let unknown = || ErrorData::resource_not_found(format!("unknown resource '{uri}'"), Some(json!({ "uri": uri })));
    let rest = uri.strip_prefix("luradb://").and_then(|rest| rest.strip_suffix("/schema")).ok_or_else(unknown)?;
    let (engine, name) = rest.split_once('/').ok_or_else(unknown)?;
    if name.is_empty() || name.contains('/') {
        return Err(unknown());
    }
    let name = encode(name);
    let parts = match engine {
        "rel" => vec![
            ("tables", Call::get(format!("/store-api/rel/{name}/tables"))),
            ("views", Call::get(format!("/store-api/rel/{name}/views"))),
        ],
        "json" => vec![("indexes", Call::get(format!("/store-api/json/{name}/indexes")))],
        "kv" => vec![("domain", Call::get(format!("/store-api/domains/{name}")))],
        _ => return Err(unknown()),
    };
    Ok(Read::Schema(parts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use rmcp::model::ErrorCode;

    fn reply(status: u16, body: &str) -> Reply {
        Reply { status: StatusCode::from_u16(status).unwrap(), body: Some(Bytes::from(body.to_string())) }
    }

    fn targets(read: &Read) -> Vec<String> {
        read.calls().iter().map(Call::target).collect()
    }

    fn text(result: &ReadResourceResult) -> Value {
        let json = serde_json::to_value(result).unwrap();
        serde_json::from_str(json["contents"][0]["text"].as_str().unwrap()).unwrap()
    }

    #[test]
    fn the_schema_of_each_engine_reads_its_routes() {
        assert_eq!(targets(&read("luradb://rel/sales/schema").unwrap()), ["/store-api/rel/sales/tables", "/store-api/rel/sales/views"]);
        assert_eq!(targets(&read("luradb://json/docs/schema").unwrap()), ["/store-api/json/docs/indexes"]);
        assert_eq!(targets(&read("luradb://kv/cache/schema").unwrap()), ["/store-api/domains/cache"]);
        assert_eq!(
            targets(&read(DOMAINS_URI).unwrap()),
            ["/store-api/domains", "/store-api/json/domains", "/store-api/rel/domains"]
        );
    }

    #[test]
    fn unknown_uris_are_not_found() {
        for uri in ["luradb://graph/x/schema", "luradb://rel/schema", "luradb://rel/a/b/schema", "file:///etc/passwd", "luradb://rel/x"] {
            assert_eq!(read(uri).unwrap_err().code, ErrorCode::RESOURCE_NOT_FOUND, "{uri}");
        }
    }

    #[test]
    fn a_schema_combines_its_answers() {
        let uri = "luradb://rel/sales/schema";
        let result = read(uri).unwrap().result(uri, &[reply(200, r#"[{"name":"t"}]"#), reply(200, "[]")]).unwrap();
        assert_eq!(text(&result), json!({"tables": [{"name": "t"}], "views": []}));
        let err = read(uri).unwrap().result(uri, &[reply(403, "Forbidden"), reply(403, "Forbidden")]).unwrap_err();
        assert_eq!(err.message, "HTTP 403 Forbidden: Forbidden");
        let err = read(uri).unwrap().result(uri, &[reply(404, "404 Not Found: domain"), reply(200, "[]")]).unwrap_err();
        assert_eq!(err.code, ErrorCode::RESOURCE_NOT_FOUND);
    }

    #[test]
    fn the_domain_list_is_the_merged_listing() {
        let read = read(DOMAINS_URI).unwrap();
        let replies = [reply(200, r#"[{"name":"a"}]"#), reply(503, "off"), reply(404, "")];
        let result = read.result(DOMAINS_URI, &replies).unwrap();
        assert_eq!(text(&result), json!({"domains": [{"name": "a", "engine": "kv"}], "unavailable_engines": ["json", "rel"]}));
    }
}
