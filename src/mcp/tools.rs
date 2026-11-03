//! The tool catalog: each tool's parameters, the REST requests a call runs
//! and how their answers become the tool result. A tool adds no behavior of
//! its own; the routes decide, with the caller's API key.

use super::internal::{encode, Call, Reply, MAX_RESULT_BYTES};
use super::sql::{self, Rejected, SqlTool};
use crate::auth::oauth::base64url;
use axum::http::{Method, StatusCode};
use rmcp::model::{CallToolResult, ContentBlock, JsonObject, Tool, ToolAnnotations};
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// What a tool does to the data, and which switch offers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    Read,
    Write,
    /// Creates structure.
    Ddl,
}

/// The operator's switches over the tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Switches {
    pub(crate) read_only: bool,
    pub(crate) allow_ddl: bool,
}

impl Switches {
    fn offer(self, access: Access) -> bool {
        match access {
            Access::Read => true,
            Access::Write => !self.read_only,
            Access::Ddl => !self.read_only && self.allow_ddl,
        }
    }
}

/// The caller's role, as `GET /store-api/auth/whoami` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Admin,
    User,
    /// Auth is off: full access.
    Disabled,
    TrustedPeer,
}

impl Role {
    pub(crate) fn from_whoami(body: &Value) -> Option<Self> {
        match body.get("role")?.as_str()? {
            "Admin" => Some(Role::Admin),
            "User" => Some(Role::User),
            "Disabled" => Some(Role::Disabled),
            "TrustedPeer" => Some(Role::TrustedPeer),
            _ => None,
        }
    }

    /// Whether the admin-only routes let this role in.
    fn reaches_admin_routes(self) -> bool {
        self != Role::User
    }
}

pub(crate) struct ToolSpec {
    pub(crate) name: &'static str,
    description: &'static str,
    access: Access,
    /// Calls only admin-only routes; listed for admins only.
    admin_only: bool,
    params: &'static [Param],
}

/// A tool parameter: name, JSON type, description, required.
type Param = (&'static str, &'static str, &'static str, bool);

const DOMAIN: Param = ("domain", "string", "Domain name", true);
const KEY: Param = ("key", "string", "Key", true);
const ENGINE: Param = ("engine", "string", "Engine of the domain: \"kv\", \"json\" or \"rel\"", true);
const NAME: Param = ("name", "string", "Domain name", true);
const LIMIT: Param = ("limit", "integer", "Page size; the route's maximum applies", false);
const OFFSET: Param = ("offset", "integer", "Entries to skip", false);
const SQL: Param = ("sql", "string", "Exactly one LuraSQL statement", true);
const SQL_PARAMS: Param = ("params", "array", "Values bound to the ? placeholders, in order", false);

pub(crate) const TOOLS: &[ToolSpec] = &[
    ToolSpec { name: "whoami", description: "Name and role of the caller's API key.", access: Access::Read, admin_only: false, params: &[] },
    ToolSpec {
        name: "list_domains",
        description: "Domains the caller may access, of all engines or of one; each entry names its engine.",
        access: Access::Read,
        admin_only: false,
        params: &[("engine", "string", "Only this engine: \"kv\", \"json\" or \"rel\"", false)],
    },
    ToolSpec { name: "describe_domain", description: "Details of one domain.", access: Access::Read, admin_only: false, params: &[ENGINE, NAME] },
    ToolSpec { name: "metrics", description: "Server metrics (admins only).", access: Access::Read, admin_only: true, params: &[] },
    ToolSpec { name: "list_tables", description: "Tables of a relational domain.", access: Access::Read, admin_only: false, params: &[DOMAIN] },
    ToolSpec {
        name: "describe_table",
        description: "Columns, indexes and links of a table of a relational domain.",
        access: Access::Read,
        admin_only: false,
        params: &[DOMAIN, ("table", "string", "Table name", true)],
    },
    ToolSpec { name: "list_views", description: "Views of a relational domain.", access: Access::Read, admin_only: false, params: &[DOMAIN] },
    ToolSpec { name: "list_json_indexes", description: "Indexes of a JSON domain.", access: Access::Read, admin_only: false, params: &[DOMAIN] },
    ToolSpec { name: "health", description: "Health report of the server and its data shards.", access: Access::Read, admin_only: false, params: &[] },
    ToolSpec { name: "kv_get", description: "Value of a key in a key-value domain as {\"value\": text}, exactly as stored; null for a key in the NULL state; a value that is not UTF-8 comes as base64url with \"encoding\": \"base64url\".", access: Access::Read, admin_only: false, params: &[DOMAIN, KEY] },
    ToolSpec {
        name: "kv_scan",
        description: "Keys of a key-value domain, optionally filtered, one page at a time.",
        access: Access::Read,
        admin_only: false,
        params: &[
            DOMAIN,
            ("prefix", "string", "Only keys with this prefix", false),
            ("contains", "string", "Only keys containing this text", false),
            LIMIT,
            OFFSET,
        ],
    },
    ToolSpec {
        name: "kv_count",
        description: "Number of keys of a key-value domain.",
        access: Access::Read,
        admin_only: false,
        params: &[DOMAIN, ("prefix", "string", "Only keys with this prefix", false)],
    },
    ToolSpec { name: "json_get", description: "A document of a JSON domain.", access: Access::Read, admin_only: false, params: &[DOMAIN, KEY] },
    ToolSpec {
        name: "json_list",
        description: "Documents of a JSON domain, one page at a time.",
        access: Access::Read,
        admin_only: false,
        params: &[DOMAIN, LIMIT, OFFSET, ("keys_only", "boolean", "Return the keys only", false)],
    },
    ToolSpec {
        name: "json_search",
        description: "Documents of a JSON domain matching a filter on indexed fields.",
        access: Access::Read,
        admin_only: false,
        params: &[
            DOMAIN,
            ("filter", "object", "Field to value, or to {\"$gt\": …} / $gte / $lt / $lte / $eq", false),
            LIMIT,
            OFFSET,
        ],
    },
    ToolSpec { name: "json_count", description: "Number of documents of a JSON domain.", access: Access::Read, admin_only: false, params: &[DOMAIN] },
    ToolSpec {
        name: "sql_query",
        description: "Runs one LuraSQL SELECT on a relational domain.",
        access: Access::Read,
        admin_only: false,
        params: &[DOMAIN, SQL, SQL_PARAMS, ("expand", "array", "REFERENCES columns to embed, or [\"*\"]", false)],
    },
    ToolSpec {
        name: "kv_put",
        description: "Sets the value of a key in a key-value domain, replacing any value it had.",
        access: Access::Write,
        admin_only: false,
        params: &[DOMAIN, KEY, ("value", "string", "The value", true), ("ttl", "integer", "Seconds until the key expires", false)],
    },
    ToolSpec { name: "kv_delete", description: "Deletes a key of a key-value domain.", access: Access::Write, admin_only: false, params: &[DOMAIN, KEY] },
    ToolSpec {
        name: "kv_set_null",
        description: "Sets a key of a key-value domain to NULL, replacing any value it had.",
        access: Access::Write,
        admin_only: false,
        params: &[DOMAIN, KEY],
    },
    ToolSpec {
        name: "json_put",
        description: "Creates or replaces a document of a JSON domain.",
        access: Access::Write,
        admin_only: false,
        params: &[DOMAIN, KEY, ("document", "object", "The document", true)],
    },
    ToolSpec { name: "json_delete", description: "Deletes a document of a JSON domain.", access: Access::Write, admin_only: false, params: &[DOMAIN, KEY] },
    ToolSpec {
        name: "sql_execute",
        description: "Runs one LuraSQL INSERT, UPDATE or DELETE on a relational domain.",
        access: Access::Write,
        admin_only: false,
        params: &[DOMAIN, SQL, SQL_PARAMS],
    },
    ToolSpec { name: "create_domain", description: "Creates a domain (admins only).", access: Access::Ddl, admin_only: true, params: &[ENGINE, NAME] },
    ToolSpec {
        name: "create_json_index",
        description: "Creates an index on a field of a JSON domain.",
        access: Access::Ddl,
        admin_only: false,
        params: &[
            DOMAIN,
            ("field", "string", "Field path, dot notation for nested fields", true),
            ("type", "string", "Value type: \"string\", \"number\" or \"boolean\"", true),
        ],
    },
    ToolSpec {
        name: "sql_ddl",
        description: "Runs one LuraSQL CREATE TABLE, CREATE INDEX, CREATE VIEW or ALTER TABLE … ADD COLUMN / RENAME COLUMN / RENAME TO on a relational domain.",
        access: Access::Ddl,
        admin_only: false,
        params: &[DOMAIN, SQL, SQL_PARAMS],
    },
];

pub(crate) fn find(name: &str) -> Option<&'static ToolSpec> {
    TOOLS.iter().find(|spec| spec.name == name)
}

impl ToolSpec {
    pub(crate) fn offered(&self, switches: Switches) -> bool {
        switches.offer(self.access)
    }

    fn listed_for(&self, role: Role, switches: Switches) -> bool {
        self.offered(switches) && (role.reaches_admin_routes() || !self.admin_only)
    }

    fn annotations(&self) -> ToolAnnotations {
        match (self.access, self.name) {
            (Access::Read, _) => ToolAnnotations::new().read_only(true),
            // A rename breaks clients as a drop would.
            (Access::Ddl, "sql_ddl") | (Access::Write, _) => ToolAnnotations::new().read_only(false).destructive(true),
            (Access::Ddl, _) => ToolAnnotations::new().read_only(false).destructive(false),
        }
    }

    fn input_schema(&self) -> Arc<JsonObject> {
        let mut properties = Map::new();
        let mut required = Vec::new();
        for (name, kind, description, mandatory) in self.params {
            properties.insert(name.to_string(), json!({ "type": kind, "description": description }));
            if *mandatory {
                required.push(json!(name));
            }
        }
        let mut schema = Map::new();
        schema.insert("type".into(), json!("object"));
        schema.insert("properties".into(), Value::Object(properties));
        if !required.is_empty() {
            schema.insert("required".into(), Value::Array(required));
        }
        Arc::new(schema)
    }

    pub(crate) fn tool(&self) -> Tool {
        Tool::new(self.name, self.description, self.input_schema()).with_annotations(self.annotations())
    }
}

/// The tools `role` sees under `switches`, in catalog order.
pub(crate) fn listed(role: Role, switches: Switches) -> Vec<Tool> {
    TOOLS.iter().filter(|spec| spec.listed_for(role, switches)).map(ToolSpec::tool).collect()
}

/// The requests of one tool call and how their answers combine.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Plan {
    pub(crate) calls: Vec<Call>,
    merge: Merge,
}

#[derive(Debug, Clone, PartialEq)]
enum Merge {
    /// The last answer is the result.
    Last,
    /// One domain listing per engine, in the order of the calls.
    Domains(Vec<&'static str>),
    /// The last answer is a KV value as raw bytes.
    KvValue,
}

impl Plan {
    fn single(call: Call) -> Self {
        Self { calls: vec![call], merge: Merge::Last }
    }

    /// The tool result of the answers to [`Self::calls`], in order.
    pub(crate) fn result(&self, replies: &[Reply]) -> CallToolResult {
        match &self.merge {
            Merge::Last => replies.last().map_or_else(|| tool_error("no answer"), reply_result),
            Merge::Domains(engines) => merge_domains(engines, replies),
            Merge::KvValue => replies.last().map_or_else(|| tool_error("no answer"), kv_value_result),
        }
    }
}

/// A failed call as a tool result.
pub(crate) fn tool_error(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.into())])
}

fn too_large() -> CallToolResult {
    tool_error(format!(
        "the result is larger than {} MiB; reduce `limit` or narrow the request",
        MAX_RESULT_BYTES / (1024 * 1024)
    ))
}

fn status_error(reply: &Reply) -> CallToolResult {
    tool_error(format!("HTTP {}: {}", reply.status, reply.text()))
}

/// A route's answer as a tool result: 2xx as text plus structured content,
/// anything else as an error with the route's status and message.
pub(crate) fn reply_result(reply: &Reply) -> CallToolResult {
    if reply.body.is_none() {
        return too_large();
    }
    if !reply.status.is_success() {
        return status_error(reply);
    }
    match reply.json() {
        Some(value @ Value::Object(_)) => CallToolResult::structured(value),
        Some(value) => CallToolResult::structured(json!({ "result": value })),
        None if reply.text().is_empty() => CallToolResult::structured(json!({ "status": reply.status.as_u16() })),
        None => CallToolResult::success(vec![ContentBlock::text(reply.text())]),
    }
}

/// The raw bytes of a KV value as `{"value": …}`, unchanged: `null` for a key
/// in the NULL state, base64url with `"encoding"` for bytes that are not UTF-8.
fn kv_value_result(reply: &Reply) -> CallToolResult {
    let Some(body) = &reply.body else {
        return too_large();
    };
    if !reply.status.is_success() {
        return status_error(reply);
    }
    if reply.status == StatusCode::NO_CONTENT {
        return CallToolResult::structured(json!({ "value": null }));
    }
    match std::str::from_utf8(body) {
        Ok(text) => CallToolResult::structured(json!({ "value": text })),
        Err(_) => CallToolResult::structured(json!({ "value": base64url(body), "encoding": "base64url" })),
    }
}

/// The domain listings of several engines as one list; an engine that is
/// off is named instead.
fn merge_domains(engines: &[&'static str], replies: &[Reply]) -> CallToolResult {
    let mut domains = Vec::new();
    let mut unavailable = Vec::new();
    for (engine, reply) in engines.iter().zip(replies) {
        if reply.body.is_none() {
            return too_large();
        }
        // A disabled relational engine has no routes at all.
        if matches!(reply.status, StatusCode::SERVICE_UNAVAILABLE | StatusCode::NOT_FOUND) {
            unavailable.push(json!(engine));
            continue;
        }
        let Some(Value::Array(entries)) = reply.json().filter(|_| reply.status.is_success()) else {
            return status_error(reply);
        };
        for mut entry in entries {
            if let Value::Object(fields) = &mut entry {
                fields.insert("engine".into(), json!(engine));
            }
            domains.push(entry);
        }
    }
    CallToolResult::structured(json!({ "domains": domains, "unavailable_engines": unavailable }))
}

/// Why the arguments of a call make no plan: missing or mistyped arguments,
/// or a refused SQL statement.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Refusal(pub(crate) String);

impl Refusal {
    pub(crate) fn into_result(self) -> CallToolResult {
        tool_error(self.0)
    }
}

struct Args<'a>(&'a JsonObject);

impl Args<'_> {
    fn string(&self, name: &str) -> Result<String, Refusal> {
        self.opt_string(name)?.ok_or_else(|| Refusal(format!("missing argument '{name}'")))
    }

    fn opt_string(&self, name: &str) -> Result<Option<String>, Refusal> {
        match self.0.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(Refusal(format!("argument '{name}' must be of type string"))),
        }
    }

    fn opt_scalar(&self, name: &str, kind: &str) -> Result<Option<String>, Refusal> {
        match self.0.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Number(n)) if kind == "integer" && n.as_u64().is_some() => Ok(Some(n.to_string())),
            Some(Value::Bool(b)) if kind == "boolean" => Ok(Some(b.to_string())),
            Some(_) => Err(Refusal(format!("argument '{name}' must be of type {kind}"))),
        }
    }

    fn opt_value(&self, name: &str, kind: &str) -> Result<Option<Value>, Refusal> {
        match self.0.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(v @ Value::Object(_)) if kind == "object" => Ok(Some(v.clone())),
            Some(v @ Value::Array(_)) if kind == "array" => Ok(Some(v.clone())),
            Some(v @ Value::Number(_)) if kind == "integer" && v.as_u64().is_some() => Ok(Some(v.clone())),
            Some(_) => Err(Refusal(format!("argument '{name}' must be of type {kind}"))),
        }
    }

    fn value(&self, name: &str, kind: &str) -> Result<Value, Refusal> {
        self.opt_value(name, kind)?.ok_or_else(|| Refusal(format!("missing argument '{name}'")))
    }

    /// `engine` as the path prefix of its domain routes.
    fn engine(&self, name: &str) -> Result<(&'static str, &'static str), Refusal> {
        match self.string(name)?.as_str() {
            "kv" => Ok(("kv", "/store-api/domains")),
            "json" => Ok(("json", "/store-api/json/domains")),
            "rel" => Ok(("rel", "/store-api/rel/domains")),
            other => Err(Refusal(format!("argument '{name}' must be \"kv\", \"json\" or \"rel\", got '{other}'"))),
        }
    }
}

const ENGINES: [(&str, &str); 3] =
    [("kv", "/store-api/domains"), ("json", "/store-api/json/domains"), ("rel", "/store-api/rel/domains")];

fn path(parts: &[&str]) -> String {
    parts.concat()
}

/// The requests of a call of `spec` with `arguments`. SQL statements pass
/// the prefilter first, with the SQL route's statement limit.
pub(crate) fn plan(spec: &ToolSpec, arguments: &JsonObject, max_statement_len: usize) -> Result<Plan, Refusal> {
    let args = Args(arguments);
    let domain = || args.string("domain").map(|d| encode(&d));
    let key = || args.string("key").map(|k| encode(&k));
    let sql_call = |tool: SqlTool| -> Result<Plan, Refusal> {
        let statement = args.string("sql")?;
        match sql::check(tool, &statement, max_statement_len) {
            Ok(()) => {}
            Err(Rejected::Invalid(message)) => return Err(Refusal(format!("HTTP {}: {message}", StatusCode::BAD_REQUEST))),
            Err(Rejected::NotAllowed(message)) => return Err(Refusal(message)),
        }
        let mut body = Map::new();
        body.insert("sql".into(), json!(statement));
        if let Some(params) = args.opt_value("params", "array")? {
            body.insert("params".into(), params);
        }
        if tool == SqlTool::Query {
            if let Some(expand) = args.opt_value("expand", "array")? {
                body.insert("expand".into(), expand);
            }
        }
        Ok(Plan::single(Call::new(Method::POST, path(&["/store-api/rel/", &domain()?, "/sql"])).json(Value::Object(body))))
    };
    let plan = match spec.name {
        "whoami" => Plan::single(Call::get("/store-api/auth/whoami".into())),
        "list_domains" => {
            let only = args.opt_string("engine")?;
            let selected: Vec<_> = match only {
                None => ENGINES.to_vec(),
                Some(_) => vec![args.engine("engine")?],
            };
            let names = selected.iter().map(|(engine, _)| *engine).collect();
            let calls = selected.iter().map(|(_, route)| Call::get(route.to_string())).collect();
            Plan { calls, merge: Merge::Domains(names) }
        }
        "describe_domain" => {
            let (_, route) = args.engine("engine")?;
            Plan::single(Call::get(path(&[route, "/", &encode(&args.string("name")?)])))
        }
        "metrics" => Plan::single(Call::get("/store-api/metrics".into())),
        "list_tables" => Plan::single(Call::get(path(&["/store-api/rel/", &domain()?, "/tables"]))),
        "describe_table" => Plan::single(Call::get(path(&[
            "/store-api/rel/",
            &domain()?,
            "/tables/",
            &encode(&args.string("table")?),
        ]))),
        "list_views" => Plan::single(Call::get(path(&["/store-api/rel/", &domain()?, "/views"]))),
        "list_json_indexes" => Plan::single(Call::get(path(&["/store-api/json/", &domain()?, "/indexes"]))),
        // `/health` is open without a key: whoami first, so the tool still
        // needs a valid one.
        "health" => Plan {
            calls: vec![Call::get("/store-api/auth/whoami".into()), Call::get("/health".into())],
            merge: Merge::Last,
        },
        "kv_get" => Plan {
            calls: vec![Call::get(path(&["/store-api/kv/", &domain()?, "/keys/", &key()?]))],
            merge: Merge::KvValue,
        },
        "kv_scan" => Plan::single(
            Call::get(path(&["/store-api/kv/", &domain()?, "/keys"]))
                .query("prefix", args.opt_string("prefix")?)
                .query("contains", args.opt_string("contains")?)
                .query("limit", args.opt_scalar("limit", "integer")?)
                .query("offset", args.opt_scalar("offset", "integer")?),
        ),
        "kv_count" => Plan::single(
            Call::get(path(&["/store-api/kv/", &domain()?, "/count"])).query("prefix", args.opt_string("prefix")?),
        ),
        "json_get" => Plan::single(Call::get(path(&["/store-api/json/", &domain()?, "/documents/", &key()?]))),
        "json_list" => Plan::single(
            Call::get(path(&["/store-api/json/", &domain()?, "/documents"]))
                .query("limit", args.opt_scalar("limit", "integer")?)
                .query("offset", args.opt_scalar("offset", "integer")?)
                .query("keys_only", args.opt_scalar("keys_only", "boolean")?),
        ),
        "json_search" => {
            let mut body = Map::new();
            for (name, kind) in [("filter", "object"), ("limit", "integer"), ("offset", "integer")] {
                if let Some(value) = args.opt_value(name, kind)? {
                    body.insert(name.into(), value);
                }
            }
            Plan::single(Call::new(Method::POST, path(&["/store-api/json/", &domain()?, "/search"])).json(Value::Object(body)))
        }
        "json_count" => Plan::single(Call::get(path(&["/store-api/json/", &domain()?, "/documents/count"]))),
        "sql_query" => sql_call(SqlTool::Query)?,
        "kv_put" => Plan::single(
            Call::new(Method::PUT, path(&["/store-api/kv/", &domain()?, "/keys/", &key()?]))
                .query("ttl", args.opt_scalar("ttl", "integer")?)
                .text(args.string("value")?),
        ),
        "kv_delete" => Plan::single(Call::new(Method::DELETE, path(&["/store-api/kv/", &domain()?, "/keys/", &key()?]))),
        "kv_set_null" => {
            Plan::single(Call::new(Method::PATCH, path(&["/store-api/kv/", &domain()?, "/keys/", &key()?, "/null"])))
        }
        "json_put" => Plan::single(
            Call::new(Method::PUT, path(&["/store-api/json/", &domain()?, "/documents/", &key()?]))
                .json(args.value("document", "object")?),
        ),
        "json_delete" => {
            Plan::single(Call::new(Method::DELETE, path(&["/store-api/json/", &domain()?, "/documents/", &key()?])))
        }
        "sql_execute" => sql_call(SqlTool::Execute)?,
        "create_domain" => {
            let (_, route) = args.engine("engine")?;
            Plan::single(Call::new(Method::POST, route.to_string()).json(json!({ "name": args.string("name")? })))
        }
        "create_json_index" => Plan::single(
            Call::new(Method::POST, path(&["/store-api/json/", &domain()?, "/indexes"]))
                .json(json!({ "field": args.string("field")?, "type": args.string("type")? })),
        ),
        "sql_ddl" => sql_call(SqlTool::Ddl)?,
        other => return Err(Refusal(format!("unknown tool '{other}'"))),
    };
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;

    fn args(value: Value) -> JsonObject {
        value.as_object().unwrap().clone()
    }

    fn plan_of(name: &str, arguments: Value) -> Result<Plan, Refusal> {
        plan(find(name).unwrap(), &args(arguments), crate::engines::rel::MAX_STATEMENT_LEN)
    }

    fn only_call(name: &str, arguments: Value) -> Call {
        let plan = plan_of(name, arguments).unwrap();
        assert_eq!(plan.calls.len(), 1, "{name}");
        plan.calls[0].clone()
    }

    fn reply(status: u16, body: &str) -> Reply {
        Reply { status: StatusCode::from_u16(status).unwrap(), body: Some(Bytes::from(body.to_string())) }
    }

    const ALL: Switches = Switches { read_only: false, allow_ddl: true };
    const READ_ONLY: Switches = Switches { read_only: true, allow_ddl: false };

    fn names(tools: &[Tool]) -> Vec<String> {
        tools.iter().map(|tool| tool.name.to_string()).collect()
    }

    #[test]
    fn read_tools_map_to_get_requests() {
        let d = json!({"domain": "shop", "key": "a/b clé", "table": "orders", "name": "shop", "engine": "json"});
        let cases = [
            ("whoami", "/store-api/auth/whoami"),
            ("describe_domain", "/store-api/json/domains/shop"),
            ("metrics", "/store-api/metrics"),
            ("list_tables", "/store-api/rel/shop/tables"),
            ("describe_table", "/store-api/rel/shop/tables/orders"),
            ("list_views", "/store-api/rel/shop/views"),
            ("list_json_indexes", "/store-api/json/shop/indexes"),
            ("kv_get", "/store-api/kv/shop/keys/a%2Fb%20cl%C3%A9"),
            ("kv_count", "/store-api/kv/shop/count"),
            ("json_get", "/store-api/json/shop/documents/a%2Fb%20cl%C3%A9"),
            ("json_count", "/store-api/json/shop/documents/count"),
        ];
        for (name, target) in cases {
            let call = only_call(name, d.clone());
            assert_eq!((call.method.clone(), call.target(), call.body.clone()), (Method::GET, target.to_string(), None), "{name}");
        }
    }

    #[test]
    fn list_tools_pass_paging_and_filters_as_query() {
        let call = only_call("kv_scan", json!({"domain": "d", "prefix": "user:", "contains": "x", "limit": 10, "offset": 20}));
        assert_eq!(call.target(), "/store-api/kv/d/keys?prefix=user%3A&contains=x&limit=10&offset=20");
        let call = only_call("json_list", json!({"domain": "d", "limit": 5, "keys_only": true}));
        assert_eq!(call.target(), "/store-api/json/d/documents?limit=5&keys_only=true");
        let call = only_call("kv_count", json!({"domain": "d", "prefix": "p"}));
        assert_eq!(call.target(), "/store-api/kv/d/count?prefix=p");
        let call = only_call("json_search", json!({"domain": "d", "filter": {"age": {"$gt": 3}}, "limit": 2}));
        assert_eq!((call.method.clone(), call.target()), (Method::POST, "/store-api/json/d/search".to_string()));
        assert_eq!(call.body, Some(super::super::internal::CallBody::Json(json!({"filter": {"age": {"$gt": 3}}, "limit": 2}))));
    }

    #[test]
    fn write_and_structure_tools_map_to_their_routes() {
        use super::super::internal::CallBody;
        let call = only_call("kv_put", json!({"domain": "d", "key": "k", "value": "clé ✓", "ttl": 60}));
        assert_eq!((call.method.clone(), call.target()), (Method::PUT, "/store-api/kv/d/keys/k?ttl=60".to_string()));
        assert_eq!(call.body, Some(CallBody::Text("clé ✓".into())));
        let call = only_call("kv_delete", json!({"domain": "d", "key": "k"}));
        assert_eq!((call.method.clone(), call.target()), (Method::DELETE, "/store-api/kv/d/keys/k".to_string()));
        let call = only_call("kv_set_null", json!({"domain": "d", "key": "k"}));
        assert_eq!((call.method.clone(), call.target()), (Method::PATCH, "/store-api/kv/d/keys/k/null".to_string()));
        let call = only_call("json_put", json!({"domain": "d", "key": "k", "document": {"n": 1}}));
        assert_eq!((call.method.clone(), call.target()), (Method::PUT, "/store-api/json/d/documents/k".to_string()));
        assert_eq!(call.body, Some(CallBody::Json(json!({"n": 1}))));
        let call = only_call("json_delete", json!({"domain": "d", "key": "k"}));
        assert_eq!((call.method.clone(), call.target()), (Method::DELETE, "/store-api/json/d/documents/k".to_string()));
        for (engine, route) in [("kv", "/store-api/domains"), ("json", "/store-api/json/domains"), ("rel", "/store-api/rel/domains")] {
            let call = only_call("create_domain", json!({"engine": engine, "name": "n"}));
            assert_eq!((call.method.clone(), call.target()), (Method::POST, route.to_string()));
            assert_eq!(call.body, Some(CallBody::Json(json!({"name": "n"}))));
        }
        let call = only_call("create_json_index", json!({"domain": "d", "field": "a.b", "type": "string"}));
        assert_eq!((call.method.clone(), call.target()), (Method::POST, "/store-api/json/d/indexes".to_string()));
        assert_eq!(call.body, Some(CallBody::Json(json!({"field": "a.b", "type": "string"}))));
    }

    #[test]
    fn sql_tools_post_their_statement_after_the_prefilter() {
        use super::super::internal::CallBody;
        let cases = [
            ("sql_query", "SELECT id FROM t"),
            ("sql_execute", "INSERT INTO t VALUES (1)"),
            ("sql_ddl", "CREATE TABLE t (id INTEGER PRIMARY KEY)"),
        ];
        for (name, statement) in cases {
            let call = only_call(name, json!({"domain": "sales", "sql": statement, "params": [1]}));
            assert_eq!((call.method.clone(), call.target()), (Method::POST, "/store-api/rel/sales/sql".to_string()), "{name}");
            assert_eq!(call.body, Some(CallBody::Json(json!({"sql": statement, "params": [1]}))), "{name}");
        }
        let call = only_call("sql_query", json!({"domain": "s", "sql": "SELECT * FROM t", "expand": ["*"]}));
        assert_eq!(call.body, Some(CallBody::Json(json!({"sql": "SELECT * FROM t", "expand": ["*"]}))));

        let refused = plan_of("sql_ddl", json!({"domain": "s", "sql": "DROP TABLE t"})).unwrap_err();
        assert!(matches!(&refused, Refusal(m) if m.contains("not available over MCP")), "{refused:?}");
        let refused = plan_of("sql_query", json!({"domain": "s", "sql": "SELEC x"})).unwrap_err();
        assert!(matches!(&refused, Refusal(m) if m.starts_with("HTTP 400 Bad Request: ")), "{refused:?}");
    }

    #[test]
    fn list_domains_asks_every_engine_or_the_one_named() {
        let plan = plan_of("list_domains", json!({})).unwrap();
        let targets: Vec<String> = plan.calls.iter().map(Call::target).collect();
        assert_eq!(targets, ["/store-api/domains", "/store-api/json/domains", "/store-api/rel/domains"]);
        let plan = plan_of("list_domains", json!({"engine": "rel"})).unwrap();
        assert_eq!(plan.calls, vec![Call::get("/store-api/rel/domains".into())]);
    }

    #[test]
    fn health_checks_the_key_before_the_open_probe() {
        let plan = plan_of("health", json!({})).unwrap();
        let targets: Vec<String> = plan.calls.iter().map(Call::target).collect();
        assert_eq!(targets, ["/store-api/auth/whoami", "/health"]);
        let result = plan.result(&[reply(200, r#"{"role":"User"}"#), reply(200, r#"{"status":"ok"}"#)]);
        assert_eq!(result.structured_content, Some(json!({"status": "ok"})));
    }

    #[test]
    fn missing_or_mistyped_arguments_are_refused() {
        let refused = plan_of("kv_get", json!({"domain": "d"})).unwrap_err();
        assert_eq!(refused, Refusal("missing argument 'key'".into()));
        let refused = plan_of("kv_scan", json!({"domain": "d", "limit": "ten"})).unwrap_err();
        assert_eq!(refused, Refusal("argument 'limit' must be of type integer".into()));
        let refused = plan_of("describe_domain", json!({"engine": "graph", "name": "n"})).unwrap_err();
        assert!(matches!(refused, Refusal(m) if m.contains("\"kv\", \"json\" or \"rel\"")));
    }

    #[test]
    fn list_domains_merges_the_engines_and_names_the_unavailable_ones() {
        let plan = plan_of("list_domains", json!({})).unwrap();
        let replies = [
            reply(200, r#"[{"name":"a"},{"name":"b"}]"#),
            reply(503, "503 Service Unavailable: the JSON engine is disabled"),
            reply(200, r#"[{"name":"s"}]"#),
        ];
        let result = plan.result(&replies);
        assert_eq!(result.is_error, Some(false));
        assert_eq!(
            result.structured_content,
            Some(json!({
                "domains": [{"name": "a", "engine": "kv"}, {"name": "b", "engine": "kv"}, {"name": "s", "engine": "rel"}],
                "unavailable_engines": ["json"],
            }))
        );
        let replies = [reply(200, "[]"), reply(200, "[]"), reply(404, "")];
        let result = plan.result(&replies);
        assert_eq!(result.structured_content, Some(json!({"domains": [], "unavailable_engines": ["rel"]})));
        let replies = [reply(200, "[]"), reply(500, "boom"), reply(200, "[]")];
        assert_eq!(plan.result(&replies).is_error, Some(true));
    }

    #[test]
    fn answers_become_tool_results() {
        let result = reply_result(&reply(200, r#"{"name":"a"}"#));
        assert_eq!((result.is_error, result.structured_content.clone()), (Some(false), Some(json!({"name": "a"}))));
        assert_eq!(result.content.len(), 1);
        let result = reply_result(&reply(200, "[1,2]"));
        assert_eq!(result.structured_content, Some(json!({"result": [1, 2]})));
        let result = reply_result(&reply(200, "clé ✓"));
        assert_eq!((result.is_error, result.structured_content.clone()), (Some(false), None));
        assert_eq!(result.content[0].as_text().unwrap().text, "clé ✓");
        let result = reply_result(&reply(204, ""));
        assert_eq!(result.structured_content, Some(json!({"status": 204})));

        for (status, body) in [(403, "Forbidden"), (404, "404 Not Found: key"), (503, "503 Service Unavailable: busy")] {
            let result = reply_result(&reply(status, body));
            assert_eq!(result.is_error, Some(true), "{status}");
            let text = &result.content[0].as_text().unwrap().text;
            assert_eq!(text, &format!("HTTP {}: {body}", StatusCode::from_u16(status).unwrap()));
        }
        let result = reply_result(&Reply { status: StatusCode::OK, body: None });
        assert_eq!(result.is_error, Some(true));
        assert!(result.content[0].as_text().unwrap().text.contains("reduce `limit`"));
    }

    #[test]
    fn kv_get_returns_the_value_byte_for_byte() {
        let plan = plan_of("kv_get", json!({"domain": "d", "key": "k"})).unwrap();
        let bytes = |status: u16, body: &[u8]| Reply {
            status: StatusCode::from_u16(status).unwrap(),
            body: Some(Bytes::copy_from_slice(body)),
        };
        let mut cases = vec![
            (reply(200, "clé ✓"), json!({"value": "clé ✓"})),
            (reply(200, ""), json!({"value": ""})),
            (reply(204, ""), json!({"value": null})),
            (bytes(200, &[0xff, 0x00, 0x41]), json!({"value": "_wBB", "encoding": "base64url"})),
        ];
        for body in [r#"{"status":204}"#, "12345678901234567890123", r#""hello""#, r#"{"b": 1, "a": 2}"#] {
            cases.push((reply(200, body), json!({ "value": body })));
        }
        for (reply, expected) in cases {
            let result = plan.result(&[reply]);
            assert_eq!((result.is_error, result.structured_content.clone()), (Some(false), Some(expected.clone())));
            assert_eq!(result.content.len(), 1);
            assert_eq!(result.content[0].as_text().unwrap().text, serde_json::to_string(&expected).unwrap());
        }

        let result = plan.result(&[reply(404, "404 Not Found: key")]);
        assert_eq!(result.is_error, Some(true));
        assert_eq!(result.content[0].as_text().unwrap().text, "HTTP 404 Not Found: 404 Not Found: key");
        let result = plan.result(&[Reply { status: StatusCode::OK, body: None }]);
        assert_eq!(result.is_error, Some(true));
        assert!(result.content[0].as_text().unwrap().text.contains("reduce `limit`"));
    }

    #[test]
    fn tools_list_follows_the_role_and_the_switches() {
        let read: Vec<&str> = TOOLS.iter().filter(|t| t.access == Access::Read).map(|t| t.name).collect();
        let writes = ["kv_put", "kv_delete", "kv_set_null", "json_put", "json_delete", "sql_execute"];
        let ddl = ["create_domain", "create_json_index", "sql_ddl"];
        let admin_only = ["metrics", "create_domain"];
        let switch_sets = [
            (READ_ONLY, read.clone()),
            (Switches { read_only: true, allow_ddl: true }, read.clone()),
            (Switches { read_only: false, allow_ddl: false }, [read.clone(), writes.to_vec()].concat()),
            (ALL, [read.clone(), writes.to_vec(), ddl.to_vec()].concat()),
        ];
        for (switches, offered) in switch_sets {
            for role in [Role::Admin, Role::Disabled, Role::TrustedPeer] {
                assert_eq!(names(&listed(role, switches)), offered, "{role:?} {switches:?}");
            }
            let for_user: Vec<&str> = offered.iter().copied().filter(|name| !admin_only.contains(name)).collect();
            assert_eq!(names(&listed(Role::User, switches)), for_user, "User {switches:?}");
        }
    }

    #[test]
    fn annotations_mark_reads_writes_and_structure() {
        for tool in listed(Role::Admin, ALL) {
            let hints = tool.annotations.clone().unwrap();
            let expected = match tool.name.as_ref() {
                "kv_put" | "kv_delete" | "kv_set_null" | "json_put" | "json_delete" | "sql_execute" | "sql_ddl" => {
                    (Some(false), Some(true))
                }
                "create_domain" | "create_json_index" => (Some(false), Some(false)),
                _ => (Some(true), None),
            };
            assert_eq!((hints.read_only_hint, hints.destructive_hint), expected, "{}", tool.name);
        }
    }

    #[test]
    fn every_tool_has_an_object_schema_with_its_required_parameters() {
        let tool = find("kv_put").unwrap().tool();
        let schema = Value::Object(tool.input_schema.as_ref().clone());
        assert_eq!(schema["type"], json!("object"));
        assert_eq!(schema["required"], json!(["domain", "key", "value"]));
        assert_eq!(schema["properties"]["ttl"]["type"], json!("integer"));
        assert_eq!(TOOLS.len(), 26);
    }

    #[test]
    fn roles_come_from_whoami() {
        for (role, expected) in [("Admin", Role::Admin), ("User", Role::User), ("Disabled", Role::Disabled), ("TrustedPeer", Role::TrustedPeer)] {
            assert_eq!(Role::from_whoami(&json!({"name": null, "role": role})), Some(expected));
        }
        assert_eq!(Role::from_whoami(&json!({"role": "Root"})), None);
    }
}
