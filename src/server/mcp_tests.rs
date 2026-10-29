//! The MCP listener in the full topology: JSON-RPC requests written by hand
//! over raw TCP, as an MCP client sends them.

use super::tests::{exchange, test_config};
use super::*;
use crate::config::AdminEntry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const ADMIN: &str = "admin";

/// A raw HTTP/1.1 request with `Connection: close`.
pub(super) fn http(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> String {
    String::from_utf8(http_bytes(method, path, headers, body.as_bytes())).unwrap()
}

/// [`http`] with a body that need not be UTF-8.
fn http_bytes(method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut raw = format!("{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n");
    for (name, value) in headers {
        raw.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty() || method == "POST" || method == "PUT" {
        raw.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    raw.push_str("\r\n");
    let mut raw = raw.into_bytes();
    raw.extend_from_slice(body);
    raw
}

/// A REST request with `key` as Bearer.
pub(super) fn rest_call(method: &str, path: &str, key: Option<&str>, body: &str) -> String {
    let bearer = key.map(|key| format!("Bearer {key}"));
    let mut headers = vec![("Content-Type", "application/json")];
    if let Some(bearer) = &bearer {
        headers.push(("Authorization", bearer.as_str()));
    }
    http(method, path, &headers, body)
}

/// The first JSON-RPC message of a response body, plain JSON or an event stream.
pub(super) fn rpc_message(body: &[u8]) -> Option<Value> {
    let text = String::from_utf8_lossy(body);
    if let Ok(value) = serde_json::from_str::<Value>(&text) {
        return Some(value);
    }
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str::<Value>(data.trim()).ok())
        .find(|message| message.get("jsonrpc").is_some())
}

/// An MCP client session, written by hand.
pub(super) struct Client {
    pub(super) addr: SocketAddr,
    pub(super) key: Option<String>,
    pub(super) session: Option<String>,
    next_id: u64,
}

/// The answer to one MCP request: status, lower-cased head, JSON-RPC message.
pub(super) struct Answer {
    pub(super) status: u16,
    pub(super) head: String,
    pub(super) message: Option<Value>,
}

impl Answer {
    pub(super) fn result(&self) -> &Value {
        let message = self.message.as_ref().unwrap_or_else(|| panic!("no message: {}", self.head));
        message.get("result").unwrap_or_else(|| panic!("no result: {message}"))
    }

    /// The text of a tool result's first content block.
    pub(super) fn text(&self) -> String {
        self.result()["content"][0]["text"].as_str().unwrap_or_default().to_string()
    }

    pub(super) fn is_error(&self) -> bool {
        self.result()["isError"] == json!(true)
    }
}

impl Client {
    pub(super) fn new(addr: SocketAddr, key: Option<&str>) -> Self {
        Self { addr, key: key.map(String::from), session: None, next_id: 1 }
    }

    pub(super) async fn post(&mut self, message: &Value) -> Answer {
        let bearer = self.key.as_ref().map(|key| format!("Bearer {key}"));
        let mut headers =
            vec![("Content-Type", "application/json"), ("Accept", "application/json, text/event-stream")];
        if let Some(bearer) = &bearer {
            headers.push(("Authorization", bearer.as_str()));
        }
        if let Some(session) = &self.session {
            headers.push(("Mcp-Session-Id", session.as_str()));
        }
        let (status, head, body) = exchange(self.addr, &http("POST", "/mcp", &headers, &message.to_string())).await;
        Answer { status, head, message: rpc_message(&body) }
    }

    pub(super) async fn request(&mut self, method: &str, params: Value) -> Answer {
        let id = self.next_id;
        self.next_id += 1;
        self.post(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })).await
    }

    /// `initialize` and `notifications/initialized`; keeps the session.
    pub(super) async fn initialize(&mut self) -> Answer {
        let params = json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "1.0" },
        });
        let answer = self.request("initialize", params).await;
        if answer.status == 200 {
            self.session = answer
                .head
                .lines()
                .find_map(|line| line.strip_prefix("mcp-session-id: "))
                .map(|id| id.trim().to_string());
            let notified = self.post(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).await;
            assert_eq!(notified.status, 202, "{}", notified.head);
        }
        answer
    }

    pub(super) async fn call(&mut self, tool: &str, arguments: Value) -> Answer {
        self.request("tools/call", json!({ "name": tool, "arguments": arguments })).await
    }

    pub(super) async fn tool_names(&mut self) -> Vec<String> {
        let answer = self.request("tools/list", json!({})).await;
        assert_eq!(answer.status, 200, "{}", answer.head);
        answer.result()["tools"].as_array().unwrap().iter().map(|tool| tool["name"].as_str().unwrap().to_string()).collect()
    }
}

/// The test config with MCP on an ephemeral port, changed by `tune`.
pub(super) fn mcp_config(dir: &Path, tune: impl FnOnce(&mut LuraConfig)) -> LuraConfig {
    let mut cfg = test_config(dir);
    cfg.mcp.enabled = true;
    cfg.mcp.port = 0;
    tune(&mut cfg);
    cfg
}

/// Auth on with one admin, `admin_key`.
pub(super) fn with_admin(cfg: &mut LuraConfig, admin_key: &str) {
    cfg.auth.enabled = true;
    cfg.auth.admins = vec![AdminEntry { name: ADMIN.to_string(), api_key: admin_key.to_string() }];
}

/// Starts a server with MCP on, runs `client` against its REST and MCP
/// addresses on a client runtime, then shuts it down.
pub(super) fn with_mcp<F, Fut>(tune: impl FnOnce(&mut LuraConfig), client: F)
where
    F: FnOnce(SocketAddr, SocketAddr) -> Fut,
    Fut: Future<Output = ()>,
{
    let dir = tempfile::TempDir::new().unwrap();
    let cfg = mcp_config(dir.path(), tune);
    let server = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).unwrap();
    let (rest, mcp) = (server.http_addr.unwrap(), server.mcp_addr.expect("MCP listener enabled"));
    tokio::runtime::Runtime::new().unwrap().block_on(client(rest, mcp));
    server.shutdown().unwrap();
}

/// Creates the user `name` over REST and returns its API key.
pub(super) async fn create_user(rest: SocketAddr, admin_key: &str, name: &str) -> String {
    let body = json!({ "name": name }).to_string();
    let (status, body) =
        super::tests::request(rest, &rest_call("POST", "/store-api/auth/users", Some(admin_key), &body)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    serde_json::from_slice::<Value>(&body).unwrap()["api_key"].as_str().unwrap().to_string()
}

/// Grants `user` `access` on the domain `domain` of `store_type`.
async fn grant(rest: SocketAddr, admin_key: &str, user: &str, store_type: &str, domain: &str, access: &str) {
    let body = json!({ "domain": domain, "access": access, "store_type": store_type }).to_string();
    rest_ok(rest, "POST", &format!("/store-api/auth/users/{user}/permissions"), admin_key, &body).await;
}

/// A REST request with `key` that must succeed.
pub(super) async fn rest_ok(addr: SocketAddr, method: &str, path: &str, key: &str, body: &str) {
    let (status, answer) = super::tests::request(addr, &rest_call(method, path, Some(key), body)).await;
    assert!(status < 300, "{method} {path}: {status} {}", String::from_utf8_lossy(&answer));
}

// Off by default: no MCP listener, no MCP runtime thread.
#[test]
fn mcp_is_off_by_default() {
    let dir = tempfile::TempDir::new().unwrap();
    let server = Server::start(Arc::new(test_config(dir.path())), &dir.path().join("luradb.toml")).unwrap();
    assert_eq!(server.mcp_addr, None);
    assert!(server.mcp.is_none());
    server.shutdown().unwrap();
}

// Without auth: the handshake, the tool list with every switch and a tool
// call across the bridge.
#[test]
fn a_client_initializes_lists_and_calls_tools_without_auth() {
    with_mcp(
        |cfg| {
            cfg.mcp.read_only = false;
            cfg.mcp.allow_ddl = true;
        },
        |rest, mcp| async move {
            let mut client = Client::new(mcp, None);
            let answer = client.initialize().await;
            assert_eq!(answer.status, 200, "{}", answer.head);
            assert_eq!(answer.result()["serverInfo"]["name"], json!("luradb"));
            assert!(client.session.is_some(), "{}", answer.head);
            let names = client.tool_names().await;
            assert_eq!(names.len(), 26, "{names:?}");

            let put = client.call("kv_put", json!({"domain": "default", "key": "clé", "value": "✓ v"})).await;
            assert!(!put.is_error(), "{}", put.text());
            let (status, value) = super::tests::request(rest, &super::tests::get("/store-api/kv/default/keys/cl%C3%A9")).await;
            assert_eq!((status, value.as_slice()), (200, "✓ v".as_bytes()));
            let whoami = client.call("whoami", json!({})).await;
            assert_eq!(whoami.result()["structuredContent"]["role"], json!("Disabled"));
        },
    );
}

// No key or an invalid one: 401 with the Bearer challenge already at
// `initialize`, and at `tools/call` too.
#[test]
fn requests_without_a_valid_key_get_401() {
    let admin_key = "lura_mcp_401_admin";
    with_mcp(
        |cfg| with_admin(cfg, admin_key),
        |_, mcp| async move {
            for key in [None, Some("lura_not_a_key")] {
                let mut client = Client::new(mcp, key);
                let answer = client.initialize().await;
                assert_eq!(answer.status, 401, "{key:?}");
                assert!(answer.head.contains("www-authenticate: bearer"), "{}", answer.head);
                let answer = client.call("kv_get", json!({"domain": "default", "key": "k"})).await;
                assert_eq!(answer.status, 401, "{key:?}: {}", answer.head);
                assert!(answer.head.contains("www-authenticate: bearer"), "{}", answer.head);
                // A tool that runs nothing, or none at all, needs the key too.
                let answer = client.call("no_such_tool", json!({})).await;
                assert_eq!(answer.status, 401, "{key:?}");
                let answer = client.call("health", json!({})).await;
                assert_eq!(answer.status, 401, "{key:?}");
            }
            let answer = Client::new(mcp, Some("lura_not_a_key")).initialize().await;
            assert!(answer.head.contains("error=\"invalid_token\""), "{}", answer.head);
        },
    );
}

// A tool call runs exactly its own request, no whoami in front.
#[test]
fn a_tool_call_runs_one_internal_request() {
    let admin_key = "lura_mcp_one_request_admin";
    with_mcp(
        |cfg| with_admin(cfg, admin_key),
        |_, mcp| async move {
            let mut client = Client::new(mcp, Some(admin_key));
            assert_eq!(client.initialize().await.status, 200);
            let before = crate::mcp::test_hook::calls_with(admin_key).len();
            let answer = client.call("kv_get", json!({"domain": "default", "key": "missing"})).await;
            assert_eq!(answer.status, 200);
            let after = crate::mcp::test_hook::calls_with(admin_key);
            assert_eq!(after[before..], ["GET /store-api/kv/default/keys/missing".to_string()]);
        },
    );
}

// A deleted user's key stops working on the open session at once.
#[test]
fn a_revoked_key_fails_without_reconnecting() {
    let admin_key = "lura_mcp_revoked_admin";
    with_mcp(
        |cfg| with_admin(cfg, admin_key),
        |rest, mcp| async move {
            let key = create_user(rest, admin_key, "leaving").await;
            let mut client = Client::new(mcp, Some(&key));
            assert_eq!(client.initialize().await.status, 200);
            assert_eq!(client.request("tools/list", json!({})).await.status, 200);
            rest_ok(rest, "DELETE", "/store-api/auth/users/leaving", admin_key, "").await;
            assert_eq!(client.request("tools/list", json!({})).await.status, 401);
            let answer = client.call("kv_get", json!({"domain": "default", "key": "k"})).await;
            assert_eq!(answer.status, 401);
            assert!(answer.head.contains("error=\"invalid_token\""), "{}", answer.head);
            let answer = client.request("resources/read", json!({"uri": "luradb://domains"})).await;
            assert_eq!(answer.status, 401);
        },
    );
}

// The resources: the domain list and a domain's schema, read with the
// caller's key.
#[test]
fn resources_list_and_read_the_schema() {
    with_mcp(
        |cfg| cfg.rel.enabled = true,
        |rest, mcp| async move {
            let (status, _) = super::tests::request(rest, &rest_call("POST", "/store-api/rel/domains", None, r#"{"name":"sales"}"#)).await;
            assert_eq!(status, 201);
            let sql = json!({"sql": "CREATE TABLE orders (id INTEGER PRIMARY KEY)"}).to_string();
            let (status, _) = super::tests::request(rest, &rest_call("POST", "/store-api/rel/sales/sql", None, &sql)).await;
            assert_eq!(status, 200);

            let mut client = Client::new(mcp, None);
            assert_eq!(client.initialize().await.status, 200);
            let listed = client.request("resources/list", json!({})).await;
            assert_eq!(listed.result()["resources"][0]["uri"], json!("luradb://domains"));
            let templates = client.request("resources/templates/list", json!({})).await;
            assert_eq!(templates.result()["resourceTemplates"][0]["uriTemplate"], json!("luradb://{engine}/{name}/schema"));

            let read = client.request("resources/read", json!({"uri": "luradb://rel/sales/schema"})).await;
            let text = read.result()["contents"][0]["text"].as_str().unwrap().to_string();
            let schema: Value = serde_json::from_str(&text).unwrap();
            assert!(schema["tables"].to_string().contains("orders") && schema["views"] == json!([]), "{schema}");
            let read = client.request("resources/read", json!({"uri": "luradb://domains"})).await;
            assert!(read.result()["contents"][0]["text"].as_str().unwrap().contains("\"sales\""));
            let missing = client.request("resources/read", json!({"uri": "luradb://rel/nowhere/schema"})).await;
            assert!(missing.message.unwrap().get("error").is_some());
        },
    );
}

// A user key sees neither the admin tools nor other users' domains; with
// read access it reads, a write is the route's 403.
#[test]
fn a_user_key_sees_and_does_what_its_permissions_allow() {
    let admin_key = "lura_mcp_user_admin";
    with_mcp(
        |cfg| {
            with_admin(cfg, admin_key);
            cfg.rel.enabled = true;
            cfg.mcp.read_only = false;
            cfg.mcp.allow_ddl = true;
        },
        |rest, mcp| async move {
            for (route, name) in [("/store-api/domains", "mine"), ("/store-api/domains", "theirs"), ("/store-api/rel/domains", "mine")] {
                rest_ok(rest, "POST", route, admin_key, &json!({ "name": name }).to_string()).await;
            }
            let sql = json!({"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY)"}).to_string();
            rest_ok(rest, "POST", "/store-api/rel/mine/sql", admin_key, &sql).await;
            rest_ok(rest, "PUT", "/store-api/kv/mine/keys/k", admin_key, "clé").await;
            let key = create_user(rest, admin_key, "reader").await;
            grant(rest, admin_key, "reader", "kv", "mine", "read").await;
            grant(rest, admin_key, "reader", "rel", "mine", "read").await;

            let mut client = Client::new(mcp, Some(&key));
            assert_eq!(client.initialize().await.status, 200);
            let names = client.tool_names().await;
            for hidden in ["metrics", "create_domain"] {
                assert!(!names.contains(&hidden.to_string()), "{hidden}: {names:?}");
            }
            assert!(names.contains(&"kv_put".to_string()) && names.contains(&"sql_ddl".to_string()), "{names:?}");

            let domains = client.call("list_domains", json!({})).await;
            let listed: Vec<(String, String)> = domains.result()["structuredContent"]["domains"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| (d["engine"].as_str().unwrap().to_string(), d["name"].as_str().unwrap().to_string()))
                .collect();
            assert_eq!(listed, [("kv".to_string(), "mine".to_string()), ("rel".to_string(), "mine".to_string())]);

            let tables = client.call("list_tables", json!({"domain": "mine"})).await;
            assert!(!tables.is_error() && tables.text().contains("\"t\""), "{}", tables.text());
            let value = client.call("kv_get", json!({"domain": "mine", "key": "k"})).await;
            assert_eq!(value.result()["structuredContent"]["value"], json!("clé"));
            let put = client.call("kv_put", json!({"domain": "mine", "key": "k", "value": "x"})).await;
            assert!(put.is_error() && put.text().starts_with("HTTP 403"), "{}", put.text());
            let create = client.call("create_domain", json!({"engine": "kv", "name": "new"})).await;
            assert!(create.is_error() && create.text().starts_with("HTTP 403"), "{}", create.text());
            let metrics = client.call("metrics", json!({})).await;
            assert!(metrics.is_error() && metrics.text().starts_with("HTTP 403"), "{}", metrics.text());
        },
    );
}

// An admin key reads, writes and creates structure in every engine; the
// domain list spans all three.
#[test]
fn an_admin_key_works_every_engine() {
    let admin_key = "lura_mcp_engines_admin";
    with_mcp(
        |cfg| {
            with_admin(cfg, admin_key);
            cfg.json.enabled = true;
            cfg.rel.enabled = true;
            cfg.mcp.read_only = false;
            cfg.mcp.allow_ddl = true;
        },
        |_, mcp| async move {
            let mut client = Client::new(mcp, Some(admin_key));
            assert_eq!(client.initialize().await.status, 200);
            let ok = |answer: Answer| {
                assert_eq!(answer.status, 200, "{}", answer.head);
                assert!(!answer.is_error(), "{}", answer.text());
                answer
            };
            for engine in ["kv", "json", "rel"] {
                ok(client.call("create_domain", json!({"engine": engine, "name": "zoo"})).await);
            }
            let listed = ok(client.call("list_domains", json!({})).await);
            let engines: Vec<&str> = listed.result()["structuredContent"]["domains"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|d| d["name"] == json!("zoo"))
                .map(|d| d["engine"].as_str().unwrap())
                .collect();
            assert_eq!(engines, ["kv", "json", "rel"]);
            assert_eq!(listed.result()["structuredContent"]["unavailable_engines"], json!([]));

            ok(client.call("kv_put", json!({"domain": "zoo", "key": "k", "value": "clé"})).await);
            let value = ok(client.call("kv_get", json!({"domain": "zoo", "key": "k"})).await);
            assert_eq!(value.result()["structuredContent"]["value"], json!("clé"));
            ok(client.call("kv_set_null", json!({"domain": "zoo", "key": "k"})).await);
            ok(client.call("kv_delete", json!({"domain": "zoo", "key": "k"})).await);
            assert_eq!(ok(client.call("kv_count", json!({"domain": "zoo"})).await).result()["structuredContent"]["count"], json!(0));

            ok(client.call("create_json_index", json!({"domain": "zoo", "field": "kind", "type": "string"})).await);
            ok(client.call("json_put", json!({"domain": "zoo", "key": "a", "document": {"kind": "🦒"}})).await);
            let found = ok(client.call("json_search", json!({"domain": "zoo", "filter": {"kind": "🦒"}})).await);
            assert!(found.text().contains("🦒"), "{}", found.text());
            ok(client.call("json_delete", json!({"domain": "zoo", "key": "a"})).await);
            assert!(ok(client.call("list_json_indexes", json!({"domain": "zoo"})).await).text().contains("kind"));

            ok(client.call("sql_ddl", json!({"domain": "zoo", "sql": "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)"})).await);
            ok(client.call("sql_execute", json!({"domain": "zoo", "sql": "INSERT INTO t VALUES (?, ?)", "params": [1, "clé"]})).await);
            let rows = ok(client.call("sql_query", json!({"domain": "zoo", "sql": "SELECT name FROM t"})).await);
            assert!(rows.text().contains("clé"), "{}", rows.text());
            let drop = client.call("sql_ddl", json!({"domain": "zoo", "sql": "DROP TABLE t"})).await;
            assert!(drop.is_error() && drop.text().contains("not available over MCP"), "{}", drop.text());
            assert!(ok(client.call("describe_table", json!({"domain": "zoo", "table": "t"})).await).text().contains("name"));
        },
    );
}

// Read-only (the default): the write tools are not offered and a direct
// call is an MCP error.
#[test]
fn switched_off_tools_are_neither_listed_nor_callable() {
    with_mcp(
        |_| {},
        |_, mcp| async move {
            let mut client = Client::new(mcp, None);
            assert_eq!(client.initialize().await.status, 200);
            assert!(!client.tool_names().await.contains(&"kv_put".to_string()));
            let answer = client.call("kv_put", json!({"domain": "default", "key": "k", "value": "v"})).await;
            let message = answer.message.unwrap();
            assert!(message.get("error").is_some(), "{message}");
        },
    );
}

// `kv_get` tells a NULL key, an empty value and a binary value apart.
#[test]
fn kv_get_returns_null_empty_and_binary_values() {
    with_mcp(
        |_| {},
        |rest, mcp| async move {
            let writes = [
                http("PATCH", "/store-api/kv/default/keys/null/null", &[], "").into_bytes(),
                http("PUT", "/store-api/kv/default/keys/empty", &[], "").into_bytes(),
                http_bytes("PUT", "/store-api/kv/default/keys/binary", &[], &[0xff, 0x00, 0x41]),
            ];
            for raw in &writes {
                let (status, body) = super::tests::request(rest, raw).await;
                assert!(status < 300, "{status} {}", String::from_utf8_lossy(&body));
            }
            let mut client = Client::new(mcp, None);
            assert_eq!(client.initialize().await.status, 200);
            let cases = [
                ("null", json!({"value": null})),
                ("empty", json!({"value": ""})),
                ("binary", json!({"value": "_wBB", "encoding": "base64url"})),
            ];
            for (key, expected) in cases {
                let answer = client.call("kv_get", json!({"domain": "default", "key": key})).await;
                assert!(!answer.is_error(), "{key}: {}", answer.text());
                assert_eq!(answer.result()["structuredContent"], expected, "{key}");
                assert_eq!(answer.text(), expected.to_string(), "{key}");
            }
        },
    );
}

// Test 4 (MCP): while writes are refused for want of disk space, a write
// tool fails with the 507 text; a read tool answers.
#[test]
fn a_write_tool_fails_with_507_while_writes_are_refused() {
    use crate::control::resources::tests::{FakeProbe, GB};
    let dir = tempfile::TempDir::new().unwrap();
    let cfg = mcp_config(dir.path(), |cfg| cfg.mcp.read_only = false);
    let system_dir = cfg.storage.system_dir.clone();
    let probe = FakeProbe::new();
    probe.mount(dir.path(), 100 * GB, 50 * GB);
    super::test_hook::use_probe(&system_dir, Arc::clone(&probe));
    let server = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).unwrap();
    let (rest, mcp) = (server.http_addr.unwrap(), server.mcp_addr.expect("MCP listener enabled"));
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let (status, _) = super::tests::request(rest, &http("PUT", "/store-api/kv/default/keys/k", &[], "clé")).await;
        assert_eq!(status, 200);
        let mut client = Client::new(mcp, None);
        assert_eq!(client.initialize().await.status, 200);
        probe.set_free(dir.path(), GB);
        super::test_hook::tick_resources(&system_dir);

        let put = client.call("kv_put", json!({"domain": "default", "key": "k", "value": "v"})).await;
        assert!(put.is_error(), "{}", put.text());
        assert!(put.text().contains("507 Insufficient Storage: write blocked: disk space below threshold"), "{}", put.text());
        let read = client.call("kv_get", json!({"domain": "default", "key": "k"})).await;
        assert_eq!(read.result()["structuredContent"], json!({"value": "clé"}), "{}", read.text());
    });
    server.shutdown().unwrap();
}

// An answer above 1 MiB is a tool error, not a truncated result.
#[test]
fn a_result_above_one_mib_is_a_tool_error() {
    with_mcp(
        |cfg| cfg.lsm.max_value_size = 2 * 1024 * 1024,
        |rest, mcp| async move {
            let big = "x".repeat(1024 * 1024 + 1);
            let (status, _) = super::tests::request(rest, &http("PUT", "/store-api/kv/default/keys/big", &[], &big)).await;
            assert_eq!(status, 200);
            let mut client = Client::new(mcp, None);
            assert_eq!(client.initialize().await.status, 200);
            let answer = client.call("kv_get", json!({"domain": "default", "key": "big"})).await;
            assert!(answer.is_error() && answer.text().contains("reduce `limit`"), "{}", answer.text());
        },
    );
}

// A browser request from an Origin not in the list is refused.
#[test]
fn a_foreign_origin_is_refused() {
    with_mcp(
        |cfg| cfg.mcp.allowed_origins = vec!["https://app.example.com".to_string()],
        |_, mcp| async move {
            let body = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}).to_string();
            let headers = [("Content-Type", "application/json"), ("Accept", "application/json, text/event-stream")];
            for (origin, expected) in [("https://evil.example.com", 403), ("https://app.example.com", 200)] {
                let mut headers = headers.to_vec();
                headers.push(("Origin", origin));
                let (status, _, _) = exchange(mcp, &http("POST", "/mcp", &headers, &body)).await;
                // A ping without a session is answered 4xx by the SDK, not 403.
                assert_eq!(status == 403, expected == 403, "{origin}: {status}");
            }
        },
    );
}

// An open event stream does not hold the shutdown longer than the drain cap.
#[test]
#[allow(clippy::disallowed_methods, reason = "the client runs on its own tokio runtime")]
fn an_open_event_stream_does_not_hold_the_shutdown() {
    let dir = tempfile::TempDir::new().unwrap();
    let server = Server::start(Arc::new(mcp_config(dir.path(), |_| {})), &dir.path().join("luradb.toml")).unwrap();
    let mcp = server.mcp_addr.unwrap();
    let client = tokio::runtime::Runtime::new().unwrap();
    let stream = client.block_on(async move {
        let mut session = Client::new(mcp, None);
        assert_eq!(session.initialize().await.status, 200);
        let id = session.session.clone().unwrap();
        let raw = format!("GET /mcp HTTP/1.1\r\nHost: test\r\nAccept: text/event-stream\r\nMcp-Session-Id: {id}\r\n\r\n");
        let mut stream = TcpStream::connect(mcp).await.unwrap();
        stream.write_all(raw.as_bytes()).await.unwrap();
        let mut head = vec![0u8; 12];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 200");
        stream
    });

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || done_tx.send(server.shutdown().is_ok()));
    // Upper bound against hanging only.
    assert_eq!(done_rx.recv_timeout(Duration::from_secs(30)), Ok(true));
    drop(stream);
}
