//! Logical backup & restore (spec general/006).
//!
//! This module currently carries only scope parsing and the cron subset
//! (`cron`) — pure, config-facing pieces needed for startup validation. The
//! job manager, NDJSON writer/restore and API handlers follow in later steps.

pub mod cron;

/// Which data a backup covers (spec general/006 "Scope-Syntax"). Parsing is
/// syntax-only — domain existence is checked when a backup job actually runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupScope {
    /// Both engines, all active domains.
    All,
    /// KV engine, all KV domains.
    Kv,
    /// JSON engine, all JSON domains (incl. index definitions).
    Json,
    /// A single KV domain.
    KvDomain(String),
    /// A single JSON domain.
    JsonDomain(String),
    /// The KV **and** JSON domain of this name (whichever engine has it).
    Domain(String),
}

impl BackupScope {
    /// Parses a scope string: `all`, `kv`, `json`, `kv:<domain>`,
    /// `json:<domain>`, or `domain:<name>`.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "all" => return Ok(Self::All),
            "kv" => return Ok(Self::Kv),
            "json" => return Ok(Self::Json),
            _ => {}
        }
        if let Some(domain) = s.strip_prefix("kv:") {
            return Ok(Self::KvDomain(validate_scope_domain(domain)?.to_string()));
        }
        if let Some(domain) = s.strip_prefix("json:") {
            return Ok(Self::JsonDomain(validate_scope_domain(domain)?.to_string()));
        }
        if let Some(domain) = s.strip_prefix("domain:") {
            return Ok(Self::Domain(validate_scope_domain(domain)?.to_string()));
        }
        anyhow::bail!(
            "invalid backup scope '{s}': expected 'all', 'kv', 'json', 'kv:<domain>', 'json:<domain>', or 'domain:<name>'"
        );
    }
}

/// Syntax check only (matches the `[a-zA-Z0-9_-]` domain-name charset used
/// elsewhere in the repo) — no existence check, no engine access.
fn validate_scope_domain(name: &str) -> anyhow::Result<&str> {
    anyhow::ensure!(!name.is_empty(), "invalid backup scope: domain name must not be empty");
    anyhow::ensure!(
        name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
        "invalid backup scope: domain name '{name}' contains invalid characters (only [a-zA-Z0-9_-] allowed)"
    );
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_fixed_scopes() {
        assert_eq!(BackupScope::parse("all").unwrap(), BackupScope::All);
        assert_eq!(BackupScope::parse("kv").unwrap(), BackupScope::Kv);
        assert_eq!(BackupScope::parse("json").unwrap(), BackupScope::Json);
    }

    #[test]
    fn test_parse_domain_scopes() {
        assert_eq!(
            BackupScope::parse("kv:shop").unwrap(),
            BackupScope::KvDomain("shop".to_string())
        );
        assert_eq!(
            BackupScope::parse("json:shop").unwrap(),
            BackupScope::JsonDomain("shop".to_string())
        );
        assert_eq!(
            BackupScope::parse("domain:shop").unwrap(),
            BackupScope::Domain("shop".to_string())
        );
    }

    #[test]
    fn test_parse_domain_name_allows_underscore_and_hyphen() {
        assert_eq!(
            BackupScope::parse("kv:my-domain_1").unwrap(),
            BackupScope::KvDomain("my-domain_1".to_string())
        );
    }

    #[test]
    fn test_parse_rejects_unknown_scope() {
        assert!(BackupScope::parse("").is_err());
        assert!(BackupScope::parse("unknown").is_err());
        assert!(BackupScope::parse("Kv").is_err()); // case-sensitive
        assert!(BackupScope::parse("kv:shop:extra").is_err());
    }

    #[test]
    fn test_parse_rejects_empty_domain_name() {
        assert!(BackupScope::parse("kv:").is_err());
        assert!(BackupScope::parse("json:").is_err());
        assert!(BackupScope::parse("domain:").is_err());
    }

    #[test]
    fn test_parse_rejects_invalid_domain_characters() {
        assert!(BackupScope::parse("kv:sh op").is_err());
        assert!(BackupScope::parse("domain:sh/op").is_err());
        assert!(BackupScope::parse("json:sh.op").is_err());
    }
}
