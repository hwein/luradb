//! `ROW:` / `IDX:` / `SEQ:` key builders (spec rel/005 §2, concept 5.2).
//!
//! `table_id`/`index_id` are written as 4-byte big-endian, so the literal `:`
//! separators to their neighbours are unambiguous. `pk_enc`/`val_enc` (from
//! `encode_sortable`, rel/003) are the only variable-length, tail-standing
//! parts — both self-terminating, so in the `IDX:` key `pk_enc` follows
//! `val_enc` directly (no `:`). No back-decoding of `pk_enc`/`val_enc` is
//! needed (the PK travels inside the LuraRow) and is a non-goal.

const ROW_PREFIX: &[u8] = b"ROW:";
const IDX_PREFIX: &[u8] = b"IDX:";
const SEQ_PREFIX: &[u8] = b"SEQ:";

/// `ROW:{prefix}:{table_id}:{pk_enc}` — the row's LSM key.
pub fn row_key(system_prefix: &[u8], table_id: u32, pk_enc: &[u8]) -> Vec<u8> {
    let mut k = row_table_prefix(system_prefix, table_id);
    k.extend_from_slice(pk_enc);
    k
}

/// `ROW:{prefix}:{table_id}:` — scan prefix for all rows of a table.
pub fn row_table_prefix(system_prefix: &[u8], table_id: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(ROW_PREFIX.len() + system_prefix.len() + 6);
    k.extend_from_slice(ROW_PREFIX);
    k.extend_from_slice(system_prefix);
    k.push(b':');
    k.extend_from_slice(&table_id.to_be_bytes());
    k.push(b':');
    k
}

/// `IDX:{prefix}:{index_id}:{val_enc}{pk_enc}` — an index entry's LSM key.
pub fn index_key(system_prefix: &[u8], index_id: u32, val_enc: &[u8], pk_enc: &[u8]) -> Vec<u8> {
    let mut k = index_value_prefix(system_prefix, index_id, val_enc);
    k.extend_from_slice(pk_enc);
    k
}

/// `IDX:{prefix}:{index_id}:{val_enc}` — value-search prefix (rel/006).
pub fn index_value_prefix(system_prefix: &[u8], index_id: u32, val_enc: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(IDX_PREFIX.len() + system_prefix.len() + 6 + val_enc.len());
    k.extend_from_slice(IDX_PREFIX);
    k.extend_from_slice(system_prefix);
    k.push(b':');
    k.extend_from_slice(&index_id.to_be_bytes());
    k.push(b':');
    k.extend_from_slice(val_enc);
    k
}

/// `SEQ:{prefix}:{table_id}` — the AUTOINCREMENT high-water key.
pub fn seq_key(system_prefix: &[u8], table_id: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(SEQ_PREFIX.len() + system_prefix.len() + 5);
    k.extend_from_slice(SEQ_PREFIX);
    k.extend_from_slice(system_prefix);
    k.push(b':');
    k.extend_from_slice(&table_id.to_be_bytes());
    k
}

// ── Domain-wide scan prefixes (rel/013 purger) ─────────────────────────────────
//
// `{family}:{system_prefix}:` — spans every table/index of the domain. The
// purger tombstones a deleting domain's data through these.

/// `ROW:{prefix}:` — all rows of a domain (every table).
pub fn row_domain_prefix(system_prefix: &[u8]) -> Vec<u8> {
    domain_prefix(ROW_PREFIX, system_prefix)
}

/// `IDX:{prefix}:` — all index entries of a domain.
pub fn index_domain_prefix(system_prefix: &[u8]) -> Vec<u8> {
    domain_prefix(IDX_PREFIX, system_prefix)
}

/// `SEQ:{prefix}:` — all AUTOINCREMENT counters of a domain.
pub fn seq_domain_prefix(system_prefix: &[u8]) -> Vec<u8> {
    domain_prefix(SEQ_PREFIX, system_prefix)
}

fn domain_prefix(family: &[u8], system_prefix: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(family.len() + system_prefix.len() + 1);
    k.extend_from_slice(family);
    k.extend_from_slice(system_prefix);
    k.push(b':');
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_row_key_layout() {
        let p = b"00000000deadbeef";
        let k = row_key(p, 1, b"\x80\x00\x00\x00\x00\x00\x00\x05");
        assert!(k.starts_with(b"ROW:00000000deadbeef:"));
        // 4-byte BE table_id then ':' then pk_enc.
        assert_eq!(&k[21..25], &1u32.to_be_bytes());
        assert_eq!(k[25], b':');
        assert!(k.starts_with(&row_table_prefix(p, 1)));
    }

    #[test]
    fn test_index_key_val_then_pk_no_separator() {
        let p = b"00000000deadbeef";
        let val = b"val_enc\x00\x00";
        let pk = b"\x80\x00\x00\x00\x00\x00\x00\x01";
        let k = index_key(p, 7, val, pk);
        let prefix = index_value_prefix(p, 7, val);
        assert!(k.starts_with(&prefix));
        assert_eq!(&k[prefix.len()..], pk); // pk directly after val_enc
    }

    #[test]
    fn test_seq_key_layout() {
        let p = b"00000000deadbeef";
        let k = seq_key(p, 42);
        assert!(k.starts_with(b"SEQ:00000000deadbeef:"));
        assert_eq!(&k[k.len() - 4..], &42u32.to_be_bytes());
    }
}
