//! Slot function: every domain belongs to one of [`SLOTS`] fixed slots, and a
//! slot to a data shard. Both are pure functions of the domain name and the
//! shard count; nothing is stored per domain.

use crate::engines::lsm::domain::fnv64;

/// Fixed number of slots; a power of two.
pub const SLOTS: u16 = 256;

/// splitmix64 finalizer: spreads the weakly mixed low bits of FNV-1a over
/// short, similar names before the slot is cut from them.
fn mix(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x
}

/// Slot of the domain whose data-key prefix carries `fnv`, the FNV-1a hash of
/// its name — computable from any data key without knowing the name.
pub fn slot_of_prefix(fnv: u64) -> u16 {
    (mix(fnv) & u64::from(SLOTS - 1)) as u16
}

/// Slot of the domain `name`, the same for every engine.
pub fn slot_of_domain(name: &str) -> u16 {
    slot_of_prefix(fnv64(name.as_bytes()))
}

/// Data shard that owns `slot` when `shards` shards run.
pub fn shard_of(slot: u16, shards: u16) -> u16 {
    slot % shards
}

/// Data shard that owns the domain `name` when `shards` shards run.
pub fn shard_of_domain(name: &str, shards: u16) -> u16 {
    shard_of(slot_of_domain(name), shards)
}

/// Metadata keys that carry their domain's name: `<prefix><name>`, the
/// index keys `<prefix><name>:<field>`.
const NAMED_KEYS: [&[u8]; 5] =
    [b"__sys:domain:", b"__sys:json_domain:", b"__sys:index:", b"__sys:rel_domain:", b"__sys:rel_catalog_seq:"];

/// Data keys that carry their domain's FNV-1a hash: `<prefix><hash:016x>:…`.
const HASHED_KEYS: [&[u8]; 6] = [b"d:", b"DOC:", b"IDX:", b"ROW:", b"SEQ:", b"CAT:"];

/// Data shard that owns `key`, a data or metadata key of a domain in any
/// engine, when `shards` shards run; `None` for a key of no domain.
pub fn shard_of_key(key: &[u8], shards: u16) -> Option<u16> {
    let slot = if let Some(rest) = NAMED_KEYS.iter().find_map(|prefix| key.strip_prefix(*prefix)) {
        let name = rest.split(|&b| b == b':').next()?;
        slot_of_domain(std::str::from_utf8(name).ok().filter(|name| !name.is_empty())?)
    } else {
        let rest = HASHED_KEYS.iter().find_map(|prefix| key.strip_prefix(*prefix))?;
        let (hash, separator) = (rest.get(..16)?, rest.get(16)?);
        if *separator != b':' {
            return None;
        }
        slot_of_prefix(u64::from_str_radix(std::str::from_utf8(hash).ok()?, 16).ok()?)
    };
    Some(shard_of(slot, shards))
}

/// Finds a domain name on data shard `k` of `n`, deterministically from
/// `seed`, so tests can place domains without any override mechanism.
#[cfg(test)]
pub(crate) fn domain_name_for_shard(k: u16, n: u16, seed: u64) -> String {
    (0u64..)
        .map(|i| format!("d{seed}-{i}"))
        .find(|name| shard_of(slot_of_domain(name), n) == k)
        .expect("every shard owns slots")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expected slots computed independently of this code (splitmix64
    // finalizer over FNV-1a 64, low 8 bits).
    const KNOWN_SLOTS: [(&str, u16); 10] = [
        ("default", 142),
        ("orders", 41),
        ("users", 229),
        ("sessions", 255),
        ("tenant-a", 57),
        ("tenant-b", 141),
        ("metrics_2026", 242),
        ("a", 248),
        ("Z9_x-y", 234),
        ("domains", 116),
    ];

    #[test]
    fn known_domain_names_map_to_their_pinned_slots() {
        for (name, slot) in KNOWN_SLOTS {
            assert_eq!(slot_of_domain(name), slot, "{name}");
        }
    }

    #[test]
    fn the_slot_of_a_name_is_the_slot_of_its_prefix_hash() {
        assert_eq!(fnv64(b"default"), 0xebad_a516_8620_c5fe);
        assert_eq!(slot_of_prefix(0xebad_a516_8620_c5fe), 142);
        for (name, _) in KNOWN_SLOTS {
            assert_eq!(slot_of_domain(name), slot_of_prefix(fnv64(name.as_bytes())), "{name}");
        }
    }

    #[test]
    fn ten_thousand_names_leave_no_slot_empty_or_crowded() {
        let mut counts = [0u32; SLOTS as usize];
        // A fixed xorshift sequence: random-looking names, same every run.
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..10_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            counts[slot_of_domain(&format!("n{state:x}")) as usize] += 1;
        }
        let expected = 10_000 / u32::from(SLOTS);
        assert!(counts.iter().all(|&c| c > 0), "empty slot: {counts:?}");
        assert!(counts.iter().all(|&c| c <= 3 * expected), "crowded slot: {counts:?}");
    }

    #[test]
    fn shard_of_is_the_slot_modulo_the_shard_count() {
        for slot in [0, 1, 2, 7, 8, 9, 142, 255] {
            assert_eq!(shard_of(slot, 1), 0);
        }
        assert_eq!([0, 1, 2, 3, 255].map(|s| shard_of(s, 2)), [0, 1, 0, 1, 1]);
        assert_eq!([0, 1, 2, 3, 4, 255].map(|s| shard_of(s, 3)), [0, 1, 2, 0, 1, 0]);
        assert_eq!([0, 7, 8, 9, 142, 255].map(|s| shard_of(s, 8)), [0, 7, 0, 1, 6, 7]);
    }

    // Every key family of every engine maps to the shard of its domain: by
    // the name in metadata keys, by the name's hash in data keys.
    #[test]
    fn every_key_of_a_domain_belongs_to_the_domain_s_shard() {
        for n in [1, 2, 3, 8] {
            for k in 0..n {
                let name = domain_name_for_shard(k, n, 11);
                let hash = format!("{:016x}", fnv64(name.as_bytes()));
                let keys = [
                    format!("__sys:domain:{name}"),
                    format!("__sys:json_domain:{name}"),
                    format!("__sys:index:{name}:address.city"),
                    format!("__sys:rel_domain:{name}"),
                    format!("__sys:rel_catalog_seq:{name}"),
                    format!("d:{hash}:clé"),
                    format!("DOC:{hash}:doc-1"),
                    format!("IDX:{hash}:field:"),
                    format!("ROW:{hash}:\0\0\0\x01:"),
                    format!("SEQ:{hash}:\0\0\0\x01"),
                    format!("CAT:{hash}:orders"),
                ];
                for key in keys {
                    assert_eq!(shard_of_key(key.as_bytes(), n), Some(k), "{key} of {name}, {n} shards");
                }
            }
        }
    }

    #[test]
    fn keys_of_no_domain_belong_to_no_shard() {
        for key in [
            &b"__sys:auth:user:alice"[..],
            b"__sys:meta:shards",
            b"__sys:domain:",
            b"hub-probe",
            b"d:not-a-hash-at-all:k",
            b"d:0123456789abcdef",
            b"DOC:0123456789abcdefk",
        ] {
            assert_eq!(shard_of_key(key, 2), None, "{}", String::from_utf8_lossy(key));
        }
    }

    #[test]
    fn domain_name_for_shard_finds_a_name_on_every_shard() {
        for n in 1..=8 {
            for k in 0..n {
                let name = domain_name_for_shard(k, n, 7);
                assert_eq!(shard_of(slot_of_domain(&name), n), k, "{name} for shard {k} of {n}");
                assert_eq!(shard_of_domain(&name, n), k, "{name} for shard {k} of {n}");
                assert_eq!(domain_name_for_shard(k, n, 7), name, "deterministic for one seed");
            }
        }
    }
}
