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

    #[test]
    fn domain_name_for_shard_finds_a_name_on_every_shard() {
        for n in 1..=8 {
            for k in 0..n {
                let name = domain_name_for_shard(k, n, 7);
                assert_eq!(shard_of(slot_of_domain(&name), n), k, "{name} for shard {k} of {n}");
                assert_eq!(domain_name_for_shard(k, n, 7), name, "deterministic for one seed");
            }
        }
    }
}
