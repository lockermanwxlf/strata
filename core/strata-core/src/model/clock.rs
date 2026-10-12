//! Vector clock operations (spec §8.2, §9.2).

use crate::format::Id;
use crate::format::body::VectorClock;

impl VectorClock {
    /// Records that `seq` of `client` has been seen, keeping entries sorted.
    /// Never lowers an entry.
    pub fn observe(&mut self, client: Id, seq: u64) {
        match self.0.binary_search_by(|(c, _)| c.cmp(&client)) {
            Ok(i) => self.0[i].1 = self.0[i].1.max(seq),
            Err(i) => {
                if seq > 0 {
                    self.0.insert(i, (client, seq));
                }
            }
        }
    }

    /// Takes the entrywise maximum with `other`.
    pub fn merge(&mut self, other: &VectorClock) {
        for &(client, seq) in &other.0 {
            self.observe(client, seq);
        }
    }

    /// Whether every entry of `other` is at most this clock's entry for that client.
    pub fn covers(&self, other: &VectorClock) -> bool {
        other.0.iter().all(|(client, seq)| self.get(client) >= *seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_merge_covers() {
        let mut a = VectorClock::default();
        a.observe([2; 16], 3);
        a.observe([1; 16], 5);
        a.observe([2; 16], 1);
        assert_eq!(a, VectorClock(vec![([1; 16], 5), ([2; 16], 3)]));

        let b = VectorClock(vec![([2; 16], 4), ([3; 16], 1)]);
        assert!(!a.covers(&b));
        a.merge(&b);
        assert_eq!(
            a,
            VectorClock(vec![([1; 16], 5), ([2; 16], 4), ([3; 16], 1)])
        );
        assert!(a.covers(&b));
        a.validate("t").unwrap();
    }
}
