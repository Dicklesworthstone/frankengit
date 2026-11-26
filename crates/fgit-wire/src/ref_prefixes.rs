//! Byte-preserving OR queries for protocol-v2 ref discovery.
//!
//! The request keeps its original prefix arguments for limits and receipts.
//! Matching uses a borrowed, sorted prefix antichain: duplicates and a prefix
//! covered by an earlier, shorter prefix cannot change the result. A matching
//! prefix is then the name's immediate lexicographic predecessor, so each ref
//! needs logarithmic prefix comparisons instead of scanning the entire query.

use crate::WireError;

pub(crate) struct RefPrefixes<'a> {
    prefixes: Vec<&'a [u8]>,
}

impl<'a> RefPrefixes<'a> {
    pub(crate) fn new(arguments: &'a [Vec<u8>]) -> Result<Self, WireError> {
        let mut prefixes = Vec::new();
        prefixes
            .try_reserve_exact(arguments.len())
            .map_err(|_| WireError::AllocationFailure)?;
        prefixes.extend(arguments.iter().map(Vec::as_slice));
        prefixes.sort_unstable();
        let mut retained = 0;
        for index in 0..prefixes.len() {
            let prefix = prefixes[index];
            if retained != 0 && prefix.starts_with(prefixes[retained - 1]) {
                continue;
            }
            prefixes[retained] = prefix;
            retained += 1;
        }
        prefixes.truncate(retained);
        Ok(Self { prefixes })
    }

    pub(crate) fn matches(&self, name: &[u8]) -> bool {
        if self.prefixes.is_empty() {
            return true;
        }
        let after = self.prefixes.partition_point(|prefix| *prefix <= name);
        after != 0 && name.starts_with(self.prefixes[after - 1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_overlapping_query_compiles_to_disjoint_byte_prefixes() {
        let arguments = [
            b"refs/heads/main".as_slice(),
            b"refs/tags/release",
            b"refs/heads/",
            b"refs/heads/main",
            b"refs/\xff/",
            b"refs/\xff/nested",
        ]
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
        let query = RefPrefixes::new(&arguments).unwrap();
        assert_eq!(
            query.prefixes,
            vec![
                b"refs/heads/".as_slice(),
                b"refs/tags/release",
                b"refs/\xff/"
            ]
        );
        for name in [
            b"HEAD".as_slice(),
            b"refs/heads",
            b"refs/heads/main",
            b"refs/heads/zz",
            b"refs/heads0",
            b"refs/tags/release",
            b"refs/tags/release-more",
            b"refs/tags/zz",
            b"refs/\xfe/z",
            b"refs/\xff/nested",
        ] {
            assert_eq!(
                query.matches(name),
                arguments.iter().any(|prefix| name.starts_with(prefix)),
                "{name:?}"
            );
        }
    }
}
