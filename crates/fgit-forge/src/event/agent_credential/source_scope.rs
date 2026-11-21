//! Immutable, finite reference and native-path ceilings for source publication.
//! A selector is a ceiling on an ordinary admission, never an authorization to
//! skip canonical protection, predecessor, closure, or revocation checks.

use super::invalid_native;
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::RefName;
use fgit_types::ref_write_scope::RefWriteScope;

pub const MAX_SOURCE_PATH_PREFIXES: usize = 64;
pub const MAX_SOURCE_PATH_BYTES: usize = 4096;
const MAX_REF_SCOPE_BYTES: usize = 2 * 4096 + 8 * 64;

/// An immutable finite ref ceiling and a canonical set of path-component
/// prefixes. The empty path, supplied alone, explicitly permits the whole tree.
/// `src` permits `src` and `src/file`, never `src-other/file`. Native bytes are
/// retained without UTF-8 conversion, normalization, or filesystem access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcePublicationScope {
    ref_scope: String,
    references: RefWriteScope,
    path_prefixes: Vec<Vec<u8>>,
}

impl SourcePublicationScope {
    pub fn new(ref_scope: &str, mut path_prefixes: Vec<Vec<u8>>) -> Result<Self, CodecRefusal> {
        if ref_scope.len() > MAX_REF_SCOPE_BYTES || matches!(ref_scope, "all" | "none") {
            return Err(invalid_native("agent_credential.source_ref_scope"));
        }
        let references = RefWriteScope::parse(ref_scope)
            .map_err(|_| invalid_native("agent_credential.source_ref_scope"))?
            .ok_or_else(|| invalid_native("agent_credential.source_ref_scope"))?;
        // Caller order carries no authority or identity. Canonical decoding
        // separately requires this exact spelling rather than accepting aliases.
        let mut selectors: Vec<_> = ref_scope.split(',').collect();
        selectors.sort_unstable();
        let ref_scope = selectors.join(",");
        if path_prefixes.is_empty() || path_prefixes.len() > MAX_SOURCE_PATH_PREFIXES {
            return Err(invalid_native("agent_credential.source_paths"));
        }
        let mut total = 0usize;
        for path in &path_prefixes {
            total = total
                .checked_add(path.len())
                .filter(|total| *total <= MAX_SOURCE_PATH_BYTES)
                .ok_or_else(|| invalid_native("agent_credential.source_paths"))?;
            if !valid_path(path, true) {
                return Err(invalid_native("agent_credential.source_path"));
            }
        }
        path_prefixes.sort();
        if path_prefixes.windows(2).any(|pair| pair[0] == pair[1])
            || (path_prefixes.len() != 1 && path_prefixes[0].is_empty())
        {
            return Err(invalid_native("agent_credential.source_paths"));
        }
        Ok(Self {
            ref_scope,
            references,
            path_prefixes,
        })
    }

    pub fn validate(&self) -> Result<(), CodecRefusal> {
        if Self::new(&self.ref_scope, self.path_prefixes.clone())? != *self {
            return Err(invalid_native("agent_credential.source_scope"));
        }
        Ok(())
    }

    #[must_use]
    pub fn ref_scope(&self) -> &str {
        &self.ref_scope
    }

    #[must_use]
    pub fn path_prefixes(&self) -> &[Vec<u8>] {
        &self.path_prefixes
    }

    #[must_use]
    pub fn permits_ref(&self, reference: &RefName) -> bool {
        self.references.permits(reference.as_bytes())
    }

    #[must_use]
    pub fn permits_path(&self, path: &[u8]) -> bool {
        valid_path(path, false)
            && self.path_prefixes.iter().any(|prefix| {
                prefix.is_empty()
                    || path == prefix
                    || (path.starts_with(prefix) && path.get(prefix.len()) == Some(&b'/'))
            })
    }

    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        out.write_bytes(
            "agent_credential.source_ref_scope",
            self.ref_scope.as_bytes(),
        )?;
        out.write_scalar(self.path_prefixes.len() as u32);
        for path in &self.path_prefixes {
            out.write_bytes("agent_credential.source_path", path)?;
        }
        Ok(())
    }

    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let references = input.read_bytes("agent_credential.source_ref_scope")?;
        if references.len() > MAX_REF_SCOPE_BYTES {
            return Err(invalid_native("agent_credential.source_ref_scope"));
        }
        let ref_scope = std::str::from_utf8(references)
            .map_err(|_| invalid_native("agent_credential.source_ref_scope"))?;
        let count = input.read_scalar::<u32>("agent_credential.source_path_count")? as usize;
        if count == 0 || count > MAX_SOURCE_PATH_PREFIXES {
            return Err(invalid_native("agent_credential.source_paths"));
        }
        let mut paths = Vec::with_capacity(count);
        let mut total = 0usize;
        for _ in 0..count {
            let path = input.read_bytes("agent_credential.source_path")?;
            total = total
                .checked_add(path.len())
                .filter(|total| *total <= MAX_SOURCE_PATH_BYTES)
                .ok_or_else(|| invalid_native("agent_credential.source_paths"))?;
            paths.push(path.to_vec());
        }
        let value = Self::new(ref_scope, paths.clone())?;
        if value.ref_scope != ref_scope || value.path_prefixes != paths {
            return Err(invalid_native("agent_credential.source_scope_order"));
        }
        Ok(value)
    }
}

fn valid_path(path: &[u8], allow_root: bool) -> bool {
    if path.is_empty() {
        return allow_root;
    }
    path.len() <= MAX_SOURCE_PATH_BYTES
        && !path.contains(&0)
        && path.split(|byte| *byte == b'/').all(|component| {
            !component.is_empty()
                && component != b"."
                && component != b".."
                && !component.eq_ignore_ascii_case(b".git")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn refs() -> String {
        format!("prefix:{}", hex(b"refs/heads/agent/"))
    }

    #[test]
    fn native_path_and_ref_ceilings_preserve_component_boundaries() {
        let scope =
            SourcePublicationScope::new(&refs(), vec![b"src".to_vec(), b"data/\xff".to_vec()])
                .unwrap();
        assert!(scope.permits_ref(&RefName::try_new(b"refs/heads/agent/one").unwrap()));
        for denied in [
            b"refs/heads/agent".as_slice(),
            b"refs/heads/agents/one",
            b"refs/heads/main",
        ] {
            assert!(!scope.permits_ref(&RefName::try_new(denied).unwrap()));
        }
        for path in [
            b"src".as_slice(),
            b"src/lib.rs",
            b"data/\xff",
            b"data/\xff/child",
        ] {
            assert!(scope.permits_path(path));
        }
        for path in [
            b"".as_slice(),
            b"src-other/lib.rs",
            b"data/\xfe",
            b"src/../secret",
            b"src/.git/config",
        ] {
            assert!(!scope.permits_path(path));
        }
        let root = SourcePublicationScope::new(&refs(), vec![Vec::new()]).unwrap();
        assert!(root.permits_path(b"README.md"));
        assert!(!root.permits_path(b".GIT/config"));
    }

    #[test]
    fn malformed_unbounded_duplicate_and_reserved_paths_are_refused() {
        for field in ["all", "none", "", "exact:00", "prefix:726566732f6865616473"] {
            assert!(SourcePublicationScope::new(field, vec![b"src".to_vec()]).is_err());
        }
        for paths in [
            vec![],
            vec![b"src".to_vec(), b"src".to_vec()],
            vec![Vec::new(), b"src".to_vec()],
            vec![b"/src".to_vec()],
            vec![b"src/".to_vec()],
            vec![b"src//x".to_vec()],
            vec![b"src/./x".to_vec()],
            vec![b"src/../x".to_vec()],
            vec![b".git/config".to_vec()],
            vec![b"src/.Git/config".to_vec()],
            vec![b"src/\0x".to_vec()],
            vec![vec![b'a'; MAX_SOURCE_PATH_BYTES + 1]],
        ] {
            assert!(SourcePublicationScope::new(&refs(), paths).is_err());
        }
        assert!(
            SourcePublicationScope::new(
                &refs(),
                (0..=MAX_SOURCE_PATH_PREFIXES)
                    .map(|i| format!("p{i}").into_bytes())
                    .collect()
            )
            .is_err()
        );
    }

    #[test]
    fn equivalent_input_order_has_one_canonical_scope() {
        let exact = format!("exact:{}", hex(b"refs/heads/work"));
        let prefix = refs();
        let first = SourcePublicationScope::new(
            &format!("{prefix},{exact}"),
            vec![b"tests".to_vec(), b"src".to_vec()],
        )
        .unwrap();
        let second = SourcePublicationScope::new(
            &format!("{exact},{prefix}"),
            vec![b"src".to_vec(), b"tests".to_vec()],
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.path_prefixes(), &[b"src".to_vec(), b"tests".to_vec()]);
    }

    #[test]
    fn decoder_refuses_unordered_duplicate_and_oversized_scope_encodings() {
        let exact = format!("exact:{}", hex(b"refs/heads/work"));
        let prefix = refs();
        for (references, paths) in [
            (format!("{prefix},{exact}"), vec![b"src".as_slice()]),
            (exact.clone(), vec![b"tests".as_slice(), b"src"]),
            (exact.clone(), vec![b"src".as_slice(), b"src"]),
            (exact.clone(), vec![b"".as_slice(), b"src"]),
            (exact.clone(), vec![]),
        ] {
            let mut encoded = Encoder::new();
            encoded.write_bytes("refs", references.as_bytes()).unwrap();
            encoded.write_scalar(paths.len() as u32);
            for path in paths {
                encoded.write_bytes("path", path).unwrap();
            }
            assert!(
                SourcePublicationScope::read(&mut Decoder::new(
                    encoded.as_bytes(),
                    fgit_codec::DecodeLimits::DEFAULT,
                ))
                .is_err()
            );
        }
        let mut excessive = Encoder::new();
        excessive.write_bytes("refs", exact.as_bytes()).unwrap();
        excessive.write_scalar(u32::MAX);
        assert!(
            SourcePublicationScope::read(&mut Decoder::new(
                excessive.as_bytes(),
                fgit_codec::DecodeLimits::DEFAULT,
            ))
            .is_err()
        );
    }
}
