//! Complete inspection data for an uploaded zero-parent native commit.
//! This is neither a construction plan nor authority to publish. In particular,
//! no patch digest or invented parent describes an independently uploaded tree.
use super::InitialCommitError;
use fgit_types::{GitHashAlgorithm, GitOid};

/// The complete path expansion has its own bounds: a small object DAG can name
/// the same subtree at exponentially many paths. Unique-object limits alone do
/// not bound a complete preview. Callers may narrow each ceiling, never widen it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitialInspectionLimits {
    pub max_files: usize,
    pub max_tree_entries: usize,
    pub max_depth: usize,
    pub max_path_bytes: usize,
    pub max_file_bytes: usize,
    pub max_commit_bytes: usize,
    pub max_output_bytes: usize,
}
impl Default for InitialInspectionLimits {
    fn default() -> Self {
        Self {
            max_files: super::MAX_INITIAL_OBJECTS,
            max_tree_entries: 100_000,
            max_depth: 64,
            max_path_bytes: 4096,
            max_file_bytes: 8 * 1024 * 1024,
            max_commit_bytes: 2 * 1024 * 1024,
            max_output_bytes: 32 * 1024 * 1024,
        }
    }
}
impl InitialInspectionLimits {
    pub fn validate(self) -> Result<(), InitialCommitError> {
        let maximum = Self::default();
        for (value, ceiling) in [
            (self.max_files, maximum.max_files),
            (self.max_tree_entries, maximum.max_tree_entries),
            (self.max_depth, maximum.max_depth),
            (self.max_path_bytes, maximum.max_path_bytes),
            (self.max_file_bytes, maximum.max_file_bytes),
            (self.max_commit_bytes, maximum.max_commit_bytes),
            (self.max_output_bytes, maximum.max_output_bytes),
        ] {
            if value == 0 || value > ceiling {
                return Err(InitialCommitError::Budget("initial inspection limits"));
            }
        }
        Ok(())
    }
}

/// Exact file contents, charged once for every visible path even when several
/// paths share a blob identity. Bytes need not be UTF-8 or end in a newline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedInitialFile {
    pub path: Vec<u8>,
    pub blob: GitOid,
    pub mode: u32,
    pub content: Vec<u8>,
}

/// A directory is retained even when empty. The root has the empty byte path;
/// omitting empty directories would misrepresent an uploaded native tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedInitialDirectory {
    pub path: Vec<u8>,
    pub tree: GitOid,
}

/// A complete, bounded view of the actual bundle, not a partial successful diff.
/// The node supplies its selecting authority head separately. All native object
/// identities, exact typed reachability and the pack trailer have been checked;
/// the public fields remain ordinary untrusted review data, not capabilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialCommitInspection {
    pub object_format: GitHashAlgorithm,
    pub candidate_commit: GitOid,
    pub root_tree: GitOid,
    pub commit_body: Vec<u8>,
    pub files: Vec<InspectedInitialFile>,
    pub directories: Vec<InspectedInitialDirectory>,
    pub bundle_sha256: [u8; 32],
    pub bundle_bytes: usize,
    pub pack_bytes: usize,
    pub object_count: usize,
    pub expanded_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inspection_limits_are_independent_closed_nonzero_bounds() {
        let normal = InitialInspectionLimits::default();
        normal.validate().unwrap();
        for bad in [
            InitialInspectionLimits { max_files: 0, ..normal },
            InitialInspectionLimits { max_files: normal.max_files + 1, ..normal },
            InitialInspectionLimits { max_tree_entries: 0, ..normal },
            InitialInspectionLimits { max_tree_entries: normal.max_tree_entries + 1, ..normal },
            InitialInspectionLimits { max_depth: 0, ..normal },
            InitialInspectionLimits { max_depth: normal.max_depth + 1, ..normal },
            InitialInspectionLimits { max_path_bytes: 0, ..normal },
            InitialInspectionLimits { max_path_bytes: normal.max_path_bytes + 1, ..normal },
            InitialInspectionLimits { max_file_bytes: 0, ..normal },
            InitialInspectionLimits { max_file_bytes: normal.max_file_bytes + 1, ..normal },
            InitialInspectionLimits { max_commit_bytes: 0, ..normal },
            InitialInspectionLimits { max_commit_bytes: normal.max_commit_bytes + 1, ..normal },
            InitialInspectionLimits { max_output_bytes: 0, ..normal },
            InitialInspectionLimits { max_output_bytes: normal.max_output_bytes + 1, ..normal },
        ] { assert!(bad.validate().is_err(), "{bad:?}"); }
    }
}
