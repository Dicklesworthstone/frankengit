//! Closed maintenance profiles sharing one progress/ownership/drain protocol.
//! Index-specific authority and recovery stay in their native owners.
use super::*;
use fgit_forge::source_symbols::index as symbols;
use fgit_types::{GitOid, RepositoryAuthorityHeadId};

type SymbolFailure = symbols::AccessError<NodeWorkspaceRefusal, GenerationAuthorityError>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum IndexKind {
    Lexical,
    Symbols,
}

pub(super) struct Source {
    pub source_head: RepositoryAuthorityHeadId,
    pub commit: GitOid,
}
pub(super) enum AttemptFailure {
    Refused(String),
    Publication {
        candidate: GraphGenerationId,
        error: String,
        definite_race: bool,
    },
}
impl From<NodeWorkspaceRefusal> for AttemptFailure {
    fn from(error: NodeWorkspaceRefusal) -> Self {
        match error {
            NodeWorkspaceRefusal::SourceIndexPublication { candidate, error } => {
                Self::Publication {
                    candidate,
                    definite_race: super::definite_race(&error),
                    error: error.to_string(),
                }
            }
            error => Self::Refused(error.to_string()),
        }
    }
}
impl From<SymbolFailure> for AttemptFailure {
    fn from(error: SymbolFailure) -> Self {
        match error {
            SymbolFailure::Publication { candidate, cause } => {
                let candidate = match GraphGenerationId::from_internal_object_id(candidate) {
                    Ok(candidate) => candidate,
                    // The worker refuses and retains an already armed row and
                    // lock on this protocol violation; it never clears pending.
                    Err(error) => {
                        return Self::Refused(format!(
                            "Invalid publication candidate: {error}; cause: {cause}"
                        ));
                    }
                };
                let definite_race = matches!(
                    cause.as_ref(),
                    SymbolFailure::Generation(
                        GenerationAuthorityError::PredecessorMismatch { .. }
                            | GenerationAuthorityError::ConcurrentActivation
                            | GenerationAuthorityError::HeadAlreadyInitialized
                    )
                );
                Self::Publication {
                    candidate,
                    definite_race,
                    error: cause.to_string(),
                }
            }
            error => Self::Refused(error.to_string()),
        }
    }
}
impl IndexKind {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Lexical => "lexical",
            Self::Symbols => "symbols",
        }
    }
    pub(super) fn bind(self, namespace: String) -> String {
        match self {
            Self::Lexical => namespace, // Preserve all existing v1/v2 progress bytes.
            Self::Symbols => format!("{namespace} symbols1"),
        }
    }
    pub(super) async fn recover(
        self,
        node: &OneNode,
        request: &NodeRequestContext,
        reference: &RefName,
        candidate: GraphGenerationId,
        minimum: Option<&GenerationActivation>,
    ) -> Result<GenerationRecovery, String> {
        match self {
            Self::Lexical => node
                .recover_source_index_local_in(
                    request,
                    reference,
                    candidate,
                    minimum,
                    Default::default(),
                )
                .await
                .map_err(|e| e.to_string()),
            Self::Symbols => node
                .recover_source_symbol_index_local_in(
                    request,
                    reference,
                    candidate,
                    minimum,
                    Default::default(),
                )
                .await
                .map_err(|e| e.to_string()),
        }
    }
    pub(super) async fn reconcile(
        self,
        node: &OneNode,
        request: &NodeRequestContext,
        reference: &RefName,
        minimum: Option<&GenerationActivation>,
        barrier: &mut (impl FnMut(GraphGenerationId) -> Result<(), NodeWorkspaceRefusal> + Send),
    ) -> Result<(Source, GenerationActivation), AttemptFailure> {
        match self {
            Self::Lexical => node
                .reconcile_source_index_guarded_local_in(
                    request,
                    reference,
                    None,
                    minimum,
                    Default::default(),
                    Default::default(),
                    barrier,
                )
                .await
                .map(|(source, activation)| {
                    (
                        Source {
                            source_head: source.source_head,
                            commit: source.commit,
                        },
                        activation,
                    )
                })
                .map_err(AttemptFailure::from),
            Self::Symbols => node
                .reconcile_source_symbol_index_guarded_local_in(
                    request,
                    reference,
                    None,
                    minimum,
                    Default::default(),
                    Default::default(),
                    barrier,
                )
                .await
                .map(|(source, activation)| {
                    (
                        Source {
                            source_head: source.head,
                            commit: source.commit,
                        },
                        activation,
                    )
                })
                .map_err(AttemptFailure::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn symbol_progress_cannot_be_resumed_as_lexical_or_vice_versa() {
        let namespace = "tenant repository incarnation sha1".to_owned();
        let refs = [b"refs/heads/main".to_vec()];
        let lexical = State::new(IndexKind::Lexical.bind(namespace.clone()), &refs).unwrap();
        let symbols = State::new(IndexKind::Symbols.bind(namespace.clone()), &refs).unwrap();
        assert_eq!(IndexKind::Lexical.bind(namespace.clone()), namespace);
        assert_ne!(lexical.encode().unwrap(), symbols.encode().unwrap());
        assert!(State::decode(&lexical.encode().unwrap(), &symbols).is_err());
        assert!(State::decode(&symbols.encode().unwrap(), &lexical).is_err());
        assert_eq!(
            State::decode(&symbols.encode().unwrap(), &symbols).unwrap(),
            symbols
        );
    }
    #[test]
    fn symbols_share_only_the_same_definitive_race_classification() {
        let candidate = generation([9; 32]).unwrap();
        for (error, race) in [
            (GenerationAuthorityError::ConcurrentActivation, true),
            (GenerationAuthorityError::HeadAlreadyInitialized, true),
            (GenerationAuthorityError::CheckpointUnresolved, false),
            (GenerationAuthorityError::InvalidActivationReceipt, false),
            (
                GenerationAuthorityError::Authority(fgit_authority::AuthorityFailure::Ambiguous(
                    fgit_authority::AmbiguityReason::NoResponse,
                )),
                false,
            ),
        ] {
            let error = SymbolFailure::Publication {
                candidate: *candidate.as_internal_object_id(),
                cause: Box::new(SymbolFailure::Generation(error)),
            };
            assert!(
                matches!(AttemptFailure::from(error),AttemptFailure::Publication {
                candidate:actual,definite_race,.. } if actual == candidate && definite_race == race)
            );
        }
        let cancelled = SymbolFailure::Publication {
            candidate: *candidate.as_internal_object_id(),
            cause: Box::new(SymbolFailure::Index(symbols::Error::Cancelled)),
        };
        assert!(matches!(
            AttemptFailure::from(cancelled),
            AttemptFailure::Publication {
                definite_race: false,
                ..
            }
        ));
        assert!(matches!(
            AttemptFailure::from(SymbolFailure::Stale),
            AttemptFailure::Refused(_)
        ));
    }
    #[test]
    fn symbols_are_an_explicit_bounded_mode_not_an_implicit_fallback() {
        let args: Vec<OsString> = [
            "/node",
            "01010101010101010101010101010101",
            "02020202020202020202020202020202",
            "sha1",
            "/private-progress",
            "init",
            "1",
            "0",
            "refs/heads/main",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        assert_eq!(parse(&args).unwrap().profile, IndexKind::Lexical);
        let mut symbols = vec![OsString::from("--symbols")];
        symbols.extend(args);
        assert_eq!(parse(&symbols).unwrap().profile, IndexKind::Symbols);
        symbols.insert(0, OsString::from("--symbols"));
        assert!(parse(&symbols).is_err());
        assert!(parse(&[OsString::from("--symbols")]).is_err());
    }
}
