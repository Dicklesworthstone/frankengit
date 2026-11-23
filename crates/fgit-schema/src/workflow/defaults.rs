//! Closed run defaults become the same validated inputs as explicit step fields.
//! Borrow source paths until their bounded per-step copy is admitted.
use super::{Node, Span, StepShell, WorkflowRefusal, context, matrix};

#[derive(Clone, Copy)]
pub(super) enum DefaultsScope {
    Workflow,
    Job,
}

impl DefaultsScope {
    const fn defaults_path(self) -> &'static str {
        match self {
            Self::Workflow => "defaults",
            Self::Job => "jobs.<id>.defaults",
        }
    }

    const fn run_path(self) -> &'static str {
        match self {
            Self::Workflow => "defaults.run",
            Self::Job => "jobs.<id>.defaults.run",
        }
    }

    const fn shell_path(self) -> &'static str {
        match self {
            Self::Workflow => "defaults.run.shell",
            Self::Job => "jobs.<id>.defaults.run.shell",
        }
    }

    const fn directory_path(self) -> &'static str {
        match self {
            Self::Workflow => "defaults.run.working-directory",
            Self::Job => "jobs.<id>.defaults.run.working-directory",
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(super) struct RunDefaults<'a> {
    shell: Option<StepShell>,
    // Absent inherits; an explicit root (Some(None)) clears its parent path.
    working_directory: Option<Option<&'a str>>,
}

impl<'a> RunDefaults<'a> {
    /// Validate every declared source layer before child fields can override it.
    pub(super) fn lower(node: &'a Node, scope: DefaultsScope) -> Result<Self, WorkflowRefusal> {
        let Some(defaults) = node.get("defaults") else {
            return Ok(Self::default());
        };
        closed_mapping(defaults, scope.defaults_path(), &["run"])?;
        let Some(run) = defaults.get("run") else {
            return Ok(Self::default());
        };
        closed_mapping(run, scope.run_path(), &["shell", "working-directory"])?;
        let shell = run
            .get("shell")
            .map(|selected| {
                let text = scalar(
                    selected,
                    scope.shell_path(),
                    "one literal shell name, sh or bash",
                )?;
                StepShell::parse(text).map_err(|error| WorkflowRefusal::Malformed {
                    expected: error.description(),
                    span: selected.span(),
                })
            })
            .transpose()?;
        let working_directory = run
            .get("working-directory")
            .map(|directory| {
                let text = scalar(directory, scope.directory_path(), "a relative path scalar")?;
                context::normalize_directory_ref(text).map_err(|error| WorkflowRefusal::Malformed {
                    expected: error.description(),
                    span: directory.span(),
                })
            })
            .transpose()?;
        Ok(Self {
            shell,
            working_directory,
        })
    }

    pub(super) fn inherit(self, parent: Self) -> Self {
        Self {
            shell: self.shell.or(parent.shell),
            working_directory: self.working_directory.or(parent.working_directory),
        }
    }

    pub(super) const fn shell(self) -> Option<StepShell> {
        self.shell
    }

    pub(super) fn copy_directory(
        self,
        expanded_bytes: &mut usize,
        span: Span,
    ) -> Result<Option<String>, WorkflowRefusal> {
        self.working_directory
            .flatten()
            .map(|directory| {
                matrix::charge_allocation(
                    expanded_bytes,
                    directory.len().saturating_add(128),
                    span,
                )?;
                Ok(directory.to_owned())
            })
            .transpose()
    }
}

fn closed_mapping(
    node: &Node,
    path: &'static str,
    accepted: &[&str],
) -> Result<(), WorkflowRefusal> {
    let Node::Mapping { entries, .. } = node else {
        return Err(WorkflowRefusal::FieldShape {
            path,
            expected: "a mapping",
            observed: node.shape(),
            span: node.span(),
        });
    };
    for (index, (key, _, span)) in entries.iter().enumerate() {
        if entries[..index].iter().any(|(prior, _, _)| prior == key) {
            return Err(WorkflowRefusal::DuplicateKey {
                key: key.clone().into(),
                span: *span,
            });
        }
        if !accepted.contains(&key.as_str()) {
            return Err(WorkflowRefusal::FieldUnknown {
                key: key.clone().into(),
                parent: path,
                span: *span,
            });
        }
    }
    Ok(())
}

fn scalar<'a>(
    node: &'a Node,
    path: &'static str,
    expected: &'static str,
) -> Result<&'a str, WorkflowRefusal> {
    match node {
        Node::Scalar { value, .. } => Ok(value),
        _ => Err(WorkflowRefusal::FieldShape {
            path,
            expected,
            observed: node.shape(),
            span: node.span(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_directory_copy_is_charged_before_allocation() {
        let defaults = RunDefaults {
            shell: None,
            working_directory: Some(Some("src")),
        };
        let charge = "src".len() + 128;
        let mut exact = matrix::MAX_EXPANDED_BYTES - charge;
        assert_eq!(
            defaults
                .copy_directory(&mut exact, Span::default())
                .unwrap(),
            Some("src".into())
        );
        assert_eq!(exact, matrix::MAX_EXPANDED_BYTES);
        let mut exceeded = matrix::MAX_EXPANDED_BYTES - charge + 1;
        let prior = exceeded;
        assert!(matches!(
            defaults.copy_directory(&mut exceeded, Span::default()),
            Err(WorkflowRefusal::LimitExceeded {
                limit: "expanded workflow allocation bytes",
                allowed: matrix::MAX_EXPANDED_BYTES,
                observed,
                ..
            }) if observed == matrix::MAX_EXPANDED_BYTES + 1
        ));
        assert_eq!(exceeded, prior);
        let root = RunDefaults {
            shell: None,
            working_directory: Some(None),
        }
        .inherit(defaults);
        assert_eq!(root.copy_directory(&mut exact, Span::default()), Ok(None));
        assert_eq!(exact, matrix::MAX_EXPANDED_BYTES);
    }
}
