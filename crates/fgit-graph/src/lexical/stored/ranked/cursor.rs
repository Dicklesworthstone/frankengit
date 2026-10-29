//! Monotone, metered seeks over a single already-verified posting column.
//!
//! Dense document scans examine the next posting once instead of binary-searching
//! the entire column again. Sparse path scopes gallop across skipped ranges and
//! then binary-search the bracket; they do not linearly visit excluded postings.
//! The cursor is query/segment-local and cannot select or authorize a generation.
use super::{LexicalError, Postings, QueryBudget};

#[derive(Clone, Default)]
pub(super) struct Cursor {
    next: usize,
    previous: Option<u64>,
}

impl Cursor {
    pub(super) fn offset(
        &mut self,
        postings: &Postings,
        wanted: u64,
        budget: &mut QueryBudget,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Option<u32>, LexicalError> {
        budget.charge(1, live)?;
        if self.previous.is_some_and(|previous| wanted <= previous) {
            return Err(LexicalError::Invalid("ranked document order"));
        }
        self.previous = Some(wanted);
        let Some(&current) = postings.documents.get(self.next) else {
            return Ok(None);
        };
        if current < wanted {
            let base = self.next;
            let mut low = base + 1;
            let mut step = 1usize;
            let mut high;
            loop {
                let probe = base.saturating_add(step).min(postings.documents.len());
                if probe == postings.documents.len() {
                    high = probe;
                    break;
                }
                budget.charge(1, live)?;
                if postings.documents[probe] >= wanted {
                    high = probe;
                    break;
                }
                low = probe + 1;
                step = step.saturating_mul(2);
            }
            while low < high {
                budget.charge(1, live)?;
                let middle = low + (high - low) / 2;
                if postings.documents[middle] < wanted {
                    low = middle + 1;
                } else {
                    high = middle;
                }
            }
            self.next = low;
            budget.charge(1, live)?;
        }
        if postings.documents.get(self.next) == Some(&wanted) {
            let offset = postings
                .offsets
                .get(self.next)
                .copied()
                .ok_or(LexicalError::Invalid("posting columns"))?;
            self.next += 1;
            Ok(Some(offset))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexical::LexicalQueryLimits;

    fn budget(max_work: u64) -> QueryBudget {
        QueryBudget::new(LexicalQueryLimits {
            max_results: 1,
            max_work,
        })
        .unwrap()
    }
    fn postings(ids: Vec<u64>) -> Postings {
        let offsets = (0..ids.len()).map(|i| (i * 13) as u32).collect();
        Postings {
            documents: ids,
            offsets,
        }
    }

    #[test]
    fn dense_and_sparse_monotone_seeks_match_an_independent_scalar_oracle() {
        for mask in 0u64..4096 {
            let p = postings((1..=12).filter(|id| mask & (1 << (id - 1)) != 0).collect());
            for probes in [(1..=13).collect::<Vec<_>>(), vec![1, 4, 9, 12, 13]] {
                let mut cursor = Cursor::default();
                let mut work = budget(4096);
                for id in probes {
                    let expected = p
                        .documents
                        .iter()
                        .position(|value| *value == id)
                        .map(|at| p.offsets[at]);
                    assert_eq!(
                        cursor.offset(&p, id, &mut work, &mut || true).unwrap(),
                        expected
                    );
                }
            }
        }
    }

    #[test]
    fn dense_scans_are_linear_and_budget_endpoints_are_inclusive() {
        let p = postings((1..=2048).collect());
        let mut cursor = Cursor::default();
        let mut work = budget(2048);
        for id in 1..=2048 {
            assert_eq!(
                cursor.offset(&p, id, &mut work, &mut || true).unwrap(),
                Some((id as u32 - 1) * 13)
            );
        }
        assert_eq!(work.work, 2048);
        let mut cursor = Cursor::default();
        let mut work = budget(2047);
        for id in 1..=2047 {
            cursor.offset(&p, id, &mut work, &mut || true).unwrap();
        }
        assert!(matches!(
            cursor.offset(&p, 2048, &mut work, &mut || true),
            Err(LexicalError::Limit("query work"))
        ));
    }

    #[test]
    fn a_sparse_scope_does_not_scan_the_excluded_posting_prefix() {
        let p = postings((1..=2048).collect());
        let mut cursor = Cursor::default();
        let mut work = budget(32);
        assert_eq!(
            cursor.offset(&p, 2048, &mut work, &mut || true).unwrap(),
            Some(2047 * 13)
        );
        assert!(work.work <= 24);
        assert_eq!(
            cursor
                .offset(&p, u64::MAX, &mut work, &mut || true)
                .unwrap(),
            None
        );
    }

    #[test]
    fn nonconsecutive_ids_empty_columns_and_maximum_ids_keep_offsets() {
        let p = postings(vec![1, 97, u64::MAX - 1, u64::MAX]);
        let mut cursor = Cursor::default();
        let mut work = budget(100);
        for (id, expected) in [
            (1, Some(0)),
            (2, None),
            (96, None),
            (97, Some(13)),
            (u64::MAX - 2, None),
            (u64::MAX - 1, Some(26)),
            (u64::MAX, Some(39)),
        ] {
            assert_eq!(
                cursor.offset(&p, id, &mut work, &mut || true).unwrap(),
                expected
            );
        }
        assert_eq!(
            Cursor::default()
                .offset(&postings(Vec::new()), 1, &mut work, &mut || true)
                .unwrap(),
            None
        );
    }

    #[test]
    fn repeated_or_reversed_documents_refuse_instead_of_silently_losing_matches() {
        let p = postings(vec![1, 2, 3]);
        for invalid in [1, 2] {
            let mut cursor = Cursor::default();
            let mut work = budget(100);
            assert_eq!(
                cursor.offset(&p, 2, &mut work, &mut || true).unwrap(),
                Some(13)
            );
            assert!(matches!(
                cursor.offset(&p, invalid, &mut work, &mut || true),
                Err(LexicalError::Invalid("ranked document order"))
            ));
        }
    }

    #[test]
    fn every_gallop_checkpoint_can_cancel_without_returning_a_match() {
        let p = postings((1..=2048).collect());
        let mut calls = 0;
        Cursor::default()
            .offset(&p, 1700, &mut budget(100), &mut || {
                calls += 1;
                true
            })
            .unwrap();
        for stop in 0..calls {
            let mut observed = 0;
            assert!(matches!(
                Cursor::default().offset(&p, 1700, &mut budget(100), &mut || {
                    let live = observed < stop;
                    observed += 1;
                    live
                }),
                Err(LexicalError::Cancelled)
            ));
        }
    }
}
