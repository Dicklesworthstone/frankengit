//! Bounded immutable staging in one native transaction.
//!
//! This groups physical writes without creating a repository decision or
//! changing the write-once law. Only the authority-head operation publishes.
//! Cached comparisons use committed bytes; newly inserted bytes enter the
//! cache only after the whole transaction's COMMIT has completed.

use super::*;

impl FsqliteAuthorityStore {
    /// One attempt of the public batch operation. Its caller preflights the
    /// authority batch count/byte limits before entering the retry driver.
    pub(super) async fn put_batch_once<Caps>(
        &self,
        cx: &Cx<Caps>,
        entries: &[(ImmutableKey, Vec<u8>)],
    ) -> Result<Vec<PutOutcome>, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        for (_, body) in entries {
            self.admit_body(body)?;
        }
        let mut lease = self.operation(cx).await?;
        let mut outcomes = Vec::with_capacity(entries.len());
        let mut all_cached = true;
        for (key, body) in entries {
            checkpoint(cx)?;
            let cached = self.bodies.matches(key.as_bytes(), body).map(|identical| {
                if identical {
                    PutOutcome::IdenticalRetry
                } else {
                    PutOutcome::Conflict
                }
            });
            all_cached &= cached.is_some();
            outcomes.push(cached);
        }
        if all_cached {
            return settled(outcomes);
        }

        self.begin(cx, &mut lease).await?;
        let attempt = self.stage_batch(cx, entries, &mut outcomes).await;
        let outcomes = match attempt {
            Ok(()) => match settled(outcomes) {
                Ok(outcomes) => outcomes,
                Err(cause) => return Err(self.rollback_after(cx, &mut lease, cause).await),
            },
            Err(cause) => return Err(self.rollback_after(cx, &mut lease, cause).await),
        };
        if let Err(cause) = self.commit(cx, &mut lease).await {
            return Err(self.rollback_after(cx, &mut lease, cause).await);
        }
        // Do not turn a completed COMMIT into cancellation afterwards. These
        // bounded cache inserts retain already committed bytes only, and the
        // exact terminal answer remains available to the caller.
        for ((key, body), outcome) in entries.iter().zip(&outcomes) {
            if matches!(outcome, PutOutcome::Created | PutOutcome::IdenticalRetry) {
                self.bodies.insert(key.as_bytes(), body);
            }
        }
        Ok(outcomes)
    }

    async fn stage_batch<Caps>(
        &self,
        cx: &Cx<Caps>,
        entries: &[(ImmutableKey, Vec<u8>)],
        outcomes: &mut [Option<PutOutcome>],
    ) -> Result<(), EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        // COUNT is a table scan. It runs once for this finite transaction;
        // only actual new rows increase the in-transaction occupancy. The
        // engine's commit validation still arbitrates concurrent writers.
        let mut occupancy = self.occupancy(cx, "body.count").await?;
        let limit = self.limits.immutable_slots;
        for ((key, body), outcome) in entries.iter().zip(outcomes) {
            checkpoint(cx)?;
            if outcome.is_some() {
                continue;
            }
            if occupancy >= limit {
                // A full store must still answer identical retries and
                // conflicts, including a key created earlier in this batch.
                let rows = self.query(cx, "body.read", &[blob(key.as_bytes())]).await?;
                let row = rows.first().ok_or(EngineError::Contract(
                    AuthorityRefusal::CapacityExhausted { occupancy, limit },
                ))?;
                *outcome = Some(compare_stored_body(read_blob(row, 0)?, body));
                continue;
            }
            let changed = self
                .execute(
                    cx,
                    "body.put_if_absent",
                    &[blob(key.as_bytes()), blob(body)],
                )
                .await?;
            *outcome = Some(match interpret_put_if_absent(changed) {
                PutStep::Created => {
                    // occupancy < limit <= usize::MAX above proves this add.
                    occupancy += 1;
                    PutOutcome::Created
                }
                PutStep::OccupiedNeedsComparison => {
                    let rows = self.query(cx, "body.read", &[blob(key.as_bytes())]).await?;
                    let row = rows.first().ok_or(EngineError::RowMissing {
                        statement: "body.read",
                    })?;
                    compare_stored_body(read_blob(row, 0)?, body)
                }
            });
        }
        checkpoint(cx)
    }
}

fn checkpoint<Caps>(cx: &Cx<Caps>) -> Result<(), EngineError>
where
    Caps: cap::SubsetOf<cap::All>,
    cap::None: cap::SubsetOf<Caps>,
{
    if cx.is_cancel_requested() || cx.checkpoint().is_err() {
        Err(EngineError::Engine(TransientClass::Cancelled))
    } else {
        Ok(())
    }
}

fn settled(outcomes: Vec<Option<PutOutcome>>) -> Result<Vec<PutOutcome>, EngineError> {
    outcomes
        .into_iter()
        .map(|outcome| outcome.ok_or(EngineError::Contract(AuthorityRefusal::Unavailable)))
        .collect()
}

#[cfg(test)]
#[path = "immutable_batch/tests.rs"]
mod tests;
