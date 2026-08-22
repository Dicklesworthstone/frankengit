#!/usr/bin/env python3
"""Generate the exact-rational oracle table for `expected_loss_error_evidence.rs`.

THIS IS AN INDEPENDENT ORACLE, NOT A DUMP OF THE RUST IMPLEMENTATION'S OUTPUT.

That distinction is the whole value of the table. A golden file recorded from
the code it checks proves only that the code is deterministic; regenerating one
to make a red test green is RH-3 (golden regeneration) and is forbidden by
AGENTS.md 16.3. Every number below is computed here from `fractions.Fraction`
-- exact rational arithmetic, no floating point anywhere on the path -- so a
disagreement between this table and the Rust code is evidence against the Rust
code, and the correct response is to fix the Rust code.

The closed form, for integer Beta parameters:

    P(theta_b > theta_a) = sum over i in 0..alpha_b of T(i)

    T(0)   = (beta_a+beta_b-1)! (alpha_a+beta_a-1)!
             ---------------------------------------
             (beta_a-1)! (alpha_a+beta_a+beta_b-1)!

    T(i+1) = T(i) * (alpha_a+i)   * (1+i+beta_b) * (beta_b+i)
                    ------------------------------------------
                    (alpha_a+i+beta_a+beta_b) * (1+i) * (beta_b+i+1)

The recurrence is the same one the Rust module walks, but it is walked here in
exact rationals where the Rust module walks it in fixed point, and it is walked
from T(0) upward where the Rust module walks outward from the peak. Those are
the two things under test: the transcription and the summation order.

Cross-check performed when this table was generated: the five reference points
in the module documentation were also computed by direct factorial evaluation
of the Beta-function form, `B(alpha_a+i, beta_a+beta_b) / ((beta_b+i)
B(1+i, beta_b) B(alpha_a, beta_a))`, which shares no code path with the
recurrence above. Both agree to the last digit.

Each row carries BOTH exact tails:

    (alpha_a, beta_a, alpha_b, beta_b, exact_b_exceeds_a, exact_a_exceeds_b)

The second is the same closed form with the two posteriors exchanged, and it is
computed here rather than derived as `1_000_000 - first`. Deriving it would make
any test that compares both tails tautological: the derived value cannot
disagree with the first, so it could not catch a normalisation that inflates one
tail. It is also not equal to the complement in general, because both are
floored — for Beta(20,10) vs Beta(10,20) the tails floor to 4037 and 995962,
which sum to 999999, not a million.

Usage:

    python3 crates/fgit-statistics/tests/oracle/generate.py

prints the Rust table body on stdout.
"""

from fractions import Fraction
import math

# Deterministic parameter draw. A fixed LCG rather than `random` so the table
# regenerates byte-identically on any machine and any Python version: the
# sample IS part of the evidence, and a sample nobody else can reproduce is
# not evidence.
LCG_MULTIPLIER = 6364136223846793005
LCG_INCREMENT = 1442695040888963407
LCG_SEED = 0x2545F4914F6CDD1D
MODULUS = (1 << 64) - 1

# All four parameters are drawn from this range. 300 is chosen because it
# exceeds the largest parameter set NEG-025 recorded while keeping the exact
# rational evaluation cheap enough to rerun.
MAX_PARAMETER = 300

ROWS = 500


def exact_ppm_floor(alpha_a, beta_a, alpha_b, beta_b):
    """P(theta_b > theta_a) in ppm, truncated toward zero, exactly."""
    term = Fraction(
        math.factorial(beta_a + beta_b - 1) * math.factorial(alpha_a + beta_a - 1),
        math.factorial(beta_a - 1) * math.factorial(alpha_a + beta_a + beta_b - 1),
    )
    total = term
    for index in range(alpha_b - 1):
        term *= Fraction(
            (alpha_a + index) * (1 + index + beta_b) * (beta_b + index),
            (alpha_a + index + beta_a + beta_b) * (1 + index) * (beta_b + index + 1),
        )
        total += term
    return int(total * 1_000_000)


def draws():
    state = LCG_SEED
    while True:
        state = (state * LCG_MULTIPLIER + LCG_INCREMENT) & MODULUS
        yield (state >> 33) % MAX_PARAMETER + 1


def main():
    stream = draws()
    for _ in range(ROWS):
        alpha_a, beta_a, alpha_b, beta_b = (next(stream) for _ in range(4))
        # The draw order is unchanged, so the first five columns of every row
        # are byte-identical to the previous five-column table. That is
        # checkable with `cut -d, -f1-5` and is the reason this extends the
        # generator rather than adding a second one.
        b_exceeds_a = exact_ppm_floor(alpha_a, beta_a, alpha_b, beta_b)
        a_exceeds_b = exact_ppm_floor(alpha_b, beta_b, alpha_a, beta_a)
        # Digit separators on the ppm values: clippy's `unreadable_literal` is
        # deny-level in this workspace, so a table without them would not
        # compile.
        print(
            f"    ({alpha_a}, {beta_a}, {alpha_b}, {beta_b}, "
            f"{b_exceeds_a:_}, {a_exceeds_b:_}),"
        )


if __name__ == "__main__":
    main()
