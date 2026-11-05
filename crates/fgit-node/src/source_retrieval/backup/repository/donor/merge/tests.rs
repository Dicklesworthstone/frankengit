use super::*;
use std::cell::Cell;
use std::io::Cursor;

#[derive(Clone, Copy)]
struct Header {
    oid: GitOid,
    length: u64,
}
impl Record for Header {
    fn oid(self) -> GitOid {
        self.oid
    }
    fn length(self) -> u64 {
        self.length
    }
}
fn oid(format: GitHashAlgorithm, marker: u8) -> GitOid {
    GitOid::from_hex(format, &format!("{marker:02x}").repeat(format.digest_len())).unwrap()
}
fn header(format: GitHashAlgorithm, marker: u8, length: u64) -> Header {
    Header {
        oid: oid(format, marker),
        length,
    }
}
fn limits(format: GitHashAlgorithm, objects: usize) -> Limits {
    Limits {
        format,
        donor_objects: objects,
        max_objects: 100,
        max_donor_payload_bytes: 1 << 30,
    }
}
fn scan(
    rows: &[(Header, &[u8])],
    visit: &mut dyn FnMut(Header, &mut dyn Read) -> Result<(), String>,
) -> Result<(), String> {
    for (header, bytes) in rows {
        visit(*header, &mut Cursor::new(*bytes))?;
    }
    Ok(())
}
fn consume(item: Source<'_, Header>) -> Result<(), String> {
    if let Source::Donor(_, input) = item {
        io::copy(input, &mut io::sink()).map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[test]
fn donor_overlap_and_local_gaps_preserve_the_complete_sorted_output_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let selected = BTreeSet::from([
            oid(format, 1),
            oid(format, 3),
            oid(format, 4),
            oid(format, 6),
        ]);
        let rows = [
            (header(format, 2, 7), b"ignored".as_slice()),
            (header(format, 3, 5), b"three".as_slice()),
            (header(format, 6, 3), b"six".as_slice()),
        ];
        let mut output = Vec::new();
        let counts = compose(
            &selected,
            limits(format, rows.len()),
            |visit| scan(&rows, visit),
            |item| {
                let (oid, bytes) = match item {
                    Source::Local(oid) if oid == self::oid(format, 1) => (oid, b"one".to_vec()),
                    Source::Local(oid) if oid == self::oid(format, 4) => (oid, b"four".to_vec()),
                    Source::Local(_) => {
                        return Err("damaged overlap must never read local storage".into());
                    }
                    Source::Donor(header, input) => {
                        let mut bytes = Vec::new();
                        input
                            .read_to_end(&mut bytes)
                            .map_err(|error| error.to_string())?;
                        (header.oid, bytes)
                    }
                };
                output.push((oid, bytes));
                Ok(())
            },
            || Ok(()),
        )
        .unwrap();
        assert_eq!(
            output,
            vec![
                (oid(format, 1), b"one".to_vec()),
                (oid(format, 3), b"three".to_vec()),
                (oid(format, 4), b"four".to_vec()),
                (oid(format, 6), b"six".to_vec()),
            ]
        );
        assert_eq!(
            counts,
            Counts {
                donor_objects: 2,
                donor_payload_bytes: 8,
                local_objects: 2
            }
        );
    }
}

struct Generated {
    remaining: u64,
    calls: usize,
    largest_offer: usize,
}
impl Read for Generated {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        self.largest_offer = self.largest_offer.max(output.len());
        let count = output.len().min(usize::try_from(self.remaining).unwrap());
        output[..count].fill(0x5a);
        self.remaining -= count as u64;
        Ok(count)
    }
}

#[test]
fn large_selected_payload_has_a_bounded_source_read_and_no_payload_sized_buffer() {
    let format = GitHashAlgorithm::Sha256;
    let length = 32 * 1024 * 1024 + 17;
    let row = header(format, 1, length);
    let mut input = Generated {
        remaining: length,
        calls: 0,
        largest_offer: 0,
    };
    let mut delivered = 0_u64;
    let counts = compose(
        &BTreeSet::from([row.oid]),
        limits(format, 1),
        |visit| visit(row, &mut input),
        |item| {
            let Source::Donor(_, input) = item else {
                return Err("unexpected local read".into());
            };
            let mut buffer = vec![0; CHUNK_BYTES * 2];
            loop {
                let count = input.read(&mut buffer).map_err(|error| error.to_string())?;
                if count == 0 {
                    break;
                }
                assert!(buffer[..count].iter().all(|byte| *byte == 0x5a));
                delivered += count as u64;
            }
            Ok(())
        },
        || Ok(()),
    )
    .unwrap();
    assert_eq!(delivered, length);
    assert_eq!(counts.donor_payload_bytes, length);
    assert_eq!(input.remaining, 0);
    assert!(input.calls > 512);
    assert_eq!(input.largest_offer, CHUNK_BYTES);
}

#[test]
fn the_local_tail_is_withheld_until_original_whole_donor_seal_validation() {
    let format = GitHashAlgorithm::Sha1;
    let donor = header(format, 2, 3);
    let selected = BTreeSet::from([oid(format, 1), donor.oid, oid(format, 3)]);
    let mut delivered = Vec::new();
    let failure = compose(
        &selected,
        limits(format, 1),
        |visit| {
            visit(donor, &mut Cursor::new(b"two"))?;
            Err("original donor seal changed at EOF".into())
        },
        |item| {
            delivered.push(match &item {
                Source::Local(oid) => *oid,
                Source::Donor(header, _) => header.oid,
            });
            consume(item)
        },
        || Ok(()),
    )
    .unwrap_err();
    assert!(failure.contains("seal changed"));
    assert_eq!(delivered, [oid(format, 1), donor.oid]);
}

#[test]
fn a_scanner_cannot_swallow_a_failed_callback_and_resume_composition() {
    let format = GitHashAlgorithm::Sha1;
    let first = header(format, 1, 1);
    let second = header(format, 2, 1);
    let mut sink_calls = 0;
    let failure = compose(
        &BTreeSet::from([first.oid, second.oid]),
        limits(format, 2),
        |visit| {
            assert!(visit(first, &mut Cursor::new(b"a")).is_err());
            assert!(visit(second, &mut Cursor::new(b"b")).is_err());
            Ok(())
        },
        |_| {
            sink_calls += 1;
            Err("output write failed after header".into())
        },
        || Ok(()),
    )
    .unwrap_err();
    assert_eq!(sink_calls, 1);
    assert!(failure.contains("output write failed"));
}

struct RejectEof(Cursor<&'static [u8]>);
impl Read for RejectEof {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.0.read(output)?;
        if count == 0 {
            Err(io::Error::other("original strong commitment mismatch"))
        } else {
            Ok(count)
        }
    }
}

#[test]
fn read_exact_still_requires_the_original_authenticated_record_eof() {
    let format = GitHashAlgorithm::Sha256;
    let row = header(format, 1, 3);
    let selected = BTreeSet::from([row.oid]);
    let exact = |item: Source<'_, Header>| {
        let Source::Donor(_, input) = item else {
            return Err("unexpected local".into());
        };
        let mut bytes = [0; 3];
        input
            .read_exact(&mut bytes)
            .map_err(|error| error.to_string())?;
        assert_eq!(&bytes, b"abc");
        Ok(())
    };
    assert!(
        compose(
            &selected,
            limits(format, 1),
            |visit| visit(row, &mut Cursor::new(b"abc")),
            exact,
            || Ok(())
        )
        .is_ok()
    );
    let failure = compose(
        &selected,
        limits(format, 1),
        |visit| visit(row, &mut RejectEof(Cursor::new(b"abc"))),
        exact,
        || Ok(()),
    )
    .unwrap_err();
    assert!(failure.contains("strong commitment mismatch"));
}

#[test]
fn a_sink_cannot_swallow_a_late_authentication_read_error() {
    let format = GitHashAlgorithm::Sha1;
    let row = header(format, 1, 3);
    let failure = compose(
        &BTreeSet::from([row.oid]),
        limits(format, 1),
        |visit| visit(row, &mut RejectEof(Cursor::new(b"abc"))),
        |item| {
            let Source::Donor(_, input) = item else {
                return Err("unexpected local".into());
            };
            let mut output = Vec::new();
            assert!(input.read_to_end(&mut output).is_err());
            assert_eq!(output, b"abc");
            Ok(())
        },
        || Ok(()),
    )
    .unwrap_err();
    assert!(failure.contains("strong commitment mismatch"));
}

#[test]
fn ignored_donor_payloads_are_authenticated_before_new_local_objects_are_read() {
    let format = GitHashAlgorithm::Sha256;
    let row = header(format, 1, 3);
    let calls = Cell::new(0);
    let failure = compose(
        &BTreeSet::from([oid(format, 2)]),
        limits(format, 1),
        |visit| visit(row, &mut RejectEof(Cursor::new(b"abc"))),
        |_| {
            calls.set(calls.get() + 1);
            Ok(())
        },
        || Ok(()),
    )
    .unwrap_err();
    assert!(failure.contains("strong commitment mismatch"));
    assert_eq!(calls.get(), 0);
    let positive = compose(
        &BTreeSet::new(),
        limits(format, 1),
        |visit| visit(row, &mut Cursor::new(b"abc")),
        |_| panic!("no selected objects"),
        || Ok(()),
    )
    .unwrap();
    assert_eq!(positive, Counts::default());
}

#[test]
fn truncated_trailing_and_unconsumed_selected_payloads_refuse() {
    let format = GitHashAlgorithm::Sha1;
    let row = header(format, 1, 3);
    for bytes in [b"ab".as_slice(), b"abcd".as_slice()] {
        assert!(
            compose(
                &BTreeSet::from([row.oid]),
                limits(format, 1),
                |visit| visit(row, &mut Cursor::new(bytes)),
                consume,
                || Ok(())
            )
            .is_err()
        );
    }
    let failure = compose(
        &BTreeSet::from([row.oid]),
        limits(format, 1),
        |visit| visit(row, &mut Cursor::new(b"abc")),
        |_| Ok(()),
        || Ok(()),
    )
    .unwrap_err();
    assert!(failure.contains("not completely consumed"));
}

struct InvalidCount;
impl Read for InvalidCount {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        Ok(output.len() + 1)
    }
}
#[test]
fn invalid_reader_counts_refuse_without_panicking_or_wrapping_the_remaining_length() {
    let format = GitHashAlgorithm::Sha256;
    let row = header(format, 1, 3);
    let failure = compose(
        &BTreeSet::from([row.oid]),
        limits(format, 1),
        |visit| visit(row, &mut InvalidCount),
        consume,
        || Ok(()),
    )
    .unwrap_err();
    assert!(failure.contains("invalid byte count"));
}

struct Interrupted {
    reads: usize,
}
impl Read for Interrupted {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        Err(io::ErrorKind::Interrupted.into())
    }
}
#[test]
fn interrupted_reads_recheck_cancellation_instead_of_spinning_forever() {
    let format = GitHashAlgorithm::Sha1;
    let row = header(format, 1, 1);
    let mut input = Interrupted { reads: 0 };
    let checkpoints = Cell::new(0);
    let failure = compose(
        &BTreeSet::from([row.oid]),
        limits(format, 1),
        |visit| visit(row, &mut input),
        consume,
        || {
            checkpoints.set(checkpoints.get() + 1);
            if checkpoints.get() >= 20 {
                Err("cancelled".into())
            } else {
                Ok(())
            }
        },
    )
    .unwrap_err();
    assert!(failure.contains("cancelled"));
    assert!((2..20).contains(&input.reads));
}

#[test]
fn cancellation_before_work_opens_neither_source() {
    let format = GitHashAlgorithm::Sha256;
    let failure = compose::<Header>(
        &BTreeSet::from([oid(format, 1)]),
        limits(format, 0),
        |_| panic!("cancelled before donor scan"),
        |_| panic!("cancelled before local source"),
        || Err("deadline exceeded".into()),
    )
    .unwrap_err();
    assert!(failure.contains("deadline exceeded"));
}

#[test]
fn malformed_order_domain_and_inventory_never_become_partial_success() {
    let format = GitHashAlgorithm::Sha1;
    let one = header(format, 1, 1);
    let two = header(format, 2, 1);
    let cases = [
        (vec![(one, b"a".as_slice()), (one, b"a".as_slice())], 2),
        (vec![(two, b"b".as_slice()), (one, b"a".as_slice())], 2),
        (
            vec![(header(GitHashAlgorithm::Sha256, 1, 1), b"a".as_slice())],
            1,
        ),
        (vec![(header(format, 0, 1), b"a".as_slice())], 1),
        (vec![(one, b"a".as_slice())], 0),
        (vec![(one, b"a".as_slice())], 2),
    ];
    for (rows, count) in cases {
        assert!(
            compose(
                &BTreeSet::new(),
                limits(format, count),
                |visit| scan(&rows, visit),
                consume,
                || Ok(())
            )
            .is_err()
        );
    }
    for selected in [
        BTreeSet::from([oid(format, 0)]),
        BTreeSet::from([oid(GitHashAlgorithm::Sha256, 1)]),
    ] {
        assert!(
            compose::<Header>(
                &selected,
                limits(format, 0),
                |_| panic!("selected domain precedes source access"),
                consume,
                || Ok(())
            )
            .is_err()
        );
    }
}

#[test]
fn finite_object_and_payload_bounds_are_shared_with_ignored_records() {
    let format = GitHashAlgorithm::Sha256;
    let row = header(format, 1, 3);
    let mut budget = limits(format, 1);
    budget.max_donor_payload_bytes = 2;
    assert!(
        compose(
            &BTreeSet::new(),
            budget,
            |visit| visit(row, &mut Cursor::new(b"abc")),
            consume,
            || Ok(())
        )
        .is_err()
    );
    budget.max_donor_payload_bytes = 3;
    assert!(
        compose(
            &BTreeSet::new(),
            budget,
            |visit| visit(row, &mut Cursor::new(b"abc")),
            consume,
            || Ok(())
        )
        .is_ok()
    );
    budget.max_objects = 0;
    assert!(
        compose::<Header>(
            &BTreeSet::new(),
            budget,
            |_| panic!("invalid bounds before scan"),
            consume,
            || Ok(())
        )
        .is_err()
    );
}

#[test]
fn a_missing_new_object_is_not_replaced_by_older_donor_metadata() {
    let format = GitHashAlgorithm::Sha1;
    let old = header(format, 1, 3);
    let failure = compose(
        &BTreeSet::from([old.oid, oid(format, 2)]),
        limits(format, 1),
        |visit| visit(old, &mut Cursor::new(b"old")),
        |item| match item {
            Source::Local(_) => Err("current selected object missing".into()),
            donor => consume(donor),
        },
        || Ok(()),
    )
    .unwrap_err();
    assert!(failure.contains("current selected object missing"));
}
