//! Persisted preparation has a bounded repository budget, while each file and
//! interactive request retain their existing limits and canonical table bytes.
use super::*;

#[test]
fn index_build_counts_all_files_and_still_refuses_one_over_either_declaration_limit() {
    let file = "fn f(){}\n".repeat(MAX_DECLARATIONS);
    let mut indexed = Budget::for_index_build();
    for _ in 0..MAX_INDEX_DECLARATIONS / MAX_DECLARATIONS {
        assert_eq!(
            extract(file.as_bytes(), &mut indexed, &|| false)
                .unwrap()
                .declarations
                .len(),
            MAX_DECLARATIONS
        );
    }
    let remainder = MAX_INDEX_DECLARATIONS % MAX_DECLARATIONS;
    assert_eq!(
        extract(
            "fn f(){}\n".repeat(remainder).as_bytes(),
            &mut indexed,
            &|| false,
        )
        .unwrap()
        .declarations
        .len(),
        remainder
    );
    assert_eq!(indexed.declarations, MAX_INDEX_DECLARATIONS);
    assert_eq!(
        extract(b"fn extra(){}", &mut indexed, &|| false)
            .unwrap_err()
            .kind,
        ErrorKind::DeclarationLimit
    );

    // The repository allowance cannot be spent on one oversized file.
    let oversized = format!("{file}fn extra(){{}}\n");
    assert_eq!(
        extract(
            oversized.as_bytes(),
            &mut Budget::for_index_build(),
            &|| false,
        )
        .unwrap_err()
        .kind,
        ErrorKind::DeclarationLimit
    );
    let mut live = Budget::new(MAX_WORK).unwrap();
    extract(file.as_bytes(), &mut live, &|| false).unwrap();
    assert_eq!(
        extract(b"fn extra(){}", &mut live, &|| false)
            .unwrap_err()
            .kind,
        ErrorKind::DeclarationLimit
    );
}

#[test]
fn repository_scanning_can_spend_more_than_interactive_work_without_refunding_bytes() {
    // Nine files contain 36 MiB of source, below the unchanged corpus ceiling.
    // UTF-8 validation and lexical traversal each charge every original byte.
    let file = vec![b' '; 4 * 1024 * 1024];
    let mut indexed = Budget::for_index_build();
    let mut live = Budget::new(MAX_WORK).unwrap();
    for _ in 0..8 {
        extract(&file, &mut indexed, &|| false).unwrap();
        extract(&file, &mut live, &|| false).unwrap();
    }
    assert_eq!(indexed.work, MAX_WORK);
    assert_eq!(live.work, MAX_WORK);
    extract(&file, &mut indexed, &|| false).unwrap();
    assert_eq!(indexed.work, MAX_WORK + 2 * file.len() as u64);
    assert_eq!(
        extract(&file, &mut live, &|| false).unwrap_err().kind,
        ErrorKind::WorkLimit
    );
    assert!(Budget::new(MAX_WORK + 1).is_err());
}

#[test]
fn repository_work_boundary_and_cancellation_are_exact() {
    let file = b"fn kept(){} /* unfinished";
    let mut measured = Budget::for_index_build();
    assert_eq!(
        extract(file, &mut measured, &|| false).unwrap_err().kind,
        ErrorKind::UnterminatedComment
    );
    assert!(measured.work > file.len() as u64);
    // A syntax omission can discard declarations, never work already spent.
    measured.declarations = 0;
    let spent = measured.work;
    extract(b"fn next(){}", &mut measured, &|| false).unwrap();
    assert!(measured.work > spent);

    let source = b"fn final_file(){}\n";
    let mut sample = Budget::for_index_build();
    extract(source, &mut sample, &|| false).unwrap();
    let mut exact = Budget::for_index_build();
    exact.work = MAX_INDEX_BUILD_WORK - sample.work;
    extract(source, &mut exact, &|| false).unwrap();
    assert_eq!(exact.work, MAX_INDEX_BUILD_WORK);
    let mut short = Budget::for_index_build();
    short.work = MAX_INDEX_BUILD_WORK - sample.work + 1;
    assert_eq!(
        extract(source, &mut short, &|| false).unwrap_err().kind,
        ErrorKind::WorkLimit
    );
    assert_eq!(
        extract(b"", &mut Budget::for_index_build(), &|| true)
            .unwrap_err()
            .kind,
        ErrorKind::Cancelled
    );
    let polls = std::cell::Cell::new(0);
    let cancel = || {
        polls.set(polls.get() + 1);
        polls.get() > 4
    };
    assert_eq!(
        extract(&vec![b' '; 8192], &mut Budget::for_index_build(), &cancel)
            .unwrap_err()
            .kind,
        ErrorKind::Cancelled
    );
}

#[test]
fn larger_build_budget_does_not_change_existing_table_encoding_or_query_work() {
    use crate::source_symbols::table::{Table, Work};
    let source = b"pub struct Existing;\nfn r#type(){}\n";
    let strict = Table::build(source, &mut Budget::new(MAX_WORK).unwrap(), &|| false).unwrap();
    let mut index_budget = Budget::for_index_build();
    index_budget.declarations = MAX_DECLARATIONS + 1;
    let indexed = Table::build(source, &mut index_budget, &|| false).unwrap();
    assert_eq!(
        strict.encode(&|| false).unwrap(),
        indexed.encode(&|| false).unwrap()
    );
    assert!(Work::new(MAX_WORK).is_ok());
    assert!(Work::new(MAX_WORK + 1).is_err());
}
