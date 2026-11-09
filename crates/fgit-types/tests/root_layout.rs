//! Layout changes must preserve old wire meanings, including reserved codes.

use fgit_types::TypeRefusal;
use fgit_types::layout::RootLayoutVersion;

#[test]
fn layouts_pin_wire_codes_proof_families_and_head_commitment() {
    let expectations = [
        (
            RootLayoutVersion::LegacyWholeBody,
            0,
            false,
            false,
            true,
            false,
        ),
        (
            RootLayoutVersion::RefStateMerkleV1,
            1,
            true,
            false,
            false,
            false,
        ),
        (
            RootLayoutVersion::RefStateAndObjectClosureMerkleV1,
            2,
            true,
            true,
            false,
            false,
        ),
        (
            RootLayoutVersion::RefStateMerkleV2,
            4,
            true,
            false,
            true,
            true,
        ),
        (
            RootLayoutVersion::RefStateAndObjectClosureMerkleV2,
            5,
            true,
            true,
            true,
            true,
        ),
    ];
    assert_eq!(RootLayoutVersion::ALL.len(), expectations.len());
    for (index, (layout, code, refs, objects, head, head_merkle)) in
        expectations.into_iter().enumerate()
    {
        assert_eq!(RootLayoutVersion::ALL[index], layout);
        assert_eq!(layout.code_point(), code);
        assert_eq!(RootLayoutVersion::from_code_point(code), Ok(layout));
        assert_eq!(layout.admits_ref_state_membership_proof(), refs);
        assert_eq!(layout.admits_object_closure_membership_proof(), objects);
        assert_eq!(layout.commits_head_target(), head);
        assert_eq!(layout.uses_head_aware_ref_merkle(), head_merkle);
    }
    assert_eq!(
        RootLayoutVersion::default(),
        RootLayoutVersion::LegacyWholeBody
    );
}

#[test]
fn reserved_forge_code_and_unknown_codes_are_not_claimed_by_head_layouts() {
    for code in [3, 6, u16::MAX] {
        assert_eq!(
            RootLayoutVersion::from_code_point(code),
            Err(TypeRefusal::CodePointUnknown {
                field: "RootLayoutVersion",
                observed: u32::from(code),
            })
        );
    }
}
