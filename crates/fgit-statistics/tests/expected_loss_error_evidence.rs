//! `frankengit-s76z`: the measured error evidence the expected-loss integral owes.
//!
//! The bead's requirement, verbatim: *"implement the expected-loss integral
//! with a STATED error-evidence obligation (the approximation owes measured
//! error bounds vs the closed-form recurrence). Not a golden-vector-free round
//! trip — pin the numeric accuracy."*
//!
//! This file is that obligation, discharged as a re-runnable test rather than a
//! sentence in a doc comment. [`ORACLE`] is 500 parameter sets with their
//! **exact** values, computed in exact rational arithmetic by
//! `tests/oracle/generate.py` — an independent evaluation of the same closed
//! form, walked from `T(0)` upward in `Fraction`s where the module under test
//! walks it outward from the peak in fixed point. The two things under test are
//! therefore the transcription and the summation order, which are exactly the
//! two things `NEG-025` got wrong.
//!
//! The table is NOT a recording of this module's own output. A golden captured
//! from the code it checks proves only determinism, and regenerating one to
//! turn a red test green is `RH-3`. If this table and the module disagree, the
//! module is wrong.
//!
//! # What was measured, and why the result is stronger than the obligation
//!
//! Over the 500 sets, all four parameters drawn from `1..=300`:
//!
//! * **457 produce a value; 327 of those have a non-zero exact value, and every
//!   one of the 457 equals the exact floor exactly.** Worst error over this
//!   sample: `0 ppm`;
//! * **zero overestimates**;
//! * **43 refuse**, and every refused set has an exact value below `1 ppm`, so
//!   nothing representable in parts per million is lost to the refusal.
//!
//! Exactness here is structural rather than lucky, which is why it is asserted
//! rather than tolerated. Each step of the walk floors one division, costing at
//! most `2^-96` relative; the walk is at most `alpha_b <= 300` steps; so the
//! accumulated error is bounded by about `300 * 2^-96 ~ 4e-27` against a `1e-6`
//! quantum — twenty-one orders of magnitude of headroom. A result that differs
//! from the exact floor would mean the true value sits within `4e-27` of a ppm
//! boundary, or that something other than flooring is happening. The second is
//! the one worth catching.
//!
//! **This sample does not contain the worst case, and the module does not claim
//! it does.** A randomly drawn parameter set essentially never lands on an
//! exact ppm boundary, which by the argument above is the only place the
//! flooring can change the reported integer. The boundary family — any
//! posterior against itself, exactly `1/2` — is walked by
//! `expected_loss_accuracy.rs`, and there the shortfall is exactly `1 ppm`.
//! That is why the module states a `1 ppm` bound while this file measures `0`:
//! the two are measurements of different regions, and the stated bound is the
//! looser of them.
//!
//! The non-zero count matters: a row whose exact value is `0 ppm` is matched by
//! any implementation that returns zero, including the broken one `NEG-025`
//! recorded. Only the 327 non-trivial rows discriminate, so that count is
//! asserted too — if the sample ever drifts toward trivial rows, this file
//! weakens silently, which is the failure mode `RH-1` names.

use fgit_statistics::beta_bernoulli::{BetaPrior, Outcomes, Posterior};
use fgit_statistics::expected_loss::{ExpectedLossRefusal, probability_b_exceeds_a_ppm};

/// Sets that produce a value.
const EXPECTED_ANSWERED: u32 = 457;

/// Answered sets whose exact value is above zero — the discriminating ones.
const EXPECTED_NON_TRIVIAL: u32 = 327;

/// Sets whose peak term is unrepresentable at this scale.
const EXPECTED_REFUSALS: u32 = 43;

fn posterior(alpha: u32, beta: u32) -> Posterior {
    BetaPrior::try_new(alpha, beta)
        .expect("every drawn parameter is at least one, so the prior is proper")
        .update(Outcomes {
            successes: 0,
            trials: 0,
        })
        .expect("zero observations update cleanly")
}

/// `(alpha_a, beta_a, alpha_b, beta_b, exact_ppm_floor)`.
///
/// Regenerate with `python3 crates/fgit-statistics/tests/oracle/generate.py`.
/// Regenerating is for extending the sample, never for absorbing a
/// disagreement.
const ORACLE: [(u32, u32, u32, u32, u32); 500] = [
    (86, 16, 150, 112, 0),
    (237, 75, 182, 214, 0),
    (95, 209, 25, 256, 0),
    (15, 116, 81, 118, 999_999),
    (161, 3, 93, 295, 0),
    (61, 210, 218, 278, 999_999),
    (105, 275, 183, 247, 999_995),
    (210, 263, 43, 216, 0),
    (208, 224, 204, 173, 954_970),
    (169, 216, 6, 289, 0),
    (179, 157, 86, 178, 0),
    (51, 113, 80, 207, 236_586),
    (269, 272, 287, 156, 999_999),
    (143, 285, 277, 177, 999_999),
    (43, 176, 217, 177, 999_999),
    (43, 199, 237, 26, 999_999),
    (253, 204, 33, 198, 0),
    (71, 296, 265, 77, 999_999),
    (162, 272, 279, 79, 999_999),
    (123, 238, 44, 141, 5_935),
    (267, 115, 166, 134, 43),
    (208, 140, 98, 270, 0),
    (140, 292, 191, 159, 999_999),
    (229, 141, 97, 75, 112_814),
    (222, 89, 115, 43, 629_726),
    (191, 72, 218, 214, 0),
    (51, 125, 236, 204, 999_999),
    (299, 222, 187, 243, 9),
    (217, 109, 5, 30, 0),
    (246, 103, 58, 11, 993_282),
    (293, 133, 47, 241, 0),
    (274, 76, 227, 11, 999_999),
    (193, 194, 299, 279, 714_528),
    (34, 90, 37, 248, 297),
    (237, 76, 156, 163, 0),
    (142, 88, 190, 33, 999_999),
    (29, 272, 125, 212, 999_999),
    (141, 200, 211, 282, 662_347),
    (248, 243, 116, 270, 0),
    (179, 204, 89, 50, 999_787),
    (216, 283, 84, 46, 999_993),
    (143, 55, 122, 128, 0),
    (55, 116, 74, 68, 999_831),
    (27, 253, 299, 51, 999_999),
    (214, 129, 114, 264, 0),
    (115, 299, 31, 2, 999_999),
    (285, 74, 41, 107, 0),
    (231, 144, 136, 132, 3_045),
    (139, 270, 98, 186, 555_470),
    (48, 252, 11, 70, 276_382),
    (55, 54, 92, 20, 999_999),
    (120, 168, 159, 135, 998_677),
    (132, 182, 130, 247, 20_723),
    (93, 163, 220, 267, 990_259),
    (122, 165, 29, 8, 999_988),
    (278, 14, 222, 223, 0),
    (74, 254, 12, 4, 999_993),
    (85, 44, 224, 162, 54_795),
    (278, 257, 53, 7, 999_999),
    (111, 146, 272, 58, 999_999),
    (106, 120, 70, 97, 161_829),
    (97, 245, 15, 167, 0),
    (193, 133, 176, 136, 237_359),
    (8, 161, 86, 220, 999_999),
    (179, 104, 7, 106, 0),
    (237, 100, 81, 228, 0),
    (168, 136, 94, 268, 0),
    (6, 112, 180, 201, 999_999),
    (265, 81, 46, 57, 0),
    (219, 294, 295, 21, 999_999),
    (81, 206, 84, 267, 109_415),
    (109, 112, 168, 47, 999_999),
    (262, 231, 199, 20, 999_999),
    (96, 103, 147, 32, 999_999),
    (87, 221, 2, 79, 0),
    (272, 34, 101, 282, 0),
    (260, 105, 69, 19, 921_435),
    (123, 152, 216, 281, 367_615),
    (271, 132, 275, 145, 295_238),
    (2, 293, 19, 155, 999_999),
    (166, 19, 108, 210, 0),
    (87, 70, 107, 8, 999_999),
    (104, 132, 145, 263, 16_341),
    (118, 18, 50, 132, 0),
    (114, 37, 271, 126, 45_156),
    (190, 117, 190, 79, 986_804),
    (9, 147, 41, 166, 999_976),
    (61, 53, 181, 121, 881_048),
    (91, 92, 263, 299, 245_418),
    (96, 20, 264, 229, 0),
    (203, 181, 43, 79, 306),
    (29, 125, 148, 47, 999_999),
    (289, 44, 41, 164, 0),
    (296, 86, 121, 106, 0),
    (198, 185, 104, 89, 690_961),
    (229, 64, 95, 25, 598_484),
    (126, 200, 224, 238, 996_992),
    (201, 172, 173, 27, 999_999),
    (196, 297, 48, 93, 105_852),
    (283, 179, 187, 297, 0),
    (132, 30, 68, 162, 0),
    (21, 5, 211, 159, 5_276),
    (165, 99, 191, 40, 999_999),
    (22, 215, 243, 179, 999_999),
    (195, 41, 78, 249, 0),
    (7, 178, 14, 90, 998_596),
    (288, 242, 273, 261, 146_489),
    (82, 54, 223, 281, 422),
    (111, 261, 295, 296, 999_999),
    (20, 55, 124, 146, 998_959),
    (266, 3, 283, 170, 0),
    (10, 228, 252, 267, 999_999),
    (258, 53, 220, 293, 0),
    (74, 47, 296, 123, 974_185),
    (24, 225, 87, 239, 999_999),
    (129, 104, 211, 102, 997_959),
    (139, 253, 235, 122, 999_999),
    (167, 222, 228, 108, 999_999),
    (292, 269, 171, 4, 999_999),
    (234, 257, 63, 163, 0),
    (170, 247, 74, 6, 999_999),
    (67, 44, 164, 254, 33),
    (236, 93, 58, 260, 0),
    (58, 186, 3, 134, 0),
    (40, 115, 145, 283, 970_651),
    (283, 156, 207, 76, 993_105),
    (136, 278, 279, 1, 999_999),
    (10, 154, 28, 212, 975_662),
    (67, 273, 33, 190, 64_247),
    (272, 231, 249, 71, 999_999),
    (19, 106, 77, 300, 911_223),
    (94, 92, 115, 289, 0),
    (143, 297, 244, 173, 999_999),
    (26, 263, 231, 277, 999_999),
    (101, 231, 138, 189, 999_196),
    (127, 11, 177, 276, 0),
    (62, 163, 4, 251, 0),
    (267, 14, 134, 298, 0),
    (272, 270, 13, 270, 0),
    (71, 78, 56, 252, 0),
    (288, 188, 190, 274, 0),
    (177, 155, 188, 119, 978_689),
    (75, 49, 128, 234, 0),
    (269, 219, 234, 214, 187_582),
    (117, 149, 45, 202, 0),
    (97, 95, 2, 225, 0),
    (117, 253, 198, 241, 999_958),
    (85, 258, 34, 41, 999_719),
    (16, 126, 23, 143, 756_929),
    (103, 220, 142, 17, 999_999),
    (259, 250, 59, 270, 0),
    (6, 245, 31, 31, 999_999),
    (91, 12, 6, 290, 0),
    (136, 163, 211, 141, 999_889),
    (104, 244, 161, 151, 999_999),
    (261, 11, 98, 26, 0),
    (225, 4, 258, 126, 0),
    (138, 244, 27, 266, 0),
    (285, 263, 181, 97, 999_850),
    (275, 211, 40, 4, 999_999),
    (78, 282, 174, 147, 999_999),
    (138, 145, 218, 242, 358_120),
    (164, 293, 61, 247, 0),
    (62, 26, 205, 168, 3_356),
    (58, 147, 186, 285, 997_675),
    (275, 142, 263, 133, 556_166),
    (258, 149, 187, 263, 0),
    (159, 188, 225, 128, 999_999),
    (161, 82, 54, 182, 0),
    (215, 204, 75, 41, 995_109),
    (185, 242, 93, 40, 999_999),
    (287, 76, 91, 262, 0),
    (294, 190, 46, 234, 0),
    (28, 130, 212, 80, 999_999),
    (58, 152, 59, 27, 999_999),
    (102, 159, 296, 172, 999_999),
    (105, 230, 60, 119, 690_316),
    (105, 182, 217, 238, 998_602),
    (234, 134, 47, 170, 0),
    (3, 267, 67, 118, 999_999),
    (295, 7, 273, 84, 0),
    (56, 215, 127, 218, 999_994),
    (125, 261, 294, 199, 999_999),
    (217, 108, 175, 297, 0),
    (88, 275, 300, 50, 999_999),
    (45, 204, 192, 193, 999_999),
    (265, 134, 266, 162, 99_968),
    (222, 131, 103, 179, 0),
    (6, 247, 49, 237, 999_999),
    (107, 5, 207, 69, 0),
    (179, 205, 36, 176, 0),
    (197, 282, 92, 74, 999_287),
    (215, 183, 127, 82, 945_329),
    (21, 166, 118, 187, 999_999),
    (34, 197, 1, 114, 0),
    (153, 188, 206, 292, 157_073),
    (203, 149, 283, 219, 352_674),
    (34, 90, 201, 98, 999_999),
    (228, 207, 283, 182, 994_760),
    (82, 147, 171, 225, 965_746),
    (104, 292, 158, 114, 999_999),
    (111, 171, 51, 219, 0),
    (174, 55, 278, 59, 970_116),
    (16, 22, 258, 80, 999_988),
    (39, 87, 202, 215, 999_785),
    (68, 68, 216, 105, 999_730),
    (208, 91, 151, 289, 0),
    (282, 75, 97, 190, 0),
    (276, 198, 43, 135, 0),
    (167, 156, 115, 223, 1),
    (210, 16, 148, 128, 0),
    (152, 101, 200, 115, 797_398),
    (87, 65, 183, 120, 740_141),
    (78, 259, 222, 247, 999_999),
    (9, 238, 204, 20, 999_999),
    (51, 154, 300, 15, 999_999),
    (41, 133, 107, 126, 999_998),
    (76, 72, 93, 214, 7),
    (266, 186, 21, 100, 0),
    (112, 277, 288, 260, 999_999),
    (150, 101, 263, 245, 18_362),
    (154, 19, 99, 124, 0),
    (28, 51, 188, 27, 999_999),
    (222, 6, 13, 271, 0),
    (177, 272, 97, 198, 34_355),
    (208, 124, 74, 110, 0),
    (285, 183, 196, 131, 393_376),
    (198, 150, 100, 112, 12_528),
    (141, 284, 228, 28, 999_999),
    (218, 55, 39, 49, 0),
    (223, 289, 111, 136, 639_936),
    (207, 104, 208, 223, 0),
    (206, 198, 66, 294, 0),
    (93, 208, 32, 84, 247_751),
    (168, 282, 201, 289, 876_672),
    (252, 180, 103, 114, 4_341),
    (282, 134, 217, 77, 959_363),
    (98, 75, 73, 168, 0),
    (98, 202, 39, 11, 999_999),
    (172, 292, 21, 133, 0),
    (266, 219, 103, 22, 999_999),
    (253, 164, 85, 66, 175_182),
    (114, 81, 226, 216, 42_951),
    (170, 247, 202, 180, 999_704),
    (287, 177, 238, 196, 16_415),
    (27, 53, 147, 169, 981_758),
    (114, 96, 68, 159, 0),
    (241, 64, 194, 110, 14),
    (191, 194, 6, 247, 0),
    (276, 30, 25, 246, 0),
    (121, 84, 136, 45, 999_640),
    (36, 287, 297, 13, 999_999),
    (30, 5, 165, 216, 0),
    (74, 157, 128, 191, 974_745),
    (14, 81, 245, 86, 999_999),
    (166, 233, 299, 126, 999_999),
    (135, 87, 190, 9, 999_999),
    (20, 211, 43, 190, 999_133),
    (26, 141, 183, 260, 999_999),
    (161, 214, 86, 169, 9_681),
    (74, 31, 269, 128, 289_743),
    (75, 17, 36, 78, 0),
    (187, 38, 241, 300, 0),
    (61, 178, 73, 14, 999_999),
    (65, 286, 165, 69, 999_999),
    (154, 56, 28, 29, 342),
    (281, 94, 290, 50, 999_756),
    (287, 270, 248, 57, 999_999),
    (288, 54, 159, 162, 0),
    (54, 211, 203, 57, 999_999),
    (152, 35, 264, 108, 3_400),
    (200, 24, 80, 114, 0),
    (158, 282, 243, 53, 999_999),
    (290, 1, 58, 2, 28_175),
    (18, 17, 125, 127, 419_054),
    (94, 173, 81, 39, 999_999),
    (259, 86, 148, 235, 0),
    (42, 243, 41, 252, 399_259),
    (192, 178, 84, 225, 0),
    (144, 139, 185, 48, 999_999),
    (52, 191, 201, 119, 999_999),
    (174, 49, 143, 42, 431_410),
    (161, 232, 89, 113, 764_667),
    (120, 32, 140, 89, 93),
    (237, 39, 54, 205, 0),
    (195, 5, 106, 105, 0),
    (189, 214, 290, 117, 999_999),
    (219, 294, 67, 220, 0),
    (48, 82, 29, 170, 1),
    (162, 191, 163, 49, 999_999),
    (58, 5, 108, 299, 0),
    (112, 88, 124, 245, 0),
    (222, 196, 107, 289, 0),
    (1, 225, 154, 81, 999_999),
    (260, 220, 237, 13, 999_999),
    (9, 269, 167, 297, 999_999),
    (147, 41, 206, 264, 0),
    (202, 104, 168, 39, 999_936),
    (137, 45, 258, 112, 83_534),
    (51, 100, 252, 256, 999_739),
    (2, 257, 122, 106, 999_999),
    (225, 173, 296, 80, 999_999),
    (288, 81, 221, 296, 0),
    (254, 293, 282, 25, 999_999),
    (259, 81, 226, 54, 915_315),
    (81, 25, 68, 194, 0),
    (178, 126, 203, 272, 7),
    (293, 231, 194, 16, 999_999),
    (134, 97, 222, 72, 999_989),
    (274, 126, 268, 183, 2_907),
    (266, 57, 216, 173, 0),
    (252, 242, 209, 229, 157_360),
    (155, 195, 150, 119, 997_731),
    (293, 257, 53, 172, 0),
    (180, 48, 277, 61, 810_775),
    (198, 58, 54, 288, 0),
    (69, 44, 185, 197, 8_702),
    (248, 73, 199, 295, 0),
    (61, 136, 65, 284, 586),
    (270, 293, 102, 31, 999_999),
    (172, 127, 138, 293, 0),
    (202, 234, 193, 248, 222_281),
    (2, 150, 217, 88, 999_999),
    (37, 22, 201, 35, 999_878),
    (37, 283, 99, 102, 999_999),
    (224, 219, 167, 37, 999_999),
    (243, 143, 29, 69, 0),
    (145, 159, 232, 159, 998_892),
    (182, 188, 126, 137, 375_098),
    (215, 139, 94, 273, 0),
    (265, 230, 152, 263, 0),
    (143, 265, 37, 279, 0),
    (161, 248, 133, 296, 5_550),
    (71, 28, 100, 195, 0),
    (102, 154, 130, 89, 999_989),
    (227, 173, 62, 96, 90),
    (202, 79, 62, 278, 0),
    (234, 2, 129, 85, 0),
    (126, 45, 136, 60, 180_024),
    (33, 198, 174, 86, 999_999),
    (256, 18, 43, 208, 0),
    (91, 159, 274, 235, 999_997),
    (238, 69, 234, 180, 0),
    (122, 126, 107, 131, 174_346),
    (142, 177, 203, 11, 999_999),
    (279, 20, 59, 149, 0),
    (288, 17, 293, 182, 0),
    (88, 181, 264, 285, 999_987),
    (7, 92, 123, 142, 999_999),
    (93, 117, 286, 203, 999_726),
    (221, 132, 5, 36, 0),
    (11, 264, 279, 285, 999_999),
    (243, 150, 45, 85, 0),
    (134, 100, 1, 290, 0),
    (79, 121, 49, 201, 1),
    (235, 173, 87, 256, 0),
    (248, 24, 28, 281, 0),
    (43, 299, 95, 9, 999_999),
    (267, 274, 285, 140, 999_999),
    (57, 3, 80, 110, 0),
    (67, 154, 281, 197, 999_999),
    (239, 86, 92, 204, 0),
    (33, 212, 175, 132, 999_999),
    (195, 37, 46, 47, 0),
    (290, 117, 104, 175, 0),
    (4, 255, 277, 37, 999_999),
    (134, 91, 31, 131, 0),
    (126, 83, 55, 238, 0),
    (295, 298, 65, 211, 0),
    (258, 91, 76, 229, 0),
    (65, 286, 298, 16, 999_999),
    (15, 258, 102, 251, 999_999),
    (117, 204, 290, 10, 999_999),
    (206, 48, 29, 20, 756),
    (44, 5, 194, 264, 0),
    (150, 179, 49, 275, 0),
    (117, 7, 296, 26, 166_415),
    (274, 248, 214, 31, 999_999),
    (76, 298, 140, 13, 999_999),
    (219, 275, 40, 80, 13_086),
    (70, 197, 178, 40, 999_999),
    (24, 248, 168, 47, 999_999),
    (149, 44, 281, 180, 20),
    (128, 2, 200, 283, 0),
    (179, 106, 221, 171, 45_822),
    (118, 180, 281, 89, 999_999),
    (146, 222, 57, 255, 0),
    (251, 122, 243, 265, 0),
    (128, 13, 209, 248, 0),
    (183, 140, 35, 250, 0),
    (98, 286, 233, 76, 999_999),
    (261, 171, 24, 148, 0),
    (287, 159, 10, 97, 0),
    (181, 214, 119, 69, 999_964),
    (92, 293, 33, 84, 820_541),
    (203, 198, 99, 206, 0),
    (186, 190, 13, 178, 0),
    (174, 30, 71, 280, 0),
    (2, 296, 111, 202, 999_999),
    (276, 214, 40, 149, 0),
    (35, 166, 22, 126, 256_812),
    (162, 174, 214, 158, 993_503),
    (100, 47, 129, 224, 0),
    (199, 243, 146, 150, 874_641),
    (228, 285, 260, 29, 999_999),
    (195, 45, 174, 4, 999_999),
    (128, 94, 188, 58, 999_993),
    (45, 166, 124, 7, 999_999),
    (58, 71, 180, 297, 69_541),
    (115, 23, 254, 115, 328),
    (139, 279, 173, 44, 999_999),
    (102, 202, 27, 133, 40),
    (87, 38, 273, 179, 27_612),
    (106, 179, 38, 271, 0),
    (6, 74, 284, 66, 999_999),
    (261, 222, 240, 137, 997_816),
    (276, 297, 232, 70, 999_999),
    (137, 27, 226, 234, 0),
    (283, 36, 291, 286, 0),
    (128, 150, 263, 191, 999_134),
    (76, 5, 201, 163, 0),
    (120, 161, 267, 111, 999_999),
    (110, 92, 168, 34, 999_999),
    (289, 19, 274, 147, 0),
    (126, 237, 149, 296, 357_511),
    (25, 239, 93, 80, 999_999),
    (127, 207, 264, 153, 999_999),
    (40, 207, 253, 177, 999_999),
    (202, 268, 104, 124, 744_219),
    (19, 146, 240, 121, 999_999),
    (113, 238, 62, 20, 999_999),
    (215, 23, 131, 253, 0),
    (256, 55, 119, 209, 0),
    (227, 80, 91, 239, 0),
    (22, 94, 99, 29, 999_999),
    (165, 185, 80, 119, 56_961),
    (45, 120, 196, 88, 999_999),
    (97, 52, 226, 300, 0),
    (48, 88, 52, 20, 999_999),
    (227, 103, 45, 72, 0),
    (80, 44, 140, 211, 0),
    (267, 217, 297, 118, 999_999),
    (74, 14, 173, 252, 0),
    (225, 41, 111, 99, 0),
    (83, 113, 261, 267, 955_784),
    (226, 78, 176, 167, 0),
    (270, 148, 52, 208, 0),
    (92, 87, 142, 161, 167_656),
    (169, 246, 203, 204, 995_867),
    (242, 90, 157, 187, 0),
    (105, 159, 181, 268, 557_555),
    (133, 71, 174, 290, 0),
    (151, 244, 164, 105, 999_999),
    (285, 292, 23, 206, 0),
    (29, 300, 47, 24, 999_999),
    (34, 211, 162, 130, 999_999),
    (293, 52, 258, 198, 0),
    (89, 47, 164, 249, 0),
    (7, 22, 211, 211, 997_545),
    (180, 168, 197, 72, 999_999),
    (299, 194, 193, 148, 121_337),
    (53, 51, 244, 47, 999_999),
    (50, 270, 137, 21, 999_999),
    (222, 269, 89, 116, 330_439),
    (95, 174, 282, 71, 999_999),
    (105, 162, 227, 27, 999_999),
    (52, 126, 260, 197, 999_999),
    (15, 67, 83, 285, 816_524),
    (123, 178, 208, 169, 999_898),
    (206, 290, 44, 257, 0),
    (248, 210, 72, 289, 0),
    (120, 175, 179, 55, 999_999),
    (3, 287, 278, 112, 999_999),
    (13, 224, 14, 162, 840_296),
    (61, 121, 22, 298, 0),
    (199, 15, 232, 100, 0),
    (228, 241, 89, 28, 999_999),
    (259, 292, 243, 239, 863_191),
    (170, 244, 172, 149, 999_639),
    (298, 271, 80, 173, 0),
    (262, 281, 24, 175, 0),
    (257, 50, 23, 98, 0),
    (99, 53, 78, 32, 840_983),
    (175, 85, 155, 268, 0),
    (232, 10, 280, 142, 0),
    (70, 75, 256, 132, 999_894),
    (275, 98, 133, 223, 0),
    (239, 282, 34, 23, 976_626),
    (90, 172, 258, 165, 999_999),
    (141, 296, 61, 113, 742_983),
    (166, 36, 77, 111, 0),
    (203, 215, 122, 91, 981_142),
    (279, 68, 189, 90, 145),
    (125, 210, 100, 300, 153),
    (72, 217, 46, 219, 14_367),
    (95, 181, 136, 10, 999_999),
    (223, 274, 278, 136, 999_999),
    (12, 1, 293, 223, 1_236),
    (2, 93, 102, 224, 999_999),
    (193, 20, 98, 75, 0),
];

#[test]
fn every_answer_equals_the_exact_value_and_none_exceeds_it() {
    let mut answered = 0;
    let mut non_trivial = 0;
    let mut refusals = 0;

    for (alpha_a, beta_a, alpha_b, beta_b, exact) in ORACLE {
        let name = format!("Beta({alpha_a},{beta_a}) vs Beta({alpha_b},{beta_b})");
        match probability_b_exceeds_a_ppm(posterior(alpha_a, beta_a), posterior(alpha_b, beta_b)) {
            Ok(got) => {
                answered += 1;
                if exact > 0 {
                    non_trivial += 1;
                }
                assert!(
                    got <= exact,
                    "{name} returned {got} ppm, ABOVE the exact {exact} ppm. Overstating \
                     P(theta_b > theta_a) overstates a candidate policy's advantage over its \
                     fallback, which is the one direction this error must never take"
                );
                assert_eq!(
                    got, exact,
                    "{name} returned {got} ppm against an exact {exact} ppm. The flooring error \
                     is bounded by ~4e-27, twenty-one orders below one ppm, so any disagreement \
                     means something other than flooring is happening"
                );
            }
            Err(ExpectedLossRefusal::PeakTermUnrepresentable { .. }) => {
                refusals += 1;
                assert_eq!(
                    exact, 0,
                    "{name} refused, but its exact value is {exact} ppm. The refusal region is \
                     only defensible while it contains nothing a caller could have used; a \
                     representable answer lost to it is a regression, not a limit"
                );
            }
            Err(refusal) => panic!("{name} produced an unexpected refusal: {refusal:?}"),
        }
    }

    assert_eq!(
        answered, EXPECTED_ANSWERED,
        "the representable region changed size; that is a material change to what this module \
         can answer and must be re-measured, not absorbed"
    );
    assert_eq!(
        non_trivial, EXPECTED_NON_TRIVIAL,
        "the count of sets with a non-zero exact value changed. Sets whose exact value is zero \
         are matched by any implementation that returns zero -- including NEG-025's -- so this \
         count is how much discrimination the sweep actually carries"
    );
    assert_eq!(
        refusals, EXPECTED_REFUSALS,
        "the unrepresentable region changed size and must be re-measured"
    );
}

#[test]
fn the_sweep_rejects_a_neg_025_style_implementation() {
    // THE PRESENCE CASE FOR THE SWEEP ITSELF.
    //
    // A conformance sweep that cannot fail is not evidence, and counting rows
    // in the table would not show that it can -- the table is an input to the
    // check, not the check. So this runs the sweep's own acceptance predicate
    // against the implementation NEG-025 actually recorded: one that returns
    // `Ok(0)` for everything, because T(0) truncated to nothing and every later
    // term was `0 * ratio`.
    //
    // If the predicate accepted that, every assertion in this file would be
    // decoration.
    fn neg_025_style(_alpha_a: u32, _beta_a: u32, _alpha_b: u32, _beta_b: u32) -> u32 {
        0
    }

    let rejections = ORACLE
        .iter()
        .filter(|(alpha_a, beta_a, alpha_b, beta_b, exact)| {
            let got = neg_025_style(*alpha_a, *beta_a, *alpha_b, *beta_b);
            // The sweep accepts a returned value when it is at or below the
            // exact one AND equal to it, which together is equality. This is
            // that rule negated, so the two cannot drift apart.
            got != *exact
        })
        .count();

    assert_eq!(
        rejections, EXPECTED_NON_TRIVIAL as usize,
        "the sweep must reject NEG-025's zero-returning implementation on every set whose exact \
         value is non-zero; it would reject {rejections}"
    );
    assert!(
        rejections > 0,
        "if the sweep cannot reject the implementation this module was written to replace, it is \
         not measuring anything"
    );

    // And the region NEG-025 got most spectacularly wrong is still in the
    // sample: near-certain advantages reported as "never wins".
    assert!(
        ORACLE.iter().any(|(_, _, _, _, exact)| *exact > 900_000),
        "the sweep must retain near-certain advantages, where NEG-025 returned 0 ppm"
    );
}
