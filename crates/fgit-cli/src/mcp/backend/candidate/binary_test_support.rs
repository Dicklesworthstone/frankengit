//! Independent Git binary-patch fixtures: stored DEFLATE blocks, Adler-32 and
//! Git base85 are encoded here, never by the native decoder under test.
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::GitHashAlgorithm;

pub(in crate::mcp::backend) fn literal_member(bytes: &[u8]) -> String {
    const DIGITS: &[u8] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
    let size = u16::try_from(bytes.len()).unwrap();
    let mut compressed = vec![0x78, 1, 1];
    compressed.extend(size.to_le_bytes());
    compressed.extend((!size).to_le_bytes());
    compressed.extend(bytes);
    let (a, b) = bytes.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65521;
        (a, (b + a) % 65521)
    });
    compressed.extend(((b << 16) | a).to_be_bytes());
    let mut out = format!("literal {}\n", bytes.len()).into_bytes();
    for row in compressed.chunks(52) {
        let length = u8::try_from(row.len()).unwrap();
        out.push(if length <= 26 {
            b'A' + length - 1
        } else {
            b'a' + length - 27
        });
        for part in row.chunks(4) {
            let mut word = [0_u8; 4];
            word[..part.len()].copy_from_slice(part);
            let mut word = u32::from_be_bytes(word);
            let mut encoded = [0_u8; 5];
            for digit in encoded.iter_mut().rev() {
                *digit = DIGITS[(word % 85) as usize];
                word /= 85;
            }
            out.extend(encoded);
        }
        out.push(b'\n');
    }
    out.push(b'\n');
    String::from_utf8(out).unwrap()
}

pub(in crate::mcp::backend) fn rename_patch(
    format: GitHashAlgorithm,
    source: &str,
    destination: &str,
    before: &[u8],
    after: &[u8],
) -> String {
    let old = git_object_id(format, GitObjectKind::Blob, before);
    let new = git_object_id(format, GitObjectKind::Blob, after);
    format!(
        "diff --git a/{source} b/{destination}\nold mode 100644\nnew mode 100755\nsimilarity index 50%\nrename from {source}\nrename to {destination}\nindex {old}..{new}\nGIT binary patch\n{}{}",
        literal_member(after),
        literal_member(before),
    )
}
