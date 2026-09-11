import pathlib, hashlib
records = [('crates/fgit-node/src/treefs_workspace/commit_replay.rs', 'ee27c8498b68e6dfa95d647788401321214c8637', [('#[cfg(test)]\nmod tests;', '#[cfg(test)]\n#[path = "commit_replay/tests.rs"]\nmod tests;'), ('#[cfg(test)]\nmod resolution_tests;', '#[cfg(test)]\n#[path = "commit_replay/resolution_tests.rs"]\nmod resolution_tests;')]), ('crates/fgit-node/src/treefs_workspace/bundle_review.rs', '461182646a96f7168c6296dcd8016a2461851713', [('mod pack;', '#[path = "bundle_review/pack.rs"]\nmod pack;'), ('#[cfg(test)]\nmod tests;', '#[cfg(test)]\n#[path = "bundle_review/tests.rs"]\nmod tests;')]), ('crates/fgit-node/src/treefs_workspace/publication.rs', '6ee8f7ad7a17da81992b47a5fbcf47fd288577ba', [('mod bundle_review;', 'mod bundle_review;\npub(super) use bundle_review::BundleInspectionRefusal;')]), ('crates/fgit-node/src/treefs_workspace/reviews.rs', '713ca22d9be5e2c321ff4e47d57ab2daad89c31f', [('use super::super::bundle_review::BundleInspectionRefusal as E;', 'use super::super::publication::BundleInspectionRefusal as E;')])]
for rel, expected, changes in records:
    path=pathlib.Path(rel)
    data=path.read_bytes()
    assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==expected, 'original changed: '+rel
    text=data.decode()
    for old,new in changes:
        assert text.count(old)==1,(rel,old)
        text=text.replace(old,new,1)
    path.write_text(text)
    print('Restored native module integration:',rel)
