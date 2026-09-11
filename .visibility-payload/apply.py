import hashlib, json, os, pathlib, subprocess

def run(*args):
    return subprocess.check_output(args).decode().strip()

def blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()

path = pathlib.Path('crates/fgit-node/src/lib.rs')
original = path.read_bytes()
assert blob(original) == '39513e0642b62d00e083360874666f5e9eb89269', 'main lib changed; refusing an unreviewed rebase'
s = original.decode()
def change(old, new):
    global s
    assert s.count(old) == 1, f'expected one exact source region: {old[:100]!r}'
    s = s.replace(old, new, 1)

change('mod verified_reads;\n', 'mod verified_reads;\nmod upload_visibility;\n')
change('        let head_target = snapshot.head_target.clone();', '''        // A hidden target must not survive as a protocol-v2 unborn symref.
        let head_target = snapshot.head_target.as_ref().filter(|target| !hides(target)).cloned();''')
change('    /// Attaches the authority-selected closure objects to resolve common haves.', '''    /// Attaches a caller-authorized disclosure closure for wants and common haves.
    ///
    /// This low-level builder does not grant permission. Production transport
    /// supplies only its private, exact-head visible-graph proof, never the
    /// cumulative admitted-history set or a physical object inventory.''')
change('pub enum NodePackMaterializationRefusal {\n', '''pub enum NodePackMaterializationRefusal {
    /// The exact-head visible native graph could not be proved completely.
    /// No partial permission, object identifier, or hidden ref is disclosed.
    DisclosureGraph(RefusalCode),
''')
start=s.index('impl Display for NodePackMaterializationRefusal {')
end=s.index('impl Error for NodePackMaterializationRefusal {',start)
piece=s[start:end]
assert piece.count('        match self {\n') == 1
s=s[:start]+piece.replace('        match self {\n', '''        match self {
            Self::DisclosureGraph(code) => write!(
                formatter, "visible upload-pack graph proof refused: {code:?}"
            ),
''',1)+s[end:]
start=s.index('impl Error for NodePackMaterializationRefusal {')
end=s.index('impl From<AdmissionMaterializationRefusal> for NodePackMaterializationRefusal {',start)
piece=s[start:end]
assert piece.count('            Self::RequestedWantOutsideClosure(_)') == 1
s=s[:start]+piece.replace('            Self::RequestedWantOutsideClosure(_)', '            Self::DisclosureGraph(_)\n            | Self::RequestedWantOutsideClosure(_)',1)+s[end:]
header='''    fn materialize_selected_pack(
        &self,
        materialized: &MaterializedAdmission,
        client_wants: Option<&[GitOid]>,
        client_haves: &[GitOid],
        write_profile: PackWriteProfile,
        database_context: &FsqliteCx,
        database_exhaustion: &Cell<Option<Exhaustion>>,
        session_is_live: Option<&dyn Fn() -> bool>,
        is_live: &mut impl FnMut() -> bool,
    ) -> Result<AuthoritySelectedPackPayload, NodePackMaterializationRefusal> {
'''
scoped=header.replace('fn materialize_selected_pack(', 'fn materialize_selected_pack_in_scope(').replace('        client_wants:', '        disclosure_closure: &PermittedObjectClosure,\n        client_wants:')
wrapper=header+'''        // Explicit local authority materialization retains the canonical
        // historical scope. Network callers must supply their disclosure proof.
        self.materialize_selected_pack_in_scope(
            materialized, materialized.selected_closure().closure(), client_wants,
            client_haves, write_profile, database_context, database_exhaustion,
            session_is_live, is_live,
        )
    }

'''
change(header, wrapper+scoped)
change('''        let ids = selected_pack_ids(
            &source,
            materialized.selected_closure().closure(),''','''        let ids = selected_pack_ids(
            &source,
            disclosure_closure,''')
change('''        let repository = AdmissionUploadPackRepository::from_snapshot(
            materialized.snapshot(),
            self.object_format,
            &limits,
        )
        .map(|repo| {
            repo.with_closure_objects(materialized.selected_closure().closure().objects().clone())
        })
        .map_err(|error| NodeGitDaemonServeRefusal::from(NodeAdmissionViewRefusal::from(error)))?;''','''        let disclosure = self.prepare_visible_upload_pack(
            &request, &materialized, &limits, &deadline,
        )?;
        let repository = disclosure.repository();''')
change('''            greeting,
            &repository,
            capabilities,''','''            greeting,
            repository,
            capabilities,''')
change('''                    self.materialize_selected_pack(
                        &materialized,
                        Some(&pack_request.wants),''','''                    self.materialize_selected_pack_in_scope(
                        &materialized,
                        disclosure.closure_for(&materialized).map_err(GitDaemonServeError::Pack)?,
                        Some(&pack_request.wants),''')
assert 'repo.with_closure_objects(materialized.selected_closure().closure().objects().clone())' not in s
path.write_text(s)
inputs = [
    ('visibility.rs', 'crates/fgit-node/src/upload_visibility.rs', '4525e577b479c852820f80b86f8a60a08f0347c8'),
    ('tests.rs', 'crates/fgit-node/src/upload_visibility/tests.rs', '0ce5b6018264b6351a65f8e12f42c526d3fbae01'),
]
for source, target, expected in inputs:
    data=subprocess.check_output(['git','show',os.environ['PAYLOAD_SHA']+':.visibility-payload/'+source])
    assert blob(data) == expected, 'payload mismatch: '+source
    dest=pathlib.Path(target)
    assert not dest.exists(), 'refusing to overwrite '+target
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
print('Guarded production patch applied', run('git','rev-parse','HEAD'), flush=True)
for raw in pathlib.Path('.beads/issues.jsonl').read_text().splitlines():
    item=json.loads(raw)
    text=(item.get('title','')+' '+item.get('description','')).lower()
    if item.get('id')=='frankengit-jkbo' or (item.get('status') in ['open','in_progress'] and ('hidden' in text and ('fetch' in text or 'upload-pack' in text))):
        print('RELATED BEAD', json.dumps({key:item.get(key) for key in ['id','title','status','assignee','priority']}), flush=True)
