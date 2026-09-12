import pathlib, hashlib, sys
root=pathlib.Path(sys.argv[1]).resolve()
payload=pathlib.Path(__file__).resolve().parent/'shallow-payload'
phase=sys.argv[2]
def blob(data): return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
def guard(path,expected):
    p=root/path
    assert p.is_file() and not p.is_symlink(),path
    assert blob(p.read_bytes())==expected,(path,blob(p.read_bytes()),expected)
def edit(path,before,after,count=1):
    p=root/path
    text=p.read_text()
    assert text.count(before)==count,(path,before[:120],text.count(before),count)
    p.write_text(text.replace(before,after))
def new(path,expected):
    data=(payload/path).read_bytes()
    assert hashlib.sha256(data).hexdigest()==expected,(path,hashlib.sha256(data).hexdigest())
    p=root/path
    assert not p.exists(),path
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_bytes(data)
w='crates/fgit-wire/src/lib.rs'
n='crates/fgit-node/src/lib.rs'
v='crates/fgit-node/src/upload_visibility.rs'
if phase=='wire':
    guard(w,'217ee35b8870a97eb7b657d3497d058c67ccf460')
    edit(w,'mod filter_syntax;\n','mod filter_syntax;\nmod shallow_response;\n')
    edit(w,'    fn is_common(&self, oid: AnyGitOid) -> bool;\n','''    fn is_common(&self, oid: AnyGitOid) -> bool;
    /// Whether this immutable repository view can resolve actual shallow updates.
    /// A transport must not advertise shallow serving from parser support alone.
    fn supports_shallow(&self) -> bool {
        false
    }
    /// Resolve shallow changes at the same authorized basis as wants and ACKs.
    ///
    /// Called before have negotiation in v0/v1 and before the shallow-info
    /// section in v2 by machines using `with_shallow_updates`. The provider
    /// owns bounded graph work and cancellation; the wire machine validates
    /// identity, authorization, ordering, counts and unshallow membership.
    fn shallow_update(&self, _request: &PackRequest) -> Result<closure::ShallowUpdate, WireError> {
        Err(WireError::PackSourceRefused)
    }
''')
    edit(w,'    saw_want_capabilities: bool,\n}','    saw_want_capabilities: bool,\n    automatic_shallow_updates: bool,\n    shallow_negotiated: bool,\n}')
    edit(w,'            saw_want_capabilities: false,\n        })','            saw_want_capabilities: false,\n            automatic_shallow_updates: false,\n            shallow_negotiated: false,\n        })')
    edit(w,'impl LegacyUploadPack {\n','''impl LegacyUploadPack {
    /// Ask the repository to resolve and frame shallow changes before haves.
    ///
    /// Without this opt-in the machine retains its low-level parser contract:
    /// the enclosing adapter is responsible for the shallow exchange itself.
    #[must_use]
    pub fn with_shallow_updates(mut self) -> Self {
        self.automatic_shallow_updates = true;
        self
    }

''')
    edit(w,'''                self.state = LegacyState::AwaitHave;
                let output = match self.ack_mode {
                    AckMode::MultiAck | AckMode::MultiAckDetailed => vec![line_packet(b"NAK\\n")],
                    AckMode::None => Vec::new(),
                };
                Ok(Transition {
                    output,
                    events: Vec::new(),
                })
''','''                let request = self.pack_request();
                let shallow_negotiated = self.automatic_shallow_updates
                    && shallow_response::changes_boundary(&request);
                let mut output = if self.automatic_shallow_updates
                    && shallow_response::has_controls(&request)
                {
                    shallow_response::response(repository, &request, &self.limits)?
                } else {
                    Vec::new()
                };
                if !shallow_negotiated && self.ack_mode != AckMode::None {
                    output.push(line_packet(b"NAK\\n"));
                }
                if self.automatic_shallow_updates && shallow_response::has_controls(&request) {
                    let _ = encode_packets(&output, &self.limits)?;
                }
                self.shallow_negotiated = shallow_negotiated;
                self.state = LegacyState::AwaitHave;
                Ok(Transition { output, events: Vec::new() })
''')
    edit(w,'''            None => match self.ack_mode {
                AckMode::None => vec![line_packet(b"NAK\\n")],
                AckMode::MultiAck | AckMode::MultiAckDetailed => Vec::new(),
            },
''','''            None => {
                if self.shallow_negotiated || self.ack_mode == AckMode::None {
                    vec![line_packet(b"NAK\\n")]
                } else {
                    Vec::new()
                }
            }
''')
    edit(w,'    ls_refs: LsRefsOptions,\n}','    ls_refs: LsRefsOptions,\n    automatic_shallow_updates: bool,\n}')
    edit(w,'            ls_refs: LsRefsOptions::default(),\n        })','            ls_refs: LsRefsOptions::default(),\n            automatic_shallow_updates: false,\n        })')
    edit(w,'impl V2UploadPack {\n','''impl V2UploadPack {
    /// Resolve and frame shallow-info before the packfile section.
    /// The default remains a parser-only handoff for existing low-level users.
    #[must_use]
    pub fn with_shallow_updates(mut self) -> Self {
        self.automatic_shallow_updates = true;
        self
    }

''')
    edit(w,'''        output.push(line_packet(b"packfile\\n"));
        self.state = V2State::Complete;
        Ok(Transition {
            output,
            events: vec![WireEvent::PackRequested(PackRequest {
                version: UploadPackVersion::V2,
                wants: self.wants.clone(),
                haves: self.haves.clone(),
                shallows: self.shallows.clone(),
                deepen: self.deepen,
                deepen_since: self.deepen_since,
                deepen_not: self.deepen_not.clone(),
                filter: self.filter.clone(),
                options: self.options.with(PackOptions::SIDE_BAND_64K.0),
            })],
        })
''','''        let request = PackRequest {
            version: UploadPackVersion::V2,
            wants: self.wants.clone(),
            haves: self.haves.clone(),
            shallows: self.shallows.clone(),
            deepen: self.deepen,
            deepen_since: self.deepen_since,
            deepen_not: self.deepen_not.clone(),
            filter: self.filter.clone(),
            options: self.options.with(PackOptions::SIDE_BAND_64K.0),
        };
        if self.automatic_shallow_updates && shallow_response::has_controls(&request) {
            output.extend(shallow_response::response(repository, &request, &self.limits)?);
        }
        output.push(line_packet(b"packfile\\n"));
        if self.automatic_shallow_updates && shallow_response::has_controls(&request) {
            let _ = encode_packets(&output, &self.limits)?;
        }
        self.state = V2State::Complete;
        Ok(Transition { output, events: vec![WireEvent::PackRequested(request)] })
''')
    new('crates/fgit-wire/src/shallow_response.rs','2d809e6c00c6c3e192198e901b15f55877a2155ea44ff315ccae7983a07c449c')
    new('crates/fgit-wire/tests/shallow_response.rs','334cc9e3cf50142329071d3f33e7aff576c1927fd0c1ed2ad9ded931fb1df5d7')
elif phase=='node':
    for path,identity in [(n,'f29e399cf51b37d9ff5d91cecb837bf212eb7b91'),(v,'6fbfa927c6faafc2e472de8a0313b52337529794'),('crates/fgit-node/src/upload_visibility/partial_clone.rs','4bdfbbc266da7e883bc38ae1b3a31b7c7b9f8ad9'),('crates/fgit-node/src/upload_visibility/tests.rs','bfc57b02c905a11630bf2ce872d1910b50521640'),('crates/fgit-node/src/upload_visibility/tests/partial_clone.rs','a591ef617389090e28f580c15aa55f6074f33784'),('crates/fgit-node/src/upload_visibility/tags.rs','b894cd58fb39f0037b5fa08e7858510df3fc1030')]: guard(path,identity)
    edit(n,'allow-reachable-sha1-in-want filter include-tag side-band-64k agent=frankengit-node','allow-reachable-sha1-in-want shallow filter include-tag side-band-64k agent=frankengit-node',10)
    edit(n,'    tag_peels: BTreeMap<GitOid, GitOid>,\n}','    tag_peels: BTreeMap<GitOid, GitOid>,\n    shallow_proof: Option<upload_visibility::shallow::ShallowProof>,\n}')
    edit(n,'            tag_peels: BTreeMap::new(),\n        })','            tag_peels: BTreeMap::new(),\n            shallow_proof: None,\n        })')
    edit(n,'        self.closure_objects = objects;\n        self\n','        self.closure_objects = objects;\n        self.shallow_proof = None;\n        self\n')
    edit(n,'''    fn is_common(&self, oid: AnyGitOid) -> bool {
        self.contains_want(oid)
    }
''','''    fn is_common(&self, oid: AnyGitOid) -> bool {
        self.contains_want(oid)
    }

    fn supports_shallow(&self) -> bool {
        self.shallow_proof.is_some()
    }

    fn shallow_update(&self, request: &PackRequest) -> Result<fgit_wire::closure::ShallowUpdate, WireError> {
        self.shallow_proof.as_ref().ok_or(WireError::PackSourceRefused)?.update(request)
    }
''')
    edit(n,'    let mut machine = LegacyUploadPack::new(upload_pack_version, capabilities, limits.clone())\n','    let mut machine = LegacyUploadPack::new(upload_pack_version, capabilities, limits.clone())\n        .map(LegacyUploadPack::with_shallow_updates)\n')
    edit(n,'        V2UploadPack::new(server_capabilities.clone(), limits.clone())\n','        V2UploadPack::new(server_capabilities.clone(), limits.clone())\n            .map(V2UploadPack::with_shallow_updates)\n')
    edit(n,'        Packet::Data(if supports_filter { b"fetch=filter\\n".to_vec() } else { b"fetch\\n".to_vec() }),\n','''        Packet::Data(match (supports_filter, repository.supports_shallow()) {
            (true, true) => b"fetch=shallow filter\\n".to_vec(),
            (true, false) => b"fetch=filter\\n".to_vec(),
            (false, true) => b"fetch=shallow\\n".to_vec(),
            (false, false) => b"fetch\\n".to_vec(),
        }),
''')
    edit(n,'''        let mut ids = selected_pack_ids(
            &source,
            disclosure_closure,
            client_wants,
            client_haves,
            &limits,
        )?;
''','''        let mut ids = if fetch.is_some_and(|(_, request)| upload_visibility::shallow::requested(request)) {
            // A shallow have proves only history above the client's boundary.
            // The visible scope below computes both clipped closures together.
            Vec::new()
        } else {
            selected_pack_ids(&source, disclosure_closure, client_wants, client_haves, &limits)?
        };
''')
    edit(v,'mod partial_clone;\n','mod partial_clone;\npub(super) mod shallow;\n')
    edit(v,'    objects: BTreeMap<GitOid, partial_clone::FilterObject>,\n}\n\nimpl VisibleUploadPack','    objects: Arc<BTreeMap<GitOid, partial_clone::FilterObject>>,\n}\n\nimpl VisibleUploadPack')
    edit(v,'        partial_clone::apply_selection(&self.objects, ids, request, limits, live)\n','''        if !shallow::requested(request) {
            return partial_clone::apply_selection(&self.objects, ids, request, limits, live);
        }
        let mut selected = shallow::select(&self.objects, request, limits, live)?;
        // History has already been clipped and validated. Reuse the existing
        // partial-clone engine for omission predicates and explicit lazy roots.
        let mut filtered = request.clone();
        filtered.shallows.clear();
        filtered.deepen = None;
        filtered.deepen_since = None;
        filtered.deepen_not.clear();
        partial_clone::apply_selection(&self.objects, &mut selected, &filtered, limits, live)?;
        *ids = selected;
        Ok(())
''')
    edit(v,'        repository.tag_peels = tags.peels.clone();\n        Ok(VisibleUploadPack {\n','''        repository.tag_peels = tags.peels.clone();
        let objects = Arc::new(graph.objects);
        repository.shallow_proof = Some(shallow::ShallowProof::new(
            Arc::clone(&objects), self.selected_pack_limits.clone(), deadline.clone(),
        ));
        Ok(VisibleUploadPack {
''')
    edit(v,'            objects: graph.objects,\n','            objects,\n')
    edit('crates/fgit-node/src/upload_visibility/partial_clone.rs','pub(super) struct FilterObject {\n','#[derive(Debug)]\npub(super) struct FilterObject {\n')
    edit('crates/fgit-node/src/upload_visibility/tests.rs','use super::*;\nuse std::cell::RefCell;\n','use super::*;\nuse std::cell::RefCell;\nmod shallow_transport;\n')
    edit('crates/fgit-node/src/upload_visibility/tests/partial_clone.rs','''                let advertisement = if version == 2 {
                    b"fetch=filter\\n".as_slice()
                } else {
                    b"allow-reachable-sha1-in-want filter".as_slice()
                };
''','''                let advertisement = if version == 2 {
                    b"fetch=shallow filter\\n".as_slice()
                } else {
                    b"allow-reachable-sha1-in-want shallow filter".as_slice()
                };
''')
    # Recovered integration omission: the legacy expanded advertisement wrapper
    # must forward the same private graph provider, never invent its own view.
    edit('crates/fgit-node/src/upload_visibility/tags.rs','''    fn is_common(&self, oid: AnyGitOid) -> bool {
        self.source.is_common(oid)
    }
''','''    fn is_common(&self, oid: AnyGitOid) -> bool {
        self.source.is_common(oid)
    }
    fn supports_shallow(&self) -> bool {
        self.source.supports_shallow()
    }
    fn shallow_update(&self, request: &PackRequest) -> Result<fgit_wire::closure::ShallowUpdate, WireError> {
        self.source.shallow_update(request)
    }
''')
    new('crates/fgit-node/src/upload_visibility/shallow.rs','bfb6f8762b238e1c55b491fb4b04549213b5affd1fb49c73baf50abbd6b0ff15')
    new('crates/fgit-node/src/upload_visibility/shallow/tests.rs','624cd1f980b86b57864d8489a606655ea8e27dd1ba249181b7c4a551945bfdd8')
    new('crates/fgit-node/src/upload_visibility/tests/shallow_transport.rs','2a1910da9b05a0e0330bf5f9e0fa5641e01524b308e0bfab3785ec8899d4b6f9')
else: raise SystemExit('unknown phase')
print('APPLIED',phase,flush=True)
