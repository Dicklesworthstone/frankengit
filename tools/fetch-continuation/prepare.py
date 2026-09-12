import os, pathlib, subprocess, tempfile
ROOT=pathlib.Path.cwd();BASE='2b150673c1af220a2e02963de756be0816d903cf'
def git(*args,cwd=ROOT):return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-relative-product-') as td:
    work=pathlib.Path(td)/'source';git('worktree','add','--detach',str(work),BASE)
    changed=set()
    def edit(path,old,new,count=1):
        p=work/path;text=p.read_text();assert text.count(old)==count,(path,old[:100],text.count(old));p.write_text(text.replace(old,new));changed.add(path)
    def new(path,payload):
        p=work/path;assert not p.exists();p.parent.mkdir(parents=True,exist_ok=True)
        text=(ROOT/'tools/fetch-continuation'/payload).read_text()
        if payload=='relative-tests.rs':
            old='let absolute = request(tip.0,Some(1)';assert text.count(old)==1;text=text.replace(old,'let absolute = super::request(tip.0,Some(1)')
        p.write_text(text);changed.add(path)
    wire='crates/fgit-wire/src/lib.rs';response='crates/fgit-wire/src/shallow_response.rs'
    node='crates/fgit-node/src/lib.rs';visible='crates/fgit-node/src/upload_visibility.rs'
    shallow='crates/fgit-node/src/upload_visibility/shallow.rs';partial='crates/fgit-node/src/upload_visibility/partial_clone.rs'
    edit(wire,'    const SIDEBAND_ALL: u8 = 1 << 5;','    const SIDEBAND_ALL: u8 = 1 << 5;\n    const DEEPEN_RELATIVE: u8 = 1 << 6;')
    edit(wire,'''    pub const fn include_tag(self) -> bool {
        self.contains(Self::INCLUDE_TAG)
    }
}''','''    pub const fn include_tag(self) -> bool {
        self.contains(Self::INCLUDE_TAG)
    }

    /// Whether depth is an increment relative to existing shallow history.
    #[must_use]
    pub const fn deepen_relative(self) -> bool {
        self.contains(Self::DEEPEN_RELATIVE)
    }

    /// Select relative history semantics without changing pack-format flags.
    #[must_use]
    pub const fn with_deepen_relative(self, enabled: bool) -> Self {
        if enabled { self.with(Self::DEEPEN_RELATIVE) }
        else { Self(self.0 & !Self::DEEPEN_RELATIVE) }
    }
}''')
    edit(wire,'                b"no-done" => self.no_done = true,','''                b"deepen-relative" => {
                    if capability.value.is_some() {
                        return Err(WireError::MalformedRequestLine { line: capability.encoded()? });
                    }
                    self.options = self.options.with_deepen_relative(true);
                }
                b"no-done" => self.no_done = true,''')
    edit(wire,'                let request = self.pack_request();','                let request = self.pack_request();\n                shallow_response::validate_relative_depth(&request)?;')
    edit(wire,'''        if line == b"sideband-all" {''','''        if line == b"deepen-relative" {
            self.require_fetch_feature(b"shallow")?;
            self.options = self.options.with_deepen_relative(true);
            return Ok(Transition::empty());
        }
        if line == b"sideband-all" {''')
    edit(wire,'''        if self.automatic_shallow_updates && shallow_response::has_controls(&request) {
            output.extend''','''        shallow_response::validate_relative_depth(&request)?;
        if self.automatic_shallow_updates && shallow_response::has_controls(&request) {
            output.extend''')
    edit(response,'    !request.shallows.is_empty() || changes_boundary(request)','    request.options.deepen_relative() || !request.shallows.is_empty() || changes_boundary(request)')
    edit(response,'pub(super) fn changes_boundary(request: &PackRequest) -> bool {','''pub(super) fn validate_relative_depth(request: &PackRequest) -> Result<(), WireError> {
    if request.options.deepen_relative()
        && (!matches!(request.deepen, Some(1..=2_147_483_647))
            || request.deepen_since.is_some() || !request.deepen_not.is_empty())
    {
        return Err(WireError::InvalidDepth);
    }
    Ok(())
}

pub(super) fn changes_boundary(request: &PackRequest) -> bool {''')
    generic='crates/fgit-wire/src/closure.rs'
    edit(generic,'    InvalidDeepenDepth,','''    InvalidDeepenDepth,
    /// Relative deepening requires the native connection-owned graph provider.
    UnsupportedRelativeDeepening,''')
    edit(generic,'            Self::InvalidDeepenDepth => formatter.write_str("deepen depth must be positive"),','''            Self::InvalidDeepenDepth => formatter.write_str("deepen depth must be positive"),
            Self::UnsupportedRelativeDeepening => formatter.write_str("relative deepening requires a native shallow provider"),''')
    edit(generic,'    let shallow_request = ShallowRequest::from_pack_request(request);','''    if request.options.deepen_relative() {
        return Err(ClosureError::UnsupportedRelativeDeepening);
    }
    let shallow_request = ShallowRequest::from_pack_request(request);''')
    text=(work/node).read_text();old='allow-reachable-sha1-in-want shallow filter include-tag';count=text.count(old);assert count>=8
    edit(node,old,'allow-reachable-sha1-in-want shallow deepen-relative filter include-tag',count)
    edit(visible,'        filtered.shallows.clear();','        filtered.options = filtered.options.with_deepen_relative(false);\n        filtered.shallows.clear();')
    edit(partial,'    if !request.shallows.is_empty()','    if request.options.deepen_relative() || !request.shallows.is_empty()')
    edit(shallow,'use fgit_wire::closure::ShallowUpdate;','use fgit_wire::closure::ShallowUpdate;\nmod relative;')
    edit(shallow,'    !request.shallows.is_empty()','    request.options.deepen_relative() || !request.shallows.is_empty()')
    edit(shallow,'    let mut depths = BTreeMap::new();','    let effective_depth = relative::effective_depth(objects, request, &old, work)?;\n    let mut depths = BTreeMap::new();')
    edit(shallow,'''                let boundary = request
                    .deepen
                    .map_or_else(|| old.contains(&id), |maximum| depth >= maximum);''','''                let boundary = effective_depth.map_or_else(
                    || old.contains(&id),
                    |maximum| maximum != relative::INFINITE_DEPTH && depth >= maximum,
                );''')
    new('crates/fgit-node/src/upload_visibility/shallow/relative.rs','relative.rs')
    new('crates/fgit-node/src/upload_visibility/shallow/relative_tests.rs','relative-tests.rs')
    tests='crates/fgit-node/src/upload_visibility/shallow/tests.rs'
    p=work/tests;p.write_text(p.read_text()+'\n#[path = "relative_tests.rs"]\nmod relative_tests;\n');changed.add(tests)
    oracle='crates/fgit-node/src/upload_visibility/tests/shallow_oracle.rs'
    p=work/oracle;p.write_text(p.read_text()+'\n#[path = "relative_oracle.rs"]\nmod relative_oracle;\n');changed.add(oracle)
    new('crates/fgit-node/src/upload_visibility/tests/relative_oracle.rs','relative-oracle.rs')
    new('crates/fgit-wire/tests/relative_deepening.rs','relative-wire-tests.rs')
    client='scripts/e2e/oracle/partial_clone_client.py'
    text=(work/client).read_text();old='"depth", "unshallow"';count=text.count(old);assert count==3
    edit(client,old,'"depth", "deepen", "unshallow"',count)
    edit(client,'shallow-clone|depth|unshallow','shallow-clone|depth|deepen|unshallow')
    edit(client,'        elif operation == "depth":','        elif operation in {"depth", "deepen"}:')
    edit(client,'            command = ["fetch", "--no-tags", "--depth=" + value, "origin"]','            flag = "--deepen=" if operation == "deepen" else "--depth="\n            command = ["fetch", "--no-tags", flag + value, "origin"]')
    for path in sorted(changed):
        if path.endswith('.rs') and path not in {wire,node,generic,partial}:
            subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',path],cwd=work,check=True)
    compile((work/client).read_text(),client,'exec')
    observed=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())
    assert observed==changed,(observed,changed);assert len(changed)==14,len(changed)
    git('diff','--check',cwd=work);git('config','user.name','Jeff Emanuel',cwd=work);git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',*sorted(changed),cwd=work)
    git('commit','-m','feat(fetch): implement native relative deepening through ordinary Git clients','-m','Carry deepen-relative through legacy capability and v2 argument negotiation without changing PackRequest layout. Resolve increments from the nearest reachable client boundary using the exact private graph, shared finite work ledger and cancellation; preserve old/new ancestry separation and partial-clone filtering. Add overflow/refusal/merge/tag/cancellation tests and a pinned 18-cell repeated-deepen/checkout/completion campaign. Generic non-native closure computation refuses unsupported relative semantics rather than treating increments as absolute depths. No dependency, lockfile, authority or retention changes.',cwd=work)
    sha=git('rev-parse','HEAD',cwd=work);branch='tooling/fetch-progress-source-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',sha+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+sha+'\n')
    print('PRODUCT_SOURCE',sha,branch,flush=True)
