// Explicit interactive history rewrite. Repository bytes enter text nodes only.
import { RebaseClient, RECEIPT_BYTES as RECEIPT_LIMIT } from './rebase.mjs';
import { decimal, fail, text, utf8, unhex } from './pulls-core.mjs';
import { FILE_BYTES as FILE_LIMIT, RESOLUTION_BYTES as RESOLUTION_LIMIT, MAX_CHOICES } from './rebase-data.mjs';
export function display(bytes, maximum = 4096) {
  const part = bytes.subarray(0, maximum); let value;
  try {
    value = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(part)
      .replace(/[\\\u0000-\u0009\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
        ch => ch === '\\' ? '\\\\' : `\\u{${ch.codePointAt(0).toString(16)}}`);
  } catch { value = Array.from(part, b => b >= 32 && b < 127 && b !== 92 ? String.fromCharCode(b) : `\\x${b.toString(16).padStart(2,'0')}`).join(''); }
  return value + (bytes.length > maximum ? `\n[preview limited to ${maximum} of ${bytes.length} bytes]` : '');
}
function hexText(value) {
  if (typeof value !== 'string' || value.length > FILE_LIMIT * 3 || /[^0-9a-fA-F \t\r\n]/.test(value)) fail('Enter bounded hex byte pairs.');
  return unhex(value.replace(/[ \t\r\n]/g,'').toLowerCase(), FILE_LIMIT);
}
function textBytes(value, endings) {
  text(value, FILE_LIMIT, 'resolved text');
  if (!['lf','crlf'].includes(endings)) fail('Choose LF or CRLF explicitly.');
  const lf = value.replace(/\r\n?/g,'\n'), bytes = utf8.encode(endings === 'crlf' ? lf.replace(/\n/g,'\r\n') : lf);
  if (bytes.length > FILE_LIMIT) fail('Converted text exceeds the resolved-file byte limit.');
  return bytes;
}
export async function chosenFile(file, maximum, current = () => true) {
  if (!file || !Number.isSafeInteger(file.size) || file.size < 0 || file.size > maximum) fail('Selected file exceeds its byte limit.');
  if (!current()) fail('File selection changed.');
  const buffer = await file.arrayBuffer();
  if (!current()) fail('File selection changed while reading.');
  if (!(buffer instanceof ArrayBuffer) || buffer.byteLength !== file.size || buffer.byteLength > maximum) fail('Selected file was truncated or changed.');
  return new Uint8Array(buffer);
}
// Validate ALL sizes and capture ALL choices before the FIRST file read. File
// objects, text, modes and original-commit context cannot change across awaits.
export async function collectResolutions(rows, retained, current) {
  if (rows.length + retained.resolutionPaths > MAX_CHOICES) fail('Cumulative conflict-choice limit exceeded.');
  let bytes = retained.resolutionBytes;
  const captured = rows.map(row => {
    const choice = row.choice.value;
    const value = { path_hex: row.path, choice };
    bytes += row.path.length / 2;
    let file = null;
    if (['text','hex','file'].includes(choice)) {
      if (!['100644','100755'].includes(row.mode.value)) fail('Choose a regular or executable resolved-file mode.');
      value.choice = 'file'; value.mode = Number.parseInt(row.mode.value,8);
      if (choice === 'file') {
        file = row.file.files?.[0];
        if (!file || !Number.isSafeInteger(file.size) || file.size < 0 || file.size > FILE_LIMIT) fail('Select a resolved file within the 256 KiB limit.');
        bytes += file.size;
      } else { value.bytes = choice === 'hex' ? hexText(row.content.value) : textBytes(row.content.value,row.endings.value); bytes += value.bytes.length; }
    } else if (!['base','ours','theirs','delete'].includes(choice)) fail('Select an explicit resolution for every conflict.');
    if (bytes > RESOLUTION_LIMIT) fail('Cumulative resolution byte limit exceeded before reading files.');
    return { value, file, row };
  });
  for (const item of captured) {
    if (!current()) fail('Resolution selection changed.');
    if (item.file) item.value.bytes = await chosenFile(item.file, FILE_LIMIT, () => current() && item.row.file.files?.[0] === item.file);
  }
  if (!current()) fail('Resolution selection changed.');
  return captured.map(item => item.value);
}
export function mountRebase(doc, options = {}) {
  const client = options.client ?? new RebaseClient({ ...options, href: options.href ?? globalThis.location.href });
  const get = id => { const e = doc.getElementById(id); if (!e) fail(`Missing rebase control ${id}.`); return e; };
  const ids = ['token','connect','disconnect','source','onto','format','select','selection','upstream','empty','committer','timestamp',
    'max-commits','prepare','cancel','report','conflicts','resolve','empty-stop','empty-policy','continue-empty','inspection',
    'stage','confirm-send','send','recover','discard','save-receipt','restore-file','restore','pending','status'];
  const c = Object.fromEntries(ids.map(id => [id,get(id)]));
  const element = (tag,value) => { const e=doc.createElement(tag); if(value !== undefined)e.textContent=value;return e; };
  let busy=false, revision=0, rows=[], draftDirty=false;
  const urls=options.urls ?? globalThis.URL, timers=options.timers ?? globalThis, downloads=new Map();
  function clearDownloads() { for(const [url,timer] of downloads){timers.clearTimeout(timer);urls.revokeObjectURL(url);} downloads.clear(); }
  function status(value) { c.status.textContent=value; }
  function sync() {
    const pending=client.pending, s=client.state;
    for(const id of ['source','onto','format','upstream','empty','committer','timestamp','max-commits','empty-policy','restore-file'])c[id].disabled=busy||!client.connected||!!pending;
    c.token.disabled=busy;c.connect.disabled=busy;c.select.disabled=busy||!client.connected||!!pending;
    c.prepare.disabled=busy||!client.connected||!!pending||!s.selection;
    c.cancel.disabled=!busy||!!pending;
    c.resolve.disabled=busy||!client.connected||!!pending||s.report?.state!=='conflicted';
    c['empty-stop'].hidden=s.report?.state!=='became_empty';c['continue-empty'].disabled=busy||!client.connected||!!pending||s.report?.state!=='became_empty';
    c.stage.disabled=busy||!client.connected||!!pending||!s.candidate||s.candidate.fields.expected_source===s.candidate.fields.candidate_commit;
    c.send.disabled=busy||!client.connected||!pending;c.recover.disabled=c.send.disabled;
    c['confirm-send'].disabled=busy||!pending;
    c.discard.disabled=busy||!pending||pending.sent||pending.exported;c['save-receipt'].disabled=busy||!pending;
    c.restore.disabled=busy||!client.connected||!!pending;
    c.pending.textContent=pending?JSON.stringify(pending,null,2):'No outstanding history rewrite.';
    for(const row of rows)for(const control of [row.choice,row.mode,row.content,row.file,row.endings])control.disabled=busy||!!pending||!client.connected;
  }
  function clearViews() {
    rows=[];draftDirty=false;clearDownloads();c.report.replaceChildren();c.conflicts.replaceChildren();c.inspection.replaceChildren();
    c.selection.textContent='';c['confirm-send'].checked=false;
  }
  function showDiff(value, target, heading) {
    target.append(element('h3',heading),element('p',`${value.requested_before} → ${value.requested_after}; ${value.entry_count} changed paths.`));
    if(!value.entries.length)target.append(element('p','Identical trees; no changed paths.'));
    for(const row of value.entries) {
      const detail=element('details');detail.append(element('summary',`${row.kind}: ${display(unhex(row.path_hex))} [${row.path_hex}]`));
      detail.append(element('pre',JSON.stringify({before:row.before,after:row.after},null,2)));
      if(row.content.kind==='text')for(const hunk of row.content.hunks)detail.append(element('p',`Before lines ${hunk.old.line_start}+${hunk.old.line_count} (zero-based)`),element('pre',display(unhex(hunk.before_hex))),
        element('p',`After lines ${hunk.new.line_start}+${hunk.new.line_count} (zero-based)`),element('pre',display(unhex(hunk.after_hex))));
      else detail.append(element('p',`${row.content.kind}: ${row.content.kind==='binary'?'binary bodies are not included':'no text hunk bodies'}.`));
      target.append(detail);
    }
  }
  function option(select,value,label,disabled=false) { const e=element('option',label);e.value=value;e.disabled=disabled;select.append(e); }
  function changedResolution() { revision++;draftDirty=true;client.cancel();c['confirm-send'].checked=false;status('Resolution changed. Validate the complete choices again before continuing.'); }
  function paint() {
    clearViews();const s=client.state;c.selection.textContent=s.selection?JSON.stringify(s.selection,null,2):'';
    if(!s.report){sync();return;}
    const r=s.report;
    c.report.append(element('h2',r.state==='clean'?'Complete rebased series':`Stopped: ${r.state}`),element('pre',JSON.stringify(s.command,null,2)));
    c.report.append(element('p',`${s.resolutionCommits.length} original commit(s), ${s.resolutionPaths} paths explicitly resolved. ${r.step_count} completed ${r.provisional_steps?'provisional ':''}steps.`));
    const steps=element('ol');for(const step of r.steps)steps.append(element('li',`${step.kind}: ${step.original} → ${step.rewritten}; tree ${step.tree}`));c.report.append(steps);
    if(r.state!=='clean')c.report.append(element('p',`Original commit ${r.stopped_commit}. Nothing in this stopped prefix can be published.`));
    if(r.state==='conflicted')for(const conflict of r.conflicts) {
      const section=element('section'),choice=element('select'),mode=element('select'),content=element('textarea'),file=element('input'),endings=element('select');
      const wrap=(label,control)=>{const l=element('label',label);l.append(control);return l;};
      section.append(element('h3',`${display(unhex(conflict.path_hex))} [${conflict.path_hex}]`),element('pre',JSON.stringify(conflict,null,2)));
      option(choice,'','Choose a resolution');
      for(const [v,label] of [['base','Base: original parent'],['ours','Ours: onto plus already replayed commits'],['theirs','Theirs: original commit being replayed'],['delete','Delete this path'],['text','Resolved UTF-8 text'],['hex','Resolved hexadecimal bytes'],['file','Upload exact resolved file']])option(choice,v,label,['base','ours','theirs'].includes(v)&&conflict[v]===null);
      option(mode,'100644','Regular (100644)');option(mode,'100755','Executable (100755)');mode.value='100644';
      option(endings,'lf','LF');option(endings,'crlf','CRLF');endings.value='lf';choice.value='';
      content.rows=5;content.maxLength=FILE_LIMIT*3;content.spellcheck=false;file.type='file';
      const custom=element('div'),textLabel=wrap('Resolved text or hex byte pairs',content),fileLabel=wrap('Exact file bytes',file),endingLabel=wrap('Text newline conversion',endings);
      custom.append(wrap('Resolved file mode',mode),textLabel,fileLabel,endingLabel);custom.hidden=true;
      const update=()=>{custom.hidden=!['text','hex','file'].includes(choice.value);textLabel.hidden=choice.value==='file';fileLabel.hidden=choice.value!=='file';endingLabel.hidden=choice.value!=='text';};
      choice.addEventListener('change',()=>{changedResolution();update();});
      for(const e of [mode,content,file,endings])for(const event of ['input','change'])e.addEventListener(event,changedResolution);
      section.append(wrap('Resolution',choice),custom);c.conflicts.append(section);rows.push({path:conflict.path_hex,choice,mode,content,file,endings});
    }
    if(s.candidate) {
      const i=s.candidate.inspection;
      c.inspection.append(element('h2','Inspected complete candidate'),element('pre',JSON.stringify({fields:s.candidate.fields,
        bundle_sha256:s.candidate.sha256,bundle_bytes:s.candidate.bundleBytes,commit_count:i.commit_count,publication_authorized:false},null,2)),
        element('p','Commit hashes, ordered parents and trees were checked. Native replay and original-author/message preservation are server claims; no signature or replay-equivalence proof is asserted.'));
      showDiff(i.net_change,c.inspection,'Net change to the source branch');
      for(const commit of i.commits){const detail=element('details');detail.append(element('summary',`Rewritten commit ${commit.index+1}: ${commit.commit}`),element('pre',display(unhex(commit.body_hex))));showDiff(commit.diff,detail,'Change from the preceding rebased commit');c.inspection.append(detail);}
    }
    sync();
  }
  async function perform(work) {
    if(busy)return;const start=++revision;busy=true;sync();
    try{await work(start);}catch(error){if(start===revision)status(`${error.outcomeUnknown?'Outcome unknown. Preserve the original request and key. ':''}${error.message}`);}
    finally{busy=false;if(!client.connected)clearViews();sync();}
  }
  function disconnect() {revision++;client.disconnect();c.token.value='';c['restore-file'].value='';clearViews();status(client.pending?'Disconnected. Original publication retained; save its recovery receipt.':'Disconnected; credentials, recipes and source views cleared.');sync();}
  c.connect.addEventListener('click',()=>perform(async()=>{const token=c.token.value;c.token.value='';clearViews();await client.connect(token);status('Connected. Select both branch tips or restore an original request.');}));
  c.disconnect.addEventListener('click',disconnect);
  c.select.addEventListener('click',()=>perform(async()=>{clearViews();await client.select(c.source.value,c.onto.value,c.format.value);paint();status('Both branches selected at one snapshot. Enter the exact upstream boundary and explicit committer.');}));
  for(const id of ['source','onto','format'])for(const event of ['input','change'])c[id].addEventListener(event,()=>{if(client.pending)return;revision++;client.clearSelection();clearViews();sync();status('Branch selection changed. Select both current tips explicitly.');});
  for(const id of ['upstream','empty','committer','timestamp','max-commits'])for(const event of ['input','change'])c[id].addEventListener(event,()=>{if(client.pending)return;revision++;client.invalidate();paint();status('Rebase inputs changed; previous recipes and candidate discarded. Branch pins remain selected.');});
  c.prepare.addEventListener('click',()=>perform(async()=>{clearViews();await client.prepare({upstream:c.upstream.value,empty:c.empty.value,committer:c.committer.value,
    timestamp:decimal(c.timestamp.value,'committer timestamp'),max_commits:decimal(c['max-commits'].value,'commit limit',1)});paint();status(client.state.candidate?'Native complete-series inspection finished. Review the net change and every commit before preparing publication.':'Rebase stopped without a publishable candidate. Resolve the displayed original commit or choose an empty-commit policy.');}));
  c.resolve.addEventListener('click',()=>perform(async start=>{const state=client.state;
    const choices=await collectResolutions(rows,state,()=>start===revision&&client.connected);await client.resolve(choices);paint();status(client.state.candidate?'Resolved series inspected. Nothing published.':'Resolution retained; continue at the next stopped original commit. Nothing published.');}));
  c['continue-empty'].addEventListener('click',()=>perform(async()=>{await client.continueEmpty(c['empty-policy'].value);c.empty.value=client.state.command.empty;paint();status('Explicit empty-commit policy applied to the same pinned series. Review its new result.');}));
  c.cancel.addEventListener('click',()=>{revision++;client.cancel();clearDownloads();status('Read cancelled. No history rewrite was submitted.');sync();});
  c.stage.addEventListener('click',()=>perform(async()=>{await client.stage();c['confirm-send'].checked=false;status('Exact history rewrite prepared locally. Separately confirm its source branch, old tip, onto and candidate.');}));
  c.send.addEventListener('click',()=>perform(async()=>{if(!c['confirm-send'].checked)fail('Confirm this exact history rewrite before sending or retrying.');c['confirm-send'].checked=false;
    const result=await client.send();paint();status(`Canonical ${result.outcome}: ${result.tx}. Delivery acknowledgement is not asserted.`);}));
  c.recover.addEventListener('click',()=>perform(async()=>{const result=await client.recover();if(result.terminal)paint();status(result.terminal?`Recovered canonical ${result.outcome}: ${result.tx}.`:`Still unresolved: ${result.state}. Absence does not prove non-commit.`);}));
  c.discard.addEventListener('click',()=>{try{client.discardUnsent();status('Unsent, unexported local request discarded.');sync();}catch(error){status(error.message);}});
  c['save-receipt'].addEventListener('click',()=>{
    try{const value=client.exportReceipt();
      if(options.saveReceipt)options.saveReceipt(value);
      else{const url=urls.createObjectURL(new Blob([value],{type:'application/json'}));
        try{const a=element('a');a.href=url;a.download='frankengit-rebase-retry.json';a.click();const timer=timers.setTimeout(()=>{urls.revokeObjectURL(url);downloads.delete(url);},30_000);timer?.unref?.();downloads.set(url,timer);}
        catch(error){urls.revokeObjectURL(url);throw error;}}
      status('Token-free original-request receipt saved. It contains repository candidate bytes; it is not authorization.');sync();
    }catch(error){status(error.message);}
  });
  c['restore-file'].addEventListener('change',()=>{revision++;client.cancel();});
  c.restore.addEventListener('click',()=>perform(async start=>{
    const file=c['restore-file'].files?.[0],bytes=await chosenFile(file,RECEIPT_LIMIT,()=>start===revision&&client.connected&&c['restore-file'].files?.[0]===file);
    await client.restoreReceipt(new TextDecoder('utf-8',{fatal:true}).decode(bytes));clearViews();status('Original request restored, not executed. Look up its outcome or separately confirm an unchanged retry.');}));
  const events=options.events ?? globalThis;
  events.addEventListener?.('pagehide',disconnect);
  events.addEventListener?.('beforeunload',event=>{if(client.pending||client.state.report||draftDirty){event.preventDefault();event.returnValue='';}});
  sync();return {client,disconnect,get rows(){return rows;}};
}
if(typeof document!=='undefined')mountRebase(document);
