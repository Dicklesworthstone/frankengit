// Conflict choices are inert, explicit inputs to read-only native construction.
// File handles never select repository paths; the report supplies exact bytes.
import { integer, text, utf8, fail } from './pulls-core.mjs';
import { RESOLUTION_FILE_LIMIT, RESOLUTION_CONTENT_LIMIT } from './pulls-resolution.mjs';

export class ResolutionEditor {
  #doc; #parent; #display; #rows = []; #serial = 0; #disabled = true;
  constructor(doc, parent, displayBytes) { this.#doc = doc; this.#parent = parent; this.#display = displayBytes; }
  #element(tag, content = '') { const node = this.#doc.createElement(tag); node.textContent = content; return node; }
  #control(parent, label, tag) {
    const wrapper = this.#element('label', label), node = this.#element(tag);
    wrapper.append(node); parent.append(wrapper); return node;
  }
  #option(select, value, label, disabled = false) {
    const option = this.#element('option', label); option.value = value; option.disabled = disabled; select.append(option);
  }
  clear() {
    this.#serial += 1;
    for (const row of this.#rows) { row.content.value = ''; row.upload.value = ''; }
    this.#rows = []; this.#parent.replaceChildren();
  }
  show(report) {
    this.clear();
    for (const conflict of report.conflicts) {
      const section = this.#element('fieldset');
      section.append(this.#element('legend', this.#display(conflict.path_hex)));
      section.append(this.#element('pre', `Path bytes: ${conflict.path_hex}\nKind: ${conflict.kind}`));
      for (const [side, label] of [['base', 'Base'], ['ours', 'Ours (target)'], ['theirs', 'Theirs (source)']]) {
        const entry = conflict[side];
        section.append(this.#element('p', `${label}: ${entry === null ? 'absent — not an implicit deletion' : `${entry.mode.toString(8)} ${entry.oid}`}`));
      }
      const choice = this.#control(section, 'Resolution (no default choice)', 'select');
      this.#option(choice, '', 'Choose explicitly');
      for (const [side, label] of [['base', 'Keep base'], ['ours', 'Keep ours (target)'], ['theirs', 'Keep theirs (source)']]) this.#option(choice, side, label, conflict[side] === null);
      this.#option(choice, 'delete', 'Delete this path'); this.#option(choice, 'file', 'Supply resolved regular-file content'); choice.value = '';
      const mode = this.#control(section, 'Resolved file mode', 'select');
      for (const [value, label] of [['', 'Choose explicit mode'], ['100644', '100644 — regular'], ['100755', '100755 — executable']]) this.#option(mode, value, label);
      mode.value = '';
      const source = this.#control(section, 'Resolved file input', 'select');
      for (const [value, label] of [['', 'Choose input'], ['text', 'UTF-8 editor text (including an empty file)'], ['upload', 'Exact bytes from a file']]) this.#option(source, value, label);
      source.value = '';
      const content = this.#control(section, 'Resolved text — editor line endings; use upload for byte-exact files', 'textarea');
      content.rows = 6; content.maxLength = RESOLUTION_FILE_LIMIT; content.spellcheck = false;
      const upload = this.#control(section, 'Resolved file bytes (up to 1 MiB)', 'input'); upload.type = 'file';
      const row = { conflict, choice, mode, source, content, upload }; this.#rows.push(row);
      for (const node of [choice, mode, source, content, upload]) {
        for (const event of ['input', 'change']) node.addEventListener(event, () => { this.#serial += 1; this.#sync(row); });
      }
      this.#parent.append(section); this.#sync(row);
    }
  }
  #sync(row) {
    row.choice.disabled = this.#disabled;
    row.mode.disabled = row.source.disabled = this.#disabled || row.choice.value !== 'file';
    row.content.disabled = row.mode.disabled || row.source.value !== 'text';
    row.upload.disabled = row.mode.disabled || row.source.value !== 'upload';
  }
  setDisabled(disabled) { this.#disabled = disabled; for (const row of this.#rows) this.#sync(row); }
  async collect(guard = () => {}) {
    guard();
    if (!this.#rows.length) fail('Prepare a complete conflict report first.');
    const serial = this.#serial;
    let total = 0;
    // Snapshot and bound every choice BEFORE reading the first asynchronous file.
    const selected = this.#rows.map(row => {
      const path_hex = row.conflict.path_hex, choice = row.choice.value; total += path_hex.length / 2;
      const value = { path_hex, choice };
      if (['base', 'ours', 'theirs'].includes(choice)) {
        if (row.conflict[choice] === null) fail('Selected side is absent; choose delete explicitly.');
      } else if (choice === 'file') {
        if (!['100644', '100755'].includes(row.mode.value)) fail('Select the resolved file mode explicitly.');
        value.mode = row.mode.value;
        if (row.source.value === 'text') {
          value.bytes = utf8.encode(text(row.content.value, RESOLUTION_FILE_LIMIT, 'resolved text'));
          total += value.bytes.length;
        } else if (row.source.value === 'upload') {
          if (row.upload.files?.length !== 1) fail('Choose exactly one resolved file.');
          value.file = row.upload.files[0];
          value.size = integer(value.file.size, 'resolved file size', 0, RESOLUTION_FILE_LIMIT);
          total += value.size;
        } else fail('Choose text or exact-file input explicitly.');
      } else if (choice !== 'delete') fail('Choose a resolution for every conflicted path.');
      if (total > RESOLUTION_CONTENT_LIMIT) fail('Resolution content exceeds the 16 MiB browser limit.');
      return value;
    });
    const check = () => { guard(); if (serial !== this.#serial) fail('Resolution choices changed; nothing was submitted.'); };
    for (const value of selected) {
      check();
      if (value.file) {
        const bytes = new Uint8Array(await value.file.arrayBuffer()); check();
        if (bytes.length !== value.size) fail('Resolved file size changed while reading.');
        value.bytes = bytes; delete value.file; delete value.size;
      }
    }
    check(); return selected;
  }
}
