import {Buffer} from 'node:buffer';
import crypto from 'node:crypto';
import {promises as fs} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';
import zlib from 'node:zlib';
import test from 'ava';
import decompressPkg from '../index.js';
import {parseCpio} from '../cpio.js';
import {
  buildCpioOdc,
  buildCpioNewc,
  dataXml,
  gzip,
  makeXar,
  pkgWithPayload,
  xar,
} from './_helpers.js';

const deflate = promisify(zlib.deflate);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

test('extract macOS pkg buffer', async t => {
  const buf = await fs.readFile(path.join(__dirname, 'fixtures/file.pkg'));
  const files = await decompressPkg()(buf);

  t.is(files.length, 1);
  t.is(files[0].path, 'test.txt');
  t.is(files[0].data.toString(), 'test');
});

test('return empty array for non-pkg buffer', async t => {
  const files = await decompressPkg()(Buffer.from('not a pkg'));
  t.deepEqual(files, []);
});

test('mtime is deterministic across multiple extractions', async t => {
  const buf = await fs.readFile(path.join(__dirname, 'fixtures/file.pkg'));
  const [first, second] = await Promise.all([decompressPkg()(buf), decompressPkg()(buf)]);

  t.deepEqual(first[0].mtime, second[0].mtime);
});

test('extract signed pkg with checksum + RSA signature block before file data', async t => {
  const buf = await fs.readFile(path.join(__dirname, 'fixtures/signed.pkg'));
  const files = await decompressPkg()(buf);

  t.is(files.length, 1);
  t.is(files[0].path, 'test.txt');
  t.is(files[0].data.toString(), 'signed-test');
});

test('throw TypeError for non-Buffer input', async t => {
  await t.throwsAsync(decompressPkg()('string'), {instanceOf: TypeError});
});

test('return empty array for buffer with wrong magic bytes', async t => {
  const files = await decompressPkg()(Buffer.alloc(28));
  t.deepEqual(files, []);
});

test('return empty array for XAR with non-standard TOC structure', async t => {
  const files = await decompressPkg()(await makeXar('<root/>'));
  t.deepEqual(files, []);
});

test('return empty array for XAR with empty TOC', async t => {
  const files = await decompressPkg()(await makeXar(xar('')));
  t.deepEqual(files, []);
});

test('return empty array for XAR whose TOC has children but no file entries', async t => {
  const files = await decompressPkg()(await makeXar(xar('<creation-time>2026-01-01</creation-time>')));
  t.deepEqual(files, []);
});

test('extract directory entry', async t => {
  const xml = xar(`
    <file>
      <name>mydir</name>
      <type>directory</type>
      <mode>0755</mode>
      <mtime>2026-01-01T00:00:00Z</mtime>
    </file>
  `);
  const files = await decompressPkg()(await makeXar(xml));
  t.is(files.length, 1);
  t.is(files[0].type, 'directory');
  t.is(files[0].path, 'mydir/');
  t.is(files[0].mode, 0o755);
});

test('extract directory with nested file', async t => {
  const content = Buffer.from('nested');
  const compressed = await deflate(content);
  const xml = xar(`
    <file>
      <name>dir</name>
      <type>directory</type>
      <mode>0755</mode>
      <mtime>2026-01-01T00:00:00Z</mtime>
      <file>
        <name>child.txt</name>
        <type>file</type>
        <mode>0644</mode>
        <mtime>2026-01-01T00:00:00Z</mtime>
        ${dataXml(compressed.length, {encoding: 'application/x-gzip'})}
      </file>
    </file>
  `);
  const files = await decompressPkg()(await makeXar(xml, compressed));
  t.is(files.length, 2);
  t.is(files[0].type, 'directory');
  t.is(files[0].path, 'dir/');
  t.is(files[1].path, 'dir/child.txt');
  t.is(files[1].data.toString(), 'nested');
});

test('extract file with octet-stream encoding', async t => {
  const content = Buffer.from('raw');
  const xml = xar(`<file><name>raw.bin</name><type>file</type>${dataXml(content.length)}</file>`);
  const files = await decompressPkg()(await makeXar(xml, content));
  t.is(files.length, 1);
  t.is(files[0].data.toString(), 'raw');
});

test('skip file with unsupported encoding', async t => {
  const xml = xar(`<file><name>bad.bin</name><type>file</type>${dataXml(4, {encoding: 'application/x-bzip2'})}</file>`);
  const files = await decompressPkg()(await makeXar(xml, Buffer.alloc(4)));
  t.deepEqual(files, []);
});

test('skip file with negative offset', async t => {
  const xml = xar(`<file><name>bad.txt</name><type>file</type>${dataXml(4, {offset: -1})}</file>`);
  const files = await decompressPkg()(await makeXar(xml, Buffer.alloc(4)));
  t.deepEqual(files, []);
});

test('skip file when offset+length exceeds buffer', async t => {
  const xml = xar(`<file><name>bad.txt</name><type>file</type>${dataXml(999)}</file>`);
  const files = await decompressPkg()(await makeXar(xml, Buffer.alloc(4)));
  t.deepEqual(files, []);
});

test('extract zero-length gzip file', async t => {
  const xml = xar(`<file><name>empty.txt</name><type>file</type>${dataXml(0, {encoding: 'application/x-gzip'})}</file>`);
  const files = await decompressPkg()(await makeXar(xml));
  t.is(files.length, 1);
  t.is(files[0].path, 'empty.txt');
  t.is(files[0].data.length, 0);
});

test('use epoch date for invalid mtime', async t => {
  const content = Buffer.from('x');
  const xml = xar(`<file><name>test.txt</name><type>file</type><mtime>not-a-date</mtime>${dataXml(content.length)}</file>`);
  const files = await decompressPkg()(await makeXar(xml, content));
  t.is(files[0].mtime.getTime(), 0);
});

test('use default 0o755 mode for invalid mode string', async t => {
  const content = Buffer.from('x');
  const xml = xar(`<file><name>test.txt</name><type>file</type><mode>invalid</mode>${dataXml(content.length)}</file>`);
  const files = await decompressPkg()(await makeXar(xml, content));
  t.is(files[0].mode, 0o755);
});

test('sanitize path traversal in entry name', async t => {
  const content = Buffer.from('x');
  const xml = xar(`<file><name>../evil.txt</name><type>file</type>${dataXml(content.length)}</file>`);
  const files = await decompressPkg()(await makeXar(xml, content));
  t.is(files[0].path, 'evil.txt');
});

test('sanitize Windows-style path traversal in entry name', async t => {
  const content = Buffer.from('x');
  const name = String.raw`..\..\Windows\evil.exe`;
  const xml = xar(`<file><name>${name}</name><type>file</type>${dataXml(content.length)}</file>`);
  const files = await decompressPkg()(await makeXar(xml, content));
  t.is(files[0].path, 'Windows/evil.exe');
});

test('extract file with no name element defaults to empty path', async t => {
  const content = Buffer.from('x');
  const xml = xar(`<file><type>file</type>${dataXml(content.length)}</file>`);
  const files = await decompressPkg()(await makeXar(xml, content));
  t.is(files.length, 1);
  t.is(files[0].path, '.');
});

test('extract file with no data element defaults to empty buffer', async t => {
  const xml = xar('<file><name>empty.txt</name><type>file</type></file>');
  const files = await decompressPkg()(await makeXar(xml));
  t.is(files.length, 1);
  t.is(files[0].path, 'empty.txt');
  t.is(files[0].data.length, 0);
});

test('handle name element containing nested XML without crashing', async t => {
  // <name> with child elements parses as an object, not a string.
  const xml = xar(`<file><name><x/></name><type>file</type>${dataXml(0)}</file>`);
  const files = await decompressPkg()(await makeXar(xml));
  t.is(files.length, 1);
  t.is(files[0].path, '.');
});

test('skip file entry whose body is text content instead of elements', async t => {
  // <file>plain text</file> parses as a string, not an object.
  const xml = xar('<file>plain text</file>');
  const files = await decompressPkg()(await makeXar(xml));
  t.deepEqual(files, []);
});

test('skip hardlink entries', async t => {
  const xml = xar('<file><name>link</name><type>hardlink</type></file>');
  const files = await decompressPkg()(await makeXar(xml));
  t.deepEqual(files, []);
});

test('skip symlink entries', async t => {
  const xml = xar('<file><name>shortcut</name><type>symlink</type></file>');
  const files = await decompressPkg()(await makeXar(xml));
  t.deepEqual(files, []);
});

test('skip hardlink siblings but keep regular files in same directory', async t => {
  const content = Buffer.from('keep');
  const xml = xar(`
    <file><name>link</name><type>hardlink</type></file>
    <file><name>real.txt</name><type>file</type>${dataXml(content.length)}</file>
  `);
  const files = await decompressPkg()(await makeXar(xml, content));
  t.is(files.length, 1);
  t.is(files[0].path, 'real.txt');
});

test('unpack gzip + cpio odc Payload', async t => {
  const cpio = buildCpioOdc([
    {name: '.', mode: 0o04_0755},
    {name: './bin/hugo', mode: 0o10_0755, data: Buffer.from('binary-content')},
  ]);
  const files = await decompressPkg()(await pkgWithPayload(cpio));
  const hugo = files.find(f => f.path === 'bin/hugo');
  t.truthy(hugo);
  t.is(hugo.type, 'file');
  t.is(hugo.mode, 0o755);
  t.is(hugo.data.toString(), 'binary-content');
});

test('unpack gzip + cpio newc Payload', async t => {
  const cpio = buildCpioNewc([
    {name: './tool', mode: 0o10_0755, data: Buffer.from('newc-content')},
  ]);
  const files = await decompressPkg()(await pkgWithPayload(cpio));
  const tool = files.find(f => f.path === 'tool');
  t.truthy(tool);
  t.is(tool.data.toString(), 'newc-content');
});

test('filter AppleDouble sidecars from Payload', async t => {
  const cpio = buildCpioOdc([
    {name: './hugo', mode: 0o10_0755, data: Buffer.from('real')},
    {name: './._hugo', mode: 0o10_0644, data: Buffer.from('apple-double')},
  ]);
  const files = await decompressPkg()(await pkgWithPayload(cpio));
  t.is(files.length, 1);
  t.is(files[0].path, 'hugo');
});

test('skip cpio root directory entry', async t => {
  const cpio = buildCpioOdc([
    {name: '.', mode: 0o04_0755},
    {name: './file.txt', mode: 0o10_0644, data: Buffer.from('x')},
  ]);
  const files = await decompressPkg()(await pkgWithPayload(cpio));
  t.is(files.length, 1);
  t.is(files[0].path, 'file.txt');
});

test('unpack nested cpio directory entry', async t => {
  // The root "." gets filtered (it sanitizes to empty), but a real subdir survives.
  const cpio = buildCpioOdc([
    {name: './bin', mode: 0o04_0755},
    {name: './bin/hugo', mode: 0o10_0755, data: Buffer.from('x')},
  ]);
  const files = await decompressPkg()(await pkgWithPayload(cpio));
  const dir = files.find(f => f.type === 'directory');
  t.truthy(dir);
  t.is(dir.path, 'bin/');
  t.is(dir.mode, 0o755);
});

test('sanitize path traversal in cpio entry name', async t => {
  const cpio = buildCpioOdc([
    {name: '../evil', mode: 0o10_0644, data: Buffer.from('x')},
  ]);
  const files = await decompressPkg()(await pkgWithPayload(cpio));
  t.is(files.length, 1);
  t.is(files[0].path, 'evil');
});

test('skip symlink entries inside cpio', async t => {
  const cpio = buildCpioOdc([
    {name: './shortcut', mode: 0o12_0777, data: Buffer.from('target')},
    {name: './real', mode: 0o10_0644, data: Buffer.from('real')},
  ]);
  const files = await decompressPkg()(await pkgWithPayload(cpio));
  t.is(files.length, 1);
  t.is(files[0].path, 'real');
});

test('rebase cpio entries under component pkg directory', async t => {
  const cpio = buildCpioOdc([
    {name: './hugo', mode: 0o10_0755, data: Buffer.from('x')},
  ]);
  const files = await decompressPkg()(await pkgWithPayload(cpio, 'Component.pkg/Payload'));
  const nested = files.find(f => f.path === 'Component.pkg/hugo');
  t.truthy(nested);
  t.is(nested.data.toString(), 'x');
});

test('leave Payload entry intact when gunzip fails', async t => {
  const raw = Buffer.from('NOPE');
  const xml = xar(`<file><name>Payload</name><type>file</type>${dataXml(raw.length)}</file>`);
  const files = await decompressPkg()(await makeXar(xml, raw));
  t.is(files.length, 1);
  t.is(files[0].path, 'Payload');
  t.is(files[0].data.toString(), 'NOPE');
});

test('leave Payload entry intact when gunzip succeeds but content is not cpio', async t => {
  const notCpio = await gzip(Buffer.from('hello world, definitely not cpio'));
  const xml = xar(`<file><name>Payload</name><type>file</type>${dataXml(notCpio.length)}</file>`);
  const files = await decompressPkg()(await makeXar(xml, notCpio));
  t.is(files.length, 1);
  t.is(files[0].path, 'Payload');
});

test('leave Payload entry intact when unpacked content is shorter than a cpio header', async t => {
  // Exercises parseCpio's <6-byte short-buffer guard.
  const short = await gzip(Buffer.from('xx'));
  const xml = xar(`<file><name>Payload</name><type>file</type>${dataXml(short.length)}</file>`);
  const files = await decompressPkg()(await makeXar(xml, short));
  t.is(files.length, 1);
  t.is(files[0].path, 'Payload');
});

test('return empty array when Payload cpio has no extractable entries', async t => {
  // buildCpioOdc([]) produces a cpio with only the TRAILER record. parseCpio
  // returns [] (not null), so unpackPayload returns []. The check must be
  // !== null rather than truthy so null (parse failure) and [] (valid but
  // empty) are handled differently.
  const cpio = buildCpioOdc([]);
  const files = await decompressPkg()(await pkgWithPayload(cpio));
  t.deepEqual(files, []);
});

test('preserve sibling metadata files alongside unpacked Payload', async t => {
  // Mirror a real .pkg layout: PackageInfo + Payload at the top level.
  const cpio = buildCpioOdc([{name: './hugo', mode: 0o10_0755, data: Buffer.from('x')}]);
  const compressed = await gzip(cpio);
  const packageInfo = Buffer.from('<pkg-info/>');
  const heap = Buffer.concat([packageInfo, compressed]);
  const xml = xar(`
    <file><name>PackageInfo</name><type>file</type>${dataXml(packageInfo.length, {offset: 0})}</file>
    <file><name>Payload</name><type>file</type>${dataXml(compressed.length, {offset: packageInfo.length})}</file>
  `);
  const files = await decompressPkg()(await makeXar(xml, heap));
  t.is(files.length, 2);
  t.truthy(files.find(f => f.path === 'PackageInfo'));
  t.truthy(files.find(f => f.path === 'hugo'));
});

test('parseCpio: rejects buffers shorter than 6 bytes', t => {
  t.is(parseCpio(Buffer.alloc(0)), null);
  t.is(parseCpio(Buffer.from('xxx')), null);
});

test('parseCpio: rejects buffers without a recognized magic', t => {
  t.is(parseCpio(Buffer.from('123456789012')), null);
});

test('parseCpio: rejects non-Buffer input', t => {
  t.is(parseCpio('not a buffer'), null);
  t.is(parseCpio(null), null);
});

test('parseCpio: rejects odc entry claiming more data than buffer holds', t => {
  // Valid 76-byte odc header but filesize claims 9999 bytes that don't exist.
  const oct = (value, length) => value.toString(8).padStart(length, '0');
  const header = '070707' + oct(0, 6).repeat(7) + oct(0, 11) + oct(2, 6) + oct(9999, 11);
  const name = 'x\0';
  t.is(parseCpio(Buffer.from(header + name, 'binary')), null);
});

test('parseCpio: rejects newc entry claiming more data than buffer holds', t => {
  // newc header is 110 bytes: magic(6) + 13 fields x 8 bytes. Field order:
  //  ino, mode, uid, gid, nlink, mtime, filesize, devmajor, devminor,
  //  rdevmajor, rdevminor, namesize, check.
  const hex = (value, length) => value.toString(16).padStart(length, '0');
  // 6 leading zero fields + filesize=9999 + 4 zero fields + namesize=2 + check=0.
  const header = '070701' + hex(0, 8).repeat(6) + hex(9999, 8) + hex(0, 8).repeat(4) + hex(2, 8) + hex(0, 8);
  const namePadded = 'x\0\0\0'; // name + NUL + 2 bytes pad to 4-byte boundary
  t.is(parseCpio(Buffer.from(header + namePadded, 'binary')), null);
});

test('parseCpio: rejects odc entry with namesize=0', t => {
  const oct = (value, length) => value.toString(8).padStart(length, '0');
  const header = '070707' + oct(0, 6).repeat(7) + oct(0, 11) + oct(0, 6) + oct(0, 11);
  t.is(parseCpio(Buffer.from(header, 'binary')), null);
});

test('parseCpio: rejects newc entry with namesize=0', t => {
  const hex = (value, length) => value.toString(16).padStart(length, '0');
  const header = '070701' + hex(0, 8).repeat(12) + hex(0, 8);
  t.is(parseCpio(Buffer.from(header, 'binary')), null);
});

// --- <size> field validation ---

test('throw when <size> does not match decompressed length', async t => {
  const content = Buffer.from('hello');
  const xml = xar(`<file><name>test.txt</name><type>file</type>${dataXml(content.length, {size: 999})}</file>`);
  await t.throwsAsync(decompressPkg()(await makeXar(xml, content)), {instanceOf: Error});
});

test('extract file when <size> matches decompressed length', async t => {
  const content = Buffer.from('hello');
  const xml = xar(`<file><name>test.txt</name><type>file</type>${dataXml(content.length, {size: content.length})}</file>`);
  const files = await decompressPkg()(await makeXar(xml, content));
  t.is(files[0].data.toString(), 'hello');
});

// --- <archived-checksum> validation ---

test('throw when archived-checksum does not match', async t => {
  const content = Buffer.from('hello');
  const xml = xar(`<file><name>test.txt</name><type>file</type>${dataXml(content.length, {
    archivedChecksum: {style: 'sha1', hash: '0000000000000000000000000000000000000000'},
  })}</file>`);
  await t.throwsAsync(decompressPkg()(await makeXar(xml, content)), {instanceOf: Error});
});

test('extract file when archived-checksum matches', async t => {
  const content = Buffer.from('hello');
  const hash = crypto.createHash('sha1').update(content).digest('hex');
  const xml = xar(`<file><name>test.txt</name><type>file</type>${dataXml(content.length, {
    archivedChecksum: {style: 'sha1', hash},
  })}</file>`);
  const files = await decompressPkg()(await makeXar(xml, content));
  t.is(files[0].data.toString(), 'hello');
});

// --- <extracted-checksum> validation ---

test('throw when extracted-checksum does not match', async t => {
  const content = Buffer.from('hello');
  const xml = xar(`<file><name>test.txt</name><type>file</type>${dataXml(content.length, {
    extractedChecksum: {style: 'sha1', hash: '0000000000000000000000000000000000000000'},
  })}</file>`);
  await t.throwsAsync(decompressPkg()(await makeXar(xml, content)), {instanceOf: Error});
});

test('extract file when extracted-checksum matches (sha256)', async t => {
  const content = Buffer.from('hello');
  const hash = crypto.createHash('sha256').update(content).digest('hex');
  const xml = xar(`<file><name>test.txt</name><type>file</type>${dataXml(content.length, {
    extractedChecksum: {style: 'sha256', hash},
  })}</file>`);
  const files = await decompressPkg()(await makeXar(xml, content));
  t.is(files[0].data.toString(), 'hello');
});

test('skip validation for unknown checksum algorithm', async t => {
  const content = Buffer.from('hello');
  const xml = xar(`<file><name>test.txt</name><type>file</type>${dataXml(content.length, {
    archivedChecksum: {style: 'xxhash128', hash: 'aabbccdd'},
  })}</file>`);
  const files = await decompressPkg()(await makeXar(xml, content));
  t.is(files[0].data.toString(), 'hello');
});

test('skip validation when checksum style is "none"', async t => {
  const content = Buffer.from('hello');
  const xml = xar(`<file><name>test.txt</name><type>file</type>${dataXml(content.length, {
    archivedChecksum: {style: 'none', hash: 'ignored'},
  })}</file>`);
  const files = await decompressPkg()(await makeXar(xml, content));
  t.is(files[0].data.toString(), 'hello');
});

test('parseCpio: rejects odc with corrupted second entry magic', t => {
  // Build a valid one-entry archive, then replace the trailer with 76 bytes of garbage
  // so the second loop iteration encounters a bad magic.
  const valid = buildCpioOdc([{name: './a', mode: 0o10_0644, data: Buffer.from('x')}]);
  const firstEntrySize = 76 + 4 + 1; // header + './a\0' + data
  const garbage = Buffer.alloc(76, 0x41); // 76 bytes of 'A'
  t.is(parseCpio(Buffer.concat([valid.subarray(0, firstEntrySize), garbage])), null);
});

test('parseCpio: rejects newc with corrupted second entry magic', t => {
  const valid = buildCpioNewc([{name: './a', mode: 0o10_0644, data: Buffer.from('x')}]);
  // newc first-entry size: header(110) + name('./a\0' 4) + 2 name-pad + data(1) + 3 data-pad = 120
  const firstEntrySize = 120;
  const garbage = Buffer.alloc(110, 0x41);
  t.is(parseCpio(Buffer.concat([valid.subarray(0, firstEntrySize), garbage])), null);
});

test('cpio file with permissions=0 defaults to 0o644 mode', async t => {
  // S_IFREG with no permission bits set.
  const cpio = buildCpioOdc([{name: './bin', mode: 0o10_0000, data: Buffer.from('x')}]);
  const files = await decompressPkg()(await pkgWithPayload(cpio));
  t.is(files.find(f => f.path === 'bin').mode, 0o644);
});

test('cpio directory with permissions=0 defaults to 0o755 mode', async t => {
  // S_IFDIR with no permission bits set.
  const cpio = buildCpioOdc([
    {name: './dir', mode: 0o04_0000},
    {name: './dir/x', mode: 0o10_0644, data: Buffer.from('x')},
  ]);
  const files = await decompressPkg()(await pkgWithPayload(cpio));
  t.is(files.find(f => f.type === 'directory').mode, 0o755);
});
