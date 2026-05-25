import {Buffer} from 'node:buffer';
import {promises as fs} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';
import zlib from 'node:zlib';
import test from 'ava';
import decompressPkg from './index.js';

const deflate = promisify(zlib.deflate);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function makeXar(xml, heap = Buffer.alloc(0)) {
  const toc = await deflate(Buffer.from(xml));
  const header = Buffer.alloc(28);

  header.write('xar!', 0, 'ascii'); // magic
  header.writeUInt16BE(28, 4); // header size
  header.writeUInt16BE(1, 6); // version
  header.writeBigUInt64BE(BigInt(toc.length), 8); // TOC length compressed
  header.writeBigUInt64BE(BigInt(xml.length), 16); // TOC length uncompressed
  header.writeUInt32BE(0, 24); // checksum algorithm (none)

  return Buffer.concat([header, toc, heap]);
}

function xar(body) {
  return `<xar><toc>${body}</toc></xar>`;
}

function dataXml(length, {offset = 0, encoding = 'application/octet-stream'} = {}) {
  return `
  <data>
    <offset>${offset}</offset>
    <length>${length}</length>
    <encoding style="${encoding}"/>
  </data>
  `;
}

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

