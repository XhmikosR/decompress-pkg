import {Buffer} from 'node:buffer';
import {promises as fs} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import test from 'ava';
import decompressPkg from './index.js';

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
