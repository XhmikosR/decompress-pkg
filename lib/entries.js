import {Buffer} from 'node:buffer';
import path from 'node:path';
import {promisify} from 'node:util';
import zlib from 'node:zlib';
import {validateChecksum} from './checksum.js';
import {sanitizeEntryPath} from './sanitize.js';
import {getFirstChild, parseDataNode} from './xar.js';

const unzip = promisify(zlib.unzip);

function toDate(value) {
  const date = value ? new Date(value) : new Date(0);
  return Number.isNaN(date.getTime()) ? new Date(0) : date;
}

function toMode(value) {
  if (typeof value !== 'string' || value.length === 0) {
    return 0o755;
  }

  const parsed = Number.parseInt(value, 8);
  return Number.isFinite(parsed) ? parsed : 0o755;
}

function nodeMetadata(node, filePath) {
  return {
    data: Buffer.alloc(0),
    mode: toMode(getFirstChild(node, 'mode')),
    mtime: toDate(getFirstChild(node, 'mtime')),
    path: filePath,
  };
}

async function getFileData(node, heapStart, input) {
  const info = parseDataNode(getFirstChild(node, 'data'));
  if (info === null) {
    return null;
  }

  const {offset, length, size, encoding, archivedChecksum, extractedChecksum} = info;
  const start = heapStart + offset;

  if (start + length > input.length) {
    return null;
  }

  if (length === 0) {
    return Buffer.alloc(0);
  }

  const compressedContent = input.subarray(start, start + length);

  if (archivedChecksum) {
    validateChecksum(compressedContent, archivedChecksum, 'archived-checksum');
  }

  let decompressed;
  if (encoding === 'application/x-gzip') {
    // unzip auto-detects zlib (RFC 1950) vs gzip (RFC 1952); Apple's xar writes
    // zlib despite the "x-gzip" MIME label, but third-party tools may write real gzip.
    decompressed = await unzip(compressedContent);
  } else if (encoding === 'application/octet-stream') {
    decompressed = compressedContent;
  } else {
    throw new Error(`unsupported encoding: ${encoding}`);
  }

  if (size >= 0 && decompressed.length !== size) {
    throw new Error(`size mismatch at heap offset ${offset}: expected ${size} bytes, got ${decompressed.length}`);
  }

  if (extractedChecksum) {
    validateChecksum(decompressed, extractedChecksum, 'extracted-checksum');
  }

  return decompressed;
}

async function processNode(node, heapStart, input, parentPath) {
  if (!node || typeof node !== 'object') {
    return [];
  }

  const rawName = getFirstChild(node, 'name');
  const name = typeof rawName === 'string' ? sanitizeEntryPath(rawName) : '';
  const currentPath = path.posix.join(parentPath, name);
  const type = getFirstChild(node, 'type');

  if (type === 'directory') {
    const entry = {...nodeMetadata(node, `${currentPath}/`), type: 'directory'};
    const children = await collectPkgEntries(node.file, heapStart, input, currentPath);
    return [entry, ...children];
  }

  // Skip hardlink, symlink, fifo, character/block special, etc
  if (type !== undefined && type !== 'file') {
    return [];
  }

  const data = await getFileData(node, heapStart, input);
  if (data === null) {
    return [];
  }

  return [{...nodeMetadata(node, currentPath), data, type: 'file'}];
}

export async function collectPkgEntries(fileNodes, heapStart, input, parentPath = '') {
  if (!Array.isArray(fileNodes)) {
    return [];
  }

  const nodePromises = fileNodes.map(node => processNode(node, heapStart, input, parentPath));
  const results = await Promise.all(nodePromises);
  return results.flat();
}
