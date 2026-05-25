import {Buffer} from 'node:buffer';
import path from 'node:path';
import {promisify} from 'node:util';
import zlib from 'node:zlib';
import {parseStringPromise} from 'xml2js';

const inflate = promisify(zlib.inflate);

function getFirstChild(node, name) {
  if (!node || typeof node !== 'object') {
    return undefined;
  }

  const arr = node[name];
  if (!Array.isArray(arr) || arr.length === 0) {
    return undefined;
  }

  return arr[0];
}

function getFirstAttr(node, name, attr) {
  const child = getFirstChild(node, name);
  if (!child || typeof child !== 'object' || !child.$) {
    return undefined;
  }

  return child.$[attr];
}

// XAR header layout (28 bytes):
//   0-3  magic "xar!"
//   4-5  header size (uint16 BE)
//   6-7  version (uint16 BE) - always 1
//   8-15 TOC length compressed (uint64 BE)
//   16-23 TOC length uncompressed (uint64 BE)
//   24-27 checksum algorithm (uint32 BE)
function readHeader(buffer) {
  if (buffer.length < 28 || buffer.subarray(0, 4).toString() !== 'xar!') {
    return null;
  }

  const headerSize = buffer.readUInt16BE(4);
  // const version = buffer.readUInt16BE(6);
  const tocLengthCompressed = Number(buffer.readBigUInt64BE(8));
  // const tocLengthUncompressed = Number(buffer.readBigUInt64BE(16));
  const checksumAlgorithm = buffer.readUInt32BE(24);

  return {
    headerSize,
    tocLengthCompressed,
    checksumAlgorithm,
  };
}

async function parseToc(input, header) {
  const tocStart = header.headerSize;
  const tocEnd = tocStart + header.tocLengthCompressed;
  const tocCompressed = input.subarray(tocStart, tocEnd);
  const tocBuffer = await inflate(tocCompressed);
  const parsed = await parseStringPromise(tocBuffer.toString());

  // parsed.xar is the root element - xml2js does NOT wrap the root in an array.
  if (!parsed || !parsed.xar) {
    return undefined;
  }

  return getFirstChild(parsed.xar, 'toc');
}

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

function parseDataNode(dataNode) {
  const offset = Number(getFirstChild(dataNode, 'offset') ?? 0);
  const length = Number(getFirstChild(dataNode, 'length') ?? 0);
  const encoding = getFirstAttr(dataNode, 'encoding', 'style') ?? 'application/octet-stream';

  if (!Number.isFinite(offset) || offset < 0 || !Number.isFinite(length) || length < 0) {
    return null;
  }

  return {offset, length, encoding};
}

async function getFileData(node, heapStart, input) {
  const info = parseDataNode(getFirstChild(node, 'data'));
  if (info === null) {
    return null;
  }

  const {offset, length, encoding} = info;
  const start = heapStart + offset;

  if (start + length > input.length) {
    return null;
  }

  if (length === 0) {
    return Buffer.alloc(0);
  }

  const compressedContent = input.subarray(start, start + length);

  if (encoding === 'application/x-gzip') {
    // XAR stores zlib (deflate) despite the "gzip" MIME name
    return inflate(compressedContent);
  }

  if (encoding === 'application/octet-stream') {
    return compressedContent;
  }

  return null;
}

async function processNode(node, heapStart, input, parentPath) {
  if (!node || typeof node !== 'object') {
    return [];
  }

  const rawName = getFirstChild(node, 'name');
  // Split on both separators so "..\\evil" can't bypass the .. filter on Windows.
  const name = typeof rawName === 'string'
    ? rawName.split(/[/\\]/).filter(p => p && p !== '..').join('/')
    : '';
  const currentPath = path.posix.join(parentPath, name);
  const type = getFirstChild(node, 'type');

  if (type === 'directory') {
    const entry = {
      data: Buffer.alloc(0),
      mode: toMode(getFirstChild(node, 'mode')),
      mtime: toDate(getFirstChild(node, 'mtime')),
      path: `${currentPath}/`,
      type: 'directory',
    };
    const children = await collectPkgEntries(node.file, heapStart, input, currentPath);
    return [entry, ...children];
  }

  // Skip hardlink, symlink, fifo, character/block special, etc.
  if (type !== undefined && type !== 'file') {
    return [];
  }

  const data = await getFileData(node, heapStart, input);
  if (data === null) {
    return [];
  }

  return [{
    data,
    mode: toMode(getFirstChild(node, 'mode')),
    mtime: toDate(getFirstChild(node, 'mtime')),
    path: currentPath,
    type: 'file',
  }];
}

async function collectPkgEntries(fileNodes, heapStart, input, parentPath = '') {
  if (!Array.isArray(fileNodes)) {
    return [];
  }

  const nodePromises = fileNodes.map(node => processNode(node, heapStart, input, parentPath));
  const results = await Promise.all(nodePromises);
  return results.flat();
}

function decompressPkg() {
  return async input => {
    if (!Buffer.isBuffer(input)) {
      throw new TypeError(`Expected a Buffer, got ${typeof input}`);
    }

    const header = readHeader(input);
    if (!header) {
      return [];
    }

    const toc = await parseToc(input, header);
    if (!toc || typeof toc !== 'object') {
      return [];
    }

    // File offsets in the TOC are relative to the raw heap start;
    // checksum/signature bytes are already accounted for in those offsets.
    const heapStart = header.headerSize + header.tocLengthCompressed;

    return collectPkgEntries(toc.file, heapStart, input);
  };
}

export default decompressPkg;
