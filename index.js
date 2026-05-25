import {Buffer} from 'node:buffer';
import path from 'node:path';
import {promisify} from 'node:util';
import zlib from 'node:zlib';
import {parseStringPromise} from 'xml2js';

const inflate = promisify(zlib.inflate);
const gunzip = promisify(zlib.gunzip);

function readHeader(buffer) {
  if (buffer.length < 28 || buffer.subarray(0, 4).toString() !== 'xar!') {
    return null;
  }

  return {
    headerSize: buffer.readUInt16BE(4),
    version: buffer.readUInt16BE(6),
    tocLengthCompressed: Number(buffer.readBigUInt64BE(8)),
    tocLengthUncompressed: Number(buffer.readBigUInt64BE(16)),
    checksumAlgorithm: buffer.readUInt32BE(24),
  };
}

async function parseToc(input, header) {
  const tocStart = header.headerSize;
  const tocEnd = tocStart + header.tocLengthCompressed;
  const tocCompressed = input.subarray(tocStart, tocEnd);
  const tocBuffer = await inflate(tocCompressed);
  const parsed = await parseStringPromise(tocBuffer.toString());

  return parsed.xar?.toc?.[0];
}

function toDate(value) {
  const date = value ? new Date(value) : new Date(0);
  return Number.isNaN(date.getTime()) ? new Date(0) : date;
}

function toMode(value) {
  const parsed = typeof value === 'string' ? Number.parseInt(value, 8) : Number(value);
  return Number.isFinite(parsed) ? parsed : 0o755;
}

async function getFileData(node, heapStart, input) {
  const dataNode = node.data?.[0];
  const offset = Number(dataNode?.offset?.[0] ?? 0);
  const length = Number(dataNode?.length?.[0] ?? 0);
  const encoding = dataNode?.encoding?.[0]?.$?.style ?? 'application/octet-stream';

  if (!Number.isFinite(length) || length < 0) {
    return null;
  }

  const start = heapStart + offset;
  const compressedContent = input.subarray(start, start + length);

  if (encoding === 'application/x-gzip') {
    return gunzip(compressedContent);
  }

  if (encoding === 'application/octet-stream') {
    return compressedContent;
  }

  return null;
}

async function processNode(node, header, input, parentPath) {
  // Heap starts after: header + compressed TOC + TOC checksum (20 bytes for SHA1)
  const heapStart = header.headerSize + header.tocLengthCompressed + 20;
  const name = node.name?.[0] ?? '';
  const currentPath = path.posix.join(parentPath, name);
  const type = node.type?.[0];

  if (type === 'directory') {
    const entry = {
      data: Buffer.alloc(0),
      mode: toMode(node.mode?.[0]),
      mtime: toDate(node.mtime?.[0]),
      path: `${currentPath}/`,
      type: 'directory',
    };
    const children = node.file
      ? await collectPkgEntries(node.file, header, input, currentPath)
      : [];

    return [entry, ...children];
  }

  const data = await getFileData(node, heapStart, input);
  if (data === null) {
    return [];
  }

  return [{
    data,
    mode: toMode(node.mode?.[0]),
    mtime: toDate(node.mtime?.[0]),
    path: currentPath,
    type: 'file',
  }];
}

async function collectPkgEntries(fileNodes = [], header, input, parentPath = '') {
  const nodePromises = fileNodes.map(node => processNode(node, header, input, parentPath));
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
    if (!toc || !toc.file) {
      return [];
    }

    return collectPkgEntries(toc.file, header, input);
  };
}

export default decompressPkg;
