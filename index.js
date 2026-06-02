import {Buffer} from 'node:buffer';
import path from 'node:path';
import {promisify} from 'node:util';
import zlib from 'node:zlib';
import {XMLParser} from 'fast-xml-parser';
import {parseCpio} from './cpio.js';
import {parseChecksum, validateChecksum} from './checksum.js';

const unzip = promisify(zlib.unzip);
const gunzip = promisify(zlib.gunzip);

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '',
  attributesGroupName: '$',
  // parseTagValue: false keeps "0755" a string so toMode can parse it as octal
  parseTagValue: false,
  parseAttributeValue: false,
  // processEntities: false blocks entity-expansion DoS via attacker-controlled TOCs
  processEntities: false,
  trimValues: true,
  // single-child toc elements otherwise collapse to scalars
  isArray: name => ['toc', 'file', 'data', 'encoding'].includes(name),
});

function getFirstChild(node, name) {
  if (!node || typeof node !== 'object') {
    return undefined;
  }

  const value = node[name];
  if (Array.isArray(value)) {
    return value.length === 0 ? undefined : value[0];
  }

  return value;
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
  const tocLengthCompressed = Number(buffer.readBigUInt64BE(8));

  return {
    headerSize,
    tocLengthCompressed,
  };
}

async function parseToc(input, header) {
  const tocStart = header.headerSize;
  const tocEnd = tocStart + header.tocLengthCompressed;
  const tocCompressed = input.subarray(tocStart, tocEnd);
  const tocBuffer = await unzip(tocCompressed);
  const parsed = xmlParser.parse(tocBuffer.toString());

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

  const size = Number(getFirstChild(dataNode, 'size'));

  return {
    offset,
    length,
    size: Number.isFinite(size) && size >= 0 ? size : -1,
    encoding,
    archivedChecksum: parseChecksum(getFirstChild(dataNode, 'archived-checksum')),
    extractedChecksum: parseChecksum(getFirstChild(dataNode, 'extracted-checksum')),
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
    return null;
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

function sanitizeCpioPath(name) {
  // Splitting on both separators stops `..\\evil` from bypassing the `..` filter on Windows.
  return name.split(/[/\\]/).filter(p => p && p !== '.' && p !== '..').join('/');
}

function cpioEntryToFile(entry, parentPath) {
  const safeName = sanitizeCpioPath(entry.name);
  if (!safeName) {
    return null;
  }

  // AppleDouble sidecars (`._file`) are macOS resource forks, not real files.
  const basename = safeName.slice(safeName.lastIndexOf('/') + 1);
  if (basename.startsWith('._')) {
    return null;
  }

  const mtime = new Date((Number.isFinite(entry.mtime) ? entry.mtime : 0) * 1000);
  const fullPath = parentPath ? `${parentPath}/${safeName}` : safeName;

  if (entry.isDirectory) {
    return {
      data: Buffer.alloc(0),
      mode: entry.permissions || 0o755,
      mtime,
      path: `${fullPath}/`,
      type: 'directory',
    };
  }

  if (entry.isFile) {
    return {
      // Detach the slice from the gunzipped buffer so the parent can be released.
      data: Buffer.from(entry.data),
      mode: entry.permissions || 0o644,
      mtime,
      path: fullPath,
      type: 'file',
    };
  }

  // Skip symlinks, fifos, character/block devices.
  return null;
}

const PAYLOAD_PATH = /(?:^|\/)Payload$/;

async function unpackPayload(payloadEntry) {
  let cpioBuffer;
  try {
    cpioBuffer = await gunzip(payloadEntry.data);
  } catch {
    return null;
  }

  const cpioEntries = parseCpio(cpioBuffer);
  if (!cpioEntries) {
    return null;
  }

  // Component pkgs nest payloads as `Foo.pkg/Payload`; rebase under that parent.
  const parent = path.posix.dirname(payloadEntry.path);
  const parentPath = parent === '.' ? '' : parent;

  return cpioEntries
    .map(entry => cpioEntryToFile(entry, parentPath))
    .filter(file => file !== null);
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
    const entries = await collectPkgEntries(toc.file, heapStart, input);

    const expanded = await Promise.all(entries.map(async entry => {
      if (entry.type === 'file' && PAYLOAD_PATH.test(entry.path)) {
        const unpacked = await unpackPayload(entry);
        if (unpacked) {
          return unpacked;
        }
      }

      return [entry];
    }));

    return expanded.flat();
  };
}

export default decompressPkg;
