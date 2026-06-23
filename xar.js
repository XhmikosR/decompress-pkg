import {promisify} from 'node:util';
import zlib from 'node:zlib';
import {XMLParser} from 'fast-xml-parser';
import {parseChecksum} from './checksum.js';

const unzip = promisify(zlib.unzip);

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
  // <file> can appear multiple times; force array so a single child doesn't collapse to a scalar
  isArray: name => name === 'file',
});

export function getFirstChild(node, name) {
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
export function readHeader(buffer) {
  if (buffer.length < 28 || buffer.subarray(0, 4).toString() !== 'xar!') {
    return null;
  }

  const version = buffer.readUInt16BE(6);
  if (version !== 1) {
    return null;
  }

  const headerSize = buffer.readUInt16BE(4);
  const tocLengthCompressed = Number(buffer.readBigUInt64BE(8));

  return {
    headerSize,
    tocLengthCompressed,
  };
}

export async function parseToc(input, header) {
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

export function parseDataNode(dataNode) {
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
