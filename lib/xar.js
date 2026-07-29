import {promisify} from 'node:util';
import zlib from 'node:zlib';
import {XMLParser} from 'fast-xml-parser';
import {parseChecksum} from './checksum.js';
import {XAR} from './constants.js';

const unzip = promisify(zlib.unzip);

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '',
  attributesGroupName: '$',
  // parseTagValue: false keeps "0755" a string so mode values can be parsed as octal
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

export function readHeader(buffer) {
  if (buffer.length < XAR.HEADER_SIZE || buffer.subarray(0, XAR.MAGIC.length).toString('latin1') !== XAR.MAGIC) {
    return null;
  }

  const version = buffer.readUInt16BE(XAR.OFFSET_VERSION);
  if (version !== XAR.VERSION) {
    return null;
  }

  const headerSize = buffer.readUInt16BE(XAR.OFFSET_HEADER_SIZE);
  const tocLengthCompressed = Number(buffer.readBigUInt64BE(XAR.OFFSET_TOC_COMPRESSED));
  // const tocLengthUncompressed = Number(buffer.readBigUInt64BE(XAR.OFFSET_TOC_UNCOMPRESSED));
  // const checksumAlgorithm = buffer.readUInt32BE(XAR.OFFSET_CHECKSUM_ALGORITHM);

  // A clamped subarray would reach zlib as truncated input (Z_BUF_ERROR)
  if (headerSize < XAR.HEADER_SIZE || headerSize + tocLengthCompressed > buffer.length) {
    return null;
  }

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
