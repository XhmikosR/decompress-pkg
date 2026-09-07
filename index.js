import {Buffer} from 'node:buffer';
import {LIMITS} from './lib/constants.js';
import {collectPkgEntries} from './lib/entries.js';
import {isPayloadPath, unpackPayload} from './lib/payload.js';
import {parseToc, readHeader} from './lib/xar.js';

// maxOutputLength accepts 1 .. MAX_SAFE_INTEGER
function resolveLimit(value, fallback, name) {
  if (value === undefined) {
    return fallback;
  }

  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`Expected ${name} to be a positive safe integer, got ${value}`);
  }

  return value;
}

function decompressPkg(options) {
  const {maxTocSize, maxFileSize, maxPayloadSize} = options ?? {};
  const limits = {
    maxTocSize: resolveLimit(maxTocSize, LIMITS.TOC_SIZE, 'maxTocSize'),
    maxFileSize: resolveLimit(maxFileSize, LIMITS.FILE_SIZE, 'maxFileSize'),
    maxPayloadSize: resolveLimit(maxPayloadSize, LIMITS.PAYLOAD_SIZE, 'maxPayloadSize'),
  };

  return async input => {
    if (!Buffer.isBuffer(input)) {
      throw new TypeError(`Expected a Buffer, got ${typeof input}`);
    }

    const header = readHeader(input);
    if (!header) {
      return [];
    }

    const toc = await parseToc(input, header, limits.maxTocSize);
    if (!toc || typeof toc !== 'object') {
      return [];
    }

    // File offsets in the TOC are relative to the raw heap start;
    // checksum/signature bytes are already accounted for in those offsets.
    const heapStart = header.headerSize + header.tocLengthCompressed;
    const entries = await collectPkgEntries(toc.file, {heapStart, input, maxFileSize: limits.maxFileSize});

    const expanded = await Promise.all(entries.map(async entry => {
      if (entry.type === 'file' && isPayloadPath(entry.path)) {
        const unpacked = await unpackPayload(entry, limits.maxPayloadSize);
        if (unpacked !== null) {
          return unpacked;
        }
      }

      return [entry];
    }));

    return expanded.flat();
  };
}

export default decompressPkg;
