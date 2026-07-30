import {Buffer} from 'node:buffer';
import {collectPkgEntries} from './lib/entries.js';
import {isPayloadPath, unpackPayload} from './lib/payload.js';
import {parseToc, readHeader} from './lib/xar.js';

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
      if (entry.type === 'file' && isPayloadPath(entry.path)) {
        const unpacked = await unpackPayload(entry);
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
