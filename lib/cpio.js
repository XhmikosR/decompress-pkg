/* eslint-disable no-bitwise */
import {Buffer} from 'node:buffer';
import {
  CPIO_TRAILER_NAME,
  NEWC,
  ODC,
  PERMISSIONS_MASK,
  S_IFDIR,
  S_IFMT,
  S_IFREG,
} from './constants.js';

// odc and both newc magics are the same width
const MAGIC_LENGTH = ODC.MAGIC.length;

function parseField(buffer, base, [fieldOffset, fieldLength], radix) {
  return Number.parseInt(buffer.subarray(base + fieldOffset, base + fieldOffset + fieldLength).toString('binary'), radix);
}

function alignUp(value, multiple) {
  return (value + multiple - 1) & ~(multiple - 1);
}

function makeEntry(mode, mtime, name, data) {
  const fileType = mode & S_IFMT;
  return {
    name,
    data,
    mtime,
    permissions: mode & PERMISSIONS_MASK,
    isDirectory: fileType === S_IFDIR,
    // A zero file-type is non-standard but some cpio writers emit it; treat as regular file
    isFile: fileType === S_IFREG || fileType === 0,
  };
}

function parseOdc(buffer) {
  const entries = [];
  let offset = 0;

  while (offset + ODC.HEADER_SIZE <= buffer.length) {
    if (buffer.subarray(offset, offset + MAGIC_LENGTH).toString('binary') !== ODC.MAGIC) {
      return null;
    }

    const mode = parseField(buffer, offset, ODC.MODE_FIELD, 8);
    const mtime = parseField(buffer, offset, ODC.MTIME_FIELD, 8);
    const namesize = parseField(buffer, offset, ODC.NAMESIZE_FIELD, 8);
    const filesize = parseField(buffer, offset, ODC.FILESIZE_FIELD, 8);

    if (![mode, mtime, namesize, filesize].every(value => Number.isFinite(value)) || namesize < 1) {
      return null;
    }

    const nameStart = offset + ODC.HEADER_SIZE;
    const dataStart = nameStart + namesize;
    const dataEnd = dataStart + filesize;

    if (dataEnd > buffer.length) {
      return null;
    }

    const name = buffer.subarray(nameStart, dataStart - 1).toString('utf8');
    if (name === CPIO_TRAILER_NAME) {
      break;
    }

    entries.push(makeEntry(mode, mtime, name, buffer.subarray(dataStart, dataEnd)));
    offset = dataEnd;
  }

  return entries;
}

function parseNewc(buffer) {
  const entries = [];
  let offset = 0;

  while (offset + NEWC.HEADER_SIZE <= buffer.length) {
    const magic = buffer.subarray(offset, offset + MAGIC_LENGTH).toString('binary');
    if (magic !== NEWC.MAGIC_NO_CRC && magic !== NEWC.MAGIC_CRC) {
      return null;
    }

    const mode = parseField(buffer, offset, NEWC.MODE_FIELD, 16);
    const mtime = parseField(buffer, offset, NEWC.MTIME_FIELD, 16);
    const filesize = parseField(buffer, offset, NEWC.FILESIZE_FIELD, 16);
    const namesize = parseField(buffer, offset, NEWC.NAMESIZE_FIELD, 16);

    if (![mode, mtime, namesize, filesize].every(value => Number.isFinite(value)) || namesize < 1) {
      return null;
    }

    const nameStart = offset + NEWC.HEADER_SIZE;
    const nameEnd = nameStart + namesize;
    // newc pads name and data fields up to a 4-byte boundary
    const dataStart = alignUp(nameEnd, NEWC.PAD_ALIGNMENT);
    const dataEnd = dataStart + filesize;

    if (dataEnd > buffer.length) {
      return null;
    }

    const name = buffer.subarray(nameStart, nameEnd - 1).toString('utf8');
    if (name === CPIO_TRAILER_NAME) {
      break;
    }

    entries.push(makeEntry(mode, mtime, name, buffer.subarray(dataStart, dataEnd)));
    offset = alignUp(dataEnd, NEWC.PAD_ALIGNMENT);
  }

  return entries;
}

export function parseCpio(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < MAGIC_LENGTH) {
    return null;
  }

  const magic = buffer.subarray(0, MAGIC_LENGTH).toString('binary');
  if (magic === ODC.MAGIC) {
    return parseOdc(buffer);
  }

  if (magic === NEWC.MAGIC_NO_CRC || magic === NEWC.MAGIC_CRC) {
    return parseNewc(buffer);
  }

  return null;
}
