/* eslint-disable no-bitwise */
import {Buffer} from 'node:buffer';

// CPIO formats found in macOS .pkg Payloads:
//   "odc" (POSIX portable, octal ASCII fields, no padding)
//   "newc" (new portable, hex ASCII fields, 4-byte padded)
const TRAILER_NAME = 'TRAILER!!!';
const MAGIC_LENGTH = 6;

// Each field constant is [byteOffset, byteLength] inside its format's fixed header
const ODC_MAGIC = '070707';
const ODC_HEADER_SIZE = 76;
const ODC_MODE_FIELD = [18, 6];
const ODC_MTIME_FIELD = [48, 11];
const ODC_NAMESIZE_FIELD = [59, 6];
const ODC_FILESIZE_FIELD = [65, 11];

const NEWC_MAGIC_NO_CRC = '070701';
const NEWC_MAGIC_CRC = '070702';
const NEWC_HEADER_SIZE = 110;
const NEWC_MODE_FIELD = [14, 8];
const NEWC_MTIME_FIELD = [46, 8];
const NEWC_FILESIZE_FIELD = [54, 8];
const NEWC_NAMESIZE_FIELD = [94, 8];
const NEWC_PAD_ALIGNMENT = 4;

// File-type bits in the cpio mode field
const S_IFMT = 0o17_0000;
const S_IFDIR = 0o04_0000;
const S_IFREG = 0o10_0000;
const PERMISSIONS_MASK = 0o7777;

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

  while (offset + ODC_HEADER_SIZE <= buffer.length) {
    if (buffer.subarray(offset, offset + MAGIC_LENGTH).toString('binary') !== ODC_MAGIC) {
      return null;
    }

    const mode = parseField(buffer, offset, ODC_MODE_FIELD, 8);
    const mtime = parseField(buffer, offset, ODC_MTIME_FIELD, 8);
    const namesize = parseField(buffer, offset, ODC_NAMESIZE_FIELD, 8);
    const filesize = parseField(buffer, offset, ODC_FILESIZE_FIELD, 8);

    if (![mode, mtime, namesize, filesize].every(value => Number.isFinite(value)) || namesize < 1) {
      return null;
    }

    const nameStart = offset + ODC_HEADER_SIZE;
    const dataStart = nameStart + namesize;
    const dataEnd = dataStart + filesize;

    if (dataEnd > buffer.length) {
      return null;
    }

    const name = buffer.subarray(nameStart, dataStart - 1).toString('utf8');
    if (name === TRAILER_NAME) {
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

  while (offset + NEWC_HEADER_SIZE <= buffer.length) {
    const magic = buffer.subarray(offset, offset + MAGIC_LENGTH).toString('binary');
    if (magic !== NEWC_MAGIC_NO_CRC && magic !== NEWC_MAGIC_CRC) {
      return null;
    }

    const mode = parseField(buffer, offset, NEWC_MODE_FIELD, 16);
    const mtime = parseField(buffer, offset, NEWC_MTIME_FIELD, 16);
    const filesize = parseField(buffer, offset, NEWC_FILESIZE_FIELD, 16);
    const namesize = parseField(buffer, offset, NEWC_NAMESIZE_FIELD, 16);

    if (![mode, mtime, namesize, filesize].every(value => Number.isFinite(value)) || namesize < 1) {
      return null;
    }

    const nameStart = offset + NEWC_HEADER_SIZE;
    const nameEnd = nameStart + namesize;
    // newc pads name and data fields up to a 4-byte boundary.
    const dataStart = alignUp(nameEnd, NEWC_PAD_ALIGNMENT);
    const dataEnd = dataStart + filesize;

    if (dataEnd > buffer.length) {
      return null;
    }

    const name = buffer.subarray(nameStart, nameEnd - 1).toString('utf8');
    if (name === TRAILER_NAME) {
      break;
    }

    entries.push(makeEntry(mode, mtime, name, buffer.subarray(dataStart, dataEnd)));
    offset = alignUp(dataEnd, NEWC_PAD_ALIGNMENT);
  }

  return entries;
}

export function parseCpio(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < MAGIC_LENGTH) {
    return null;
  }

  const magic = buffer.subarray(0, MAGIC_LENGTH).toString('binary');
  if (magic === ODC_MAGIC) {
    return parseOdc(buffer);
  }

  if (magic === NEWC_MAGIC_NO_CRC || magic === NEWC_MAGIC_CRC) {
    return parseNewc(buffer);
  }

  return null;
}
