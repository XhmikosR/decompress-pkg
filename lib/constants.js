// Byte-level layout of the XAR container and of the cpio streams inside its Payload entries

// XAR header layout (28 bytes):
//   0-3   magic "xar!"
//   4-5   header size (uint16 BE)
//   6-7   version (uint16 BE), always 1
//   8-15  TOC length compressed (uint64 BE)
//   16-23 TOC length uncompressed (uint64 BE)
//   24-27 checksum algorithm (uint32 BE)
export const XAR = {
  MAGIC: 'xar!',
  VERSION: 1,
  HEADER_SIZE: 28,
  OFFSET_HEADER_SIZE: 4,
  OFFSET_VERSION: 6,
  OFFSET_TOC_COMPRESSED: 8,
  OFFSET_TOC_UNCOMPRESSED: 16,
  OFFSET_CHECKSUM_ALGORITHM: 24,
};

// CPIO formats found in macOS .pkg Payloads:
//   "odc" (POSIX portable, octal ASCII fields, no padding)
//   "newc" (new portable, hex ASCII fields, 4-byte padded)
// Each *_FIELD is [byteOffset, byteLength] inside the format's fixed header.
const ODC_FIELD_WIDTH = 6;
const ODC_WIDE_FIELD_WIDTH = 11;
const NEWC_FIELD_WIDTH = 8;

export const ODC = {
  MAGIC: '070707',
  HEADER_SIZE: 76,
  FIELD_WIDTH: ODC_FIELD_WIDTH,
  WIDE_FIELD_WIDTH: ODC_WIDE_FIELD_WIDTH,
  MODE_FIELD: [18, ODC_FIELD_WIDTH],
  MTIME_FIELD: [48, ODC_WIDE_FIELD_WIDTH],
  NAMESIZE_FIELD: [59, ODC_FIELD_WIDTH],
  FILESIZE_FIELD: [65, ODC_WIDE_FIELD_WIDTH],
};

export const NEWC = {
  MAGIC_NO_CRC: '070701',
  MAGIC_CRC: '070702',
  HEADER_SIZE: 110,
  FIELD_WIDTH: NEWC_FIELD_WIDTH,
  PAD_ALIGNMENT: 4,
  MODE_FIELD: [14, NEWC_FIELD_WIDTH],
  MTIME_FIELD: [46, NEWC_FIELD_WIDTH],
  FILESIZE_FIELD: [54, NEWC_FIELD_WIDTH],
  NAMESIZE_FIELD: [94, NEWC_FIELD_WIDTH],
};

export const CPIO_TRAILER_NAME = 'TRAILER!!!';

// File-type bits in the cpio mode field
export const S_IFMT = 0o17_0000;
export const S_IFDIR = 0o04_0000;
export const S_IFREG = 0o10_0000;
export const PERMISSIONS_MASK = 0o7777;
