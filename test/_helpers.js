import {Buffer} from 'node:buffer';
import {promisify} from 'node:util';
import zlib from 'node:zlib';
import {
  CPIO_TRAILER_NAME,
  NEWC,
  ODC,
  XAR,
} from '../lib/constants.js';

const deflate = promisify(zlib.deflate);
const gzip = promisify(zlib.gzip);

function padTo(length, alignment) {
  return Buffer.alloc((alignment - (length % alignment)) % alignment);
}

function cpioOdcEntry({name, data = Buffer.alloc(0), mode = 0o10_0644, mtime = 0}) {
  const nameNul = `${name}\0`;
  const formatToOctal = (value, length) => value.toString(8).padStart(length, '0');
  const header = [
    ODC.MAGIC,
    formatToOctal(0, ODC.FIELD_WIDTH), // dev
    formatToOctal(0, ODC.FIELD_WIDTH), // ino
    formatToOctal(mode, ODC.FIELD_WIDTH),
    formatToOctal(0, ODC.FIELD_WIDTH), // uid
    formatToOctal(0, ODC.FIELD_WIDTH), // gid
    formatToOctal(1, ODC.FIELD_WIDTH), // nlink
    formatToOctal(0, ODC.FIELD_WIDTH), // rdev
    formatToOctal(mtime, ODC.WIDE_FIELD_WIDTH),
    formatToOctal(nameNul.length, ODC.FIELD_WIDTH),
    formatToOctal(data.length, ODC.WIDE_FIELD_WIDTH),
  ].join('');

  return Buffer.concat([Buffer.from(header, 'latin1'), Buffer.from(nameNul, 'latin1'), data]);
}

export function buildCpioOdc(entries) {
  const trailer = cpioOdcEntry({name: CPIO_TRAILER_NAME});
  return Buffer.concat([...entries.map(entry => cpioOdcEntry(entry)), trailer]);
}

function cpioNewcEntry({name, data = Buffer.alloc(0), mode = 0o10_0644, mtime = 0}) {
  const nameNul = `${name}\0`;
  const formatToHex = (value, length) => value.toString(16).padStart(length, '0');
  const header = [
    NEWC.MAGIC_NO_CRC,
    formatToHex(0, NEWC.FIELD_WIDTH), // ino
    formatToHex(mode, NEWC.FIELD_WIDTH),
    formatToHex(0, NEWC.FIELD_WIDTH), // uid
    formatToHex(0, NEWC.FIELD_WIDTH), // gid
    formatToHex(1, NEWC.FIELD_WIDTH), // nlink
    formatToHex(mtime, NEWC.FIELD_WIDTH),
    formatToHex(data.length, NEWC.FIELD_WIDTH),
    formatToHex(0, NEWC.FIELD_WIDTH),
    formatToHex(0, NEWC.FIELD_WIDTH),
    formatToHex(0, NEWC.FIELD_WIDTH),
    formatToHex(0, NEWC.FIELD_WIDTH), // devmajor, devminor, rdevmajor, rdevminor
    formatToHex(nameNul.length, NEWC.FIELD_WIDTH),
    formatToHex(0, NEWC.FIELD_WIDTH), // check
  ].join('');
  const headerName = Buffer.concat([Buffer.from(header, 'latin1'), Buffer.from(nameNul, 'latin1')]);

  return Buffer.concat([
    headerName,
    padTo(headerName.length, NEWC.PAD_ALIGNMENT),
    data,
    padTo(data.length, NEWC.PAD_ALIGNMENT),
  ]);
}

export function buildCpioNewc(entries) {
  const trailer = cpioNewcEntry({name: CPIO_TRAILER_NAME});
  return Buffer.concat([...entries.map(entry => cpioNewcEntry(entry)), trailer]);
}

export async function makeXar(xml, heap = Buffer.alloc(0)) {
  const toc = await deflate(Buffer.from(xml));
  const header = Buffer.alloc(XAR.HEADER_SIZE);

  header.write(XAR.MAGIC, 0, 'ascii');
  header.writeUInt16BE(XAR.HEADER_SIZE, XAR.OFFSET_HEADER_SIZE);
  header.writeUInt16BE(XAR.VERSION, XAR.OFFSET_VERSION);
  header.writeBigUInt64BE(BigInt(toc.length), XAR.OFFSET_TOC_COMPRESSED);
  header.writeBigUInt64BE(BigInt(xml.length), XAR.OFFSET_TOC_UNCOMPRESSED);
  header.writeUInt32BE(0, XAR.OFFSET_CHECKSUM_ALGORITHM); // none

  return Buffer.concat([header, toc, heap]);
}

export function xar(body) {
  return `<xar><toc>${body}</toc></xar>`;
}

export function dataXml(length, {offset = 0, encoding = 'application/octet-stream', size, archivedChecksum, extractedChecksum} = {}) {
  return `<data>
    <offset>${offset}</offset>
    <length>${length}</length>
    ${size === undefined ? '' : `<size>${size}</size>`}
    ${archivedChecksum ? `<archived-checksum style="${archivedChecksum.style}">${archivedChecksum.hash}</archived-checksum>` : ''}
    ${extractedChecksum ? `<extracted-checksum style="${extractedChecksum.style}">${extractedChecksum.hash}</extracted-checksum>` : ''}
    <encoding style="${encoding}"/>
  </data>`;
}

export async function pkgWithPayload(payloadBytes, payloadPath = 'Payload') {
  const compressed = await gzip(payloadBytes);
  const dataElement = `<data>
        <offset>0</offset>
        <length>${compressed.length}</length>
        <encoding style="application/octet-stream"/>
      </data>`;

  // Payload may live at the top level or under a Foo.pkg/ component directory.
  const xml = payloadPath.includes('/')
    ? `<xar>
      <toc>
        <file>
          <name>${payloadPath.split('/')[0]}</name>
          <type>directory</type>
          <file>
            <name>Payload</name>
            <type>file</type>
            ${dataElement}
          </file>
        </file>
      </toc>
    </xar>`
    : `<xar>
      <toc>
        <file>
          <name>Payload</name>
          <type>file</type>
          ${dataElement}
        </file>
      </toc>
    </xar>`;

  return makeXar(xml, compressed);
}

export {gzip};
