import {Buffer} from 'node:buffer';
import {promisify} from 'node:util';
import zlib from 'node:zlib';

const deflate = promisify(zlib.deflate);
const gzip = promisify(zlib.gzip);

function cpioOdcEntry({name, data = Buffer.alloc(0), mode = 0o10_0644, mtime = 0}) {
  const nameNul = `${name}\0`;
  const formatToOctal = (value, length) => value.toString(8).padStart(length, '0');
  const header = [
    '070707',
    formatToOctal(0, 6), // dev
    formatToOctal(0, 6), // ino
    formatToOctal(mode, 6),
    formatToOctal(0, 6), // uid
    formatToOctal(0, 6), // gid
    formatToOctal(1, 6), // nlink
    formatToOctal(0, 6), // rdev
    formatToOctal(mtime, 11),
    formatToOctal(nameNul.length, 6),
    formatToOctal(data.length, 11),
  ].join('');

  return Buffer.concat([Buffer.from(header, 'binary'), Buffer.from(nameNul, 'binary'), data]);
}

export function buildCpioOdc(entries) {
  const trailer = cpioOdcEntry({name: 'TRAILER!!!'});
  return Buffer.concat([...entries.map(entry => cpioOdcEntry(entry)), trailer]);
}

function cpioNewcEntry({name, data = Buffer.alloc(0), mode = 0o10_0644, mtime = 0}) {
  const nameNul = `${name}\0`;
  const formatToHex = (value, length) => value.toString(16).padStart(length, '0');
  const header = [
    '070701',
    formatToHex(0, 8), // ino
    formatToHex(mode, 8),
    formatToHex(0, 8), // uid
    formatToHex(0, 8), // gid
    formatToHex(1, 8), // nlink
    formatToHex(mtime, 8),
    formatToHex(data.length, 8),
    formatToHex(0, 8),
    formatToHex(0, 8),
    formatToHex(0, 8),
    formatToHex(0, 8), // devmajor, devminor, rdevmajor, rdevminor
    formatToHex(nameNul.length, 8),
    formatToHex(0, 8), // check
  ].join('');
  const headerName = Buffer.concat([Buffer.from(header, 'binary'), Buffer.from(nameNul, 'binary')]);
  const padName = Buffer.alloc((4 - (headerName.length % 4)) % 4);
  const padData = Buffer.alloc((4 - (data.length % 4)) % 4);

  return Buffer.concat([headerName, padName, data, padData]);
}

export function buildCpioNewc(entries) {
  const trailer = cpioNewcEntry({name: 'TRAILER!!!'});
  return Buffer.concat([...entries.map(entry => cpioNewcEntry(entry)), trailer]);
}

export async function makeXar(xml, heap = Buffer.alloc(0)) {
  const toc = await deflate(Buffer.from(xml));
  const header = Buffer.alloc(28);

  header.write('xar!', 0, 'ascii'); // magic
  header.writeUInt16BE(28, 4); // header size
  header.writeUInt16BE(1, 6); // version
  header.writeBigUInt64BE(BigInt(toc.length), 8); // TOC length compressed
  header.writeBigUInt64BE(BigInt(xml.length), 16); // TOC length uncompressed
  header.writeUInt32BE(0, 24); // checksum algorithm (none)

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
