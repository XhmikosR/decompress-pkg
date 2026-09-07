import {Buffer} from 'node:buffer';
import path from 'node:path';
import {promisify} from 'node:util';
import zlib from 'node:zlib';
import {parseCpio} from './cpio.js';
import {sanitizeEntryPath} from './sanitize.js';

const gunzip = promisify(zlib.gunzip);

const PAYLOAD_PATH = /(?:^|\/)Payload$/;

export function isPayloadPath(filePath) {
  return PAYLOAD_PATH.test(filePath);
}

function cpioEntryToFile(entry, parentPath) {
  const safeName = sanitizeEntryPath(entry.name);
  if (!safeName) {
    return null;
  }

  // AppleDouble sidecars (`._file`) are macOS resource forks, not real files
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
      // Detach the slice from the gunzipped buffer so the parent can be released
      data: Buffer.from(entry.data),
      mode: entry.permissions || 0o644,
      mtime,
      path: fullPath,
      type: 'file',
    };
  }

  // Skip symlinks, fifos, character/block devices
  return null;
}

export async function unpackPayload(payloadEntry, maxPayloadSize) {
  let cpioBuffer;
  try {
    cpioBuffer = await gunzip(payloadEntry.data, {maxOutputLength: maxPayloadSize});
  } catch (error) {
    // A non-gzip Payload falls through intact, but an oversized one would come
    // back as an opaque blob looking unpacked
    if (error.code === 'ERR_BUFFER_TOO_LARGE') {
      throw new Error(
        `payload at ${payloadEntry.path} inflates past maxPayloadSize (${maxPayloadSize} bytes)`,
        {cause: error},
      );
    }

    return null;
  }

  const cpioEntries = parseCpio(cpioBuffer);
  if (!cpioEntries) {
    return null;
  }

  // Component pkgs nest payloads as `Foo.pkg/Payload`; rebase under that parent
  const parent = path.posix.dirname(payloadEntry.path);
  const parentPath = parent === '.' ? '' : parent;

  return cpioEntries
    .map(entry => cpioEntryToFile(entry, parentPath))
    .filter(file => file !== null);
}
