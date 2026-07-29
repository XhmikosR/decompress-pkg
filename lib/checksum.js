import crypto from 'node:crypto';

// Reads {style, hash} out of e.g. <archived-checksum style="sha1">abc123</archived-checksum>
export function parseChecksum(child) {
  if (!child || typeof child !== 'object') {
    return null;
  }

  const style = child.$?.style;
  const hash = child['#text'];

  if (!style || typeof hash !== 'string' || !hash) {
    return null;
  }

  return {style, hash};
}

// style="none" and algorithms Node doesn't implement are skipped rather than
// fatal, so a newer XAR still extracts
export function validateChecksum(data, {style, hash}, label) {
  if (style === 'none') {
    return;
  }

  let actual;
  try {
    actual = crypto.createHash(style).update(data).digest('hex');
  } catch {
    return;
  }

  if (actual !== hash.toLowerCase()) {
    throw new Error(`${label} mismatch: expected ${hash.toLowerCase()}, got ${actual}`);
  }
}
