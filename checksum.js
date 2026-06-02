import crypto from 'node:crypto';

// Extracts {style, hash} from a parsed XML element that has both an attribute
// and text content, e.g. <archived-checksum style="sha1">abc123</archived-checksum>.
// Returns null when the element is absent, malformed, or has no hash value.
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

// Validates data against a {style, hash} checksum object.
// Silently skips style="none" and any unrecognised algorithm (forward-compat).
// Throws Error on mismatch.
export function validateChecksum(data, {style, hash}, label) {
  if (style === 'none') {
    return;
  }

  let actual;
  try {
    actual = crypto.createHash(style).update(data).digest('hex');
  } catch {
    return; // Unknown algorithm, skip validation
  }

  if (actual !== hash.toLowerCase()) {
    throw new Error(`${label} mismatch: expected ${hash.toLowerCase()}, got ${actual}`);
  }
}
