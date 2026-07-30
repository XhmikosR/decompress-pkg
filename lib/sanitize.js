// Split on both separators so "..\evil" can't bypass the ".." filter on Windows
export function sanitizeEntryPath(name) {
  return name.split(/[/\\]/).filter(p => p && p !== '.' && p !== '..').join('/');
}
