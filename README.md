# @xhmikosr/decompress-pkg [![npm version](https://img.shields.io/npm/v/@xhmikosr/decompress-pkg?logo=npm&logoColor=fff)](https://www.npmjs.com/package/@xhmikosr/decompress-pkg) [![CI Status](https://img.shields.io/github/actions/workflow/status/XhmikosR/decompress-pkg/ci.yml?branch=main&label=CI&logo=github)](https://github.com/XhmikosR/decompress-pkg/actions/workflows/ci.yml?query=branch%3Amain)

> macOS `.pkg` (XAR archive) decompress plugin

Reads a `.pkg` buffer and returns the archive entries. macOS Installer packages are XAR archives, so this plugin also handles raw XAR files. Only regular files and directories are extracted; hardlinks, symlinks, fifos, and device nodes are skipped.

## Install

```sh
npm install @xhmikosr/decompress-pkg
```

## Usage

```js
import {promises as fs} from 'node:fs';
import decompress from '@xhmikosr/decompress';
import decompressPkg from '@xhmikosr/decompress-pkg';

const data = await fs.readFile('myapp.pkg');
await decompress(data, 'output', {
  plugins: [
    decompressPkg()
  ]
});
```

## API

### decompressPkg()(input)

Returns a `Promise` that resolves to an array of file objects. Returns an empty array if `input` is not a XAR archive (wrong magic bytes or malformed header).

Throws `TypeError` if `input` is not a `Buffer`.

#### input

Type: `Buffer`

Buffer of the `.pkg` file contents.

#### file object

Each entry has the following properties:

- `data` `Buffer` - File contents. Empty `Buffer` for directories.
- `mode` `number` - POSIX mode bits. Defaults to `0o755` when the entry has no `<mode>` or an invalid one.
- `mtime` `Date` - Modification time. Falls back to the Unix epoch when the entry has no `<mtime>` or an invalid one.
- `path` `string` - POSIX path. Directories end with `/`. Path traversal segments (`..`) and both `/` and `\` separators are stripped.
- `type` `string` - Either `'file'` or `'directory'`.

## License

[MIT](LICENSE) © XhmikosR
