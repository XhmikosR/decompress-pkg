# @xhmikosr/decompress-pkg [![npm version](https://img.shields.io/npm/v/@xhmikosr/decompress-pkg?logo=npm&logoColor=fff)](https://www.npmjs.com/package/@xhmikosr/decompress-pkg) [![CI Status](https://img.shields.io/github/actions/workflow/status/XhmikosR/decompress-pkg/ci.yml?branch=main&label=CI&logo=github)](https://github.com/XhmikosR/decompress-pkg/actions/workflows/ci.yml?query=branch%3Amain)

> macOS `.pkg` (XAR + cpio) decompress plugin

Reads a `.pkg` buffer and returns the archive entries. A macOS Installer package is a XAR shell whose actual contents live in a gzip-compressed cpio archive named `Payload`. This plugin unwraps the XAR and, when present, expands the `Payload` so callers receive the real installer files instead of the opaque archive blob. Both cpio variants found in `.pkg` files are supported: `odc` (POSIX portable, octal headers) and `newc` (new portable, hex headers). Raw XAR files without a `Payload` are also handled.

Only regular files and directories are extracted; hardlinks, symlinks, fifos, device nodes, and macOS AppleDouble sidecars (`._file`) are skipped.

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

### decompressPkg(options?)(input)

Returns a `Promise` that resolves to an array of file objects. Returns an empty array if `input` is not a XAR archive (wrong magic bytes or malformed header).

Throws `TypeError` if `input` is not a `Buffer`, or if an option is not a positive safe integer.

A `Payload` entry that fails to gunzip, or whose decompressed contents are not a recognized cpio stream, is returned as-is rather than dropped so the plugin stays useful for non-installer XAR files. A `Payload` that gunzips correctly but exceeds `maxPayloadSize` throws instead, since returning the opaque blob would look like a successful extraction.

#### input

Type: `Buffer`

Buffer of the `.pkg` file contents.

#### options

Ceilings on how much data zlib may produce, so that a crafted archive cannot inflate a few KB into an out-of-memory crash. Exceeding one throws; the error from a zlib cap has `code: 'ERR_BUFFER_TOO_LARGE'`. The defaults are far above any real `.pkg`, so raise them only for archives you trust.

##### options.maxTocSize

* Type: `number`
* Default: `67108864` (64 MiB)

Cap on the inflated XAR table of contents. The header's own uncompressed TOC length is used instead when it is smaller. Real TOCs are kilobytes: a `.pkg` keeps its file list in the cpio `Payload`, not here.

##### options.maxFileSize

* Type: `number`
* Default: `4294967296` (4 GiB)

Cap on a single inflated XAR heap entry. An entry's `<size>` is used instead when it is smaller, and an entry that declares no `<size>` is bounded by this alone.

##### options.maxPayloadSize

* Type: `number`
* Default: `4294967296` (4 GiB)

Cap on the unpacked cpio `Payload`. Nothing in the archive declares this size up front, so it is the only bound available.

#### file object

Each entry has the following properties:

- `data` `Buffer` - File contents. Empty `Buffer` for directories.
- `mode` `number` - POSIX mode bits. Defaults to `0o755` when the entry has no `<mode>` or an invalid one.
- `mtime` `Date` - Modification time. Falls back to the Unix epoch when the entry has no `<mtime>` or an invalid one.
- `path` `string` - POSIX path. Directories end with `/`. Path traversal segments (`..`) and both `/` and `\` separators are stripped. Entries unpacked from a `Component.pkg/Payload` are rebased under `Component.pkg/`.
- `type` `string` - Either `'file'` or `'directory'`.

## License

[MIT](LICENSE) © XhmikosR
