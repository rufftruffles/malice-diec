# malice/diec

[![Docker Repository on Quay](https://quay.io/repository/malice/diec/status "Docker Repository on Quay")](https://quay.io/repository/malice/diec)

`malice/diec` is a [malice](https://github.com/maliceio/malice) scan engine that
runs [Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) v3.21 (`diec`,
the command-line detector) to identify a file's format and any packer/protector
it is built with.

Detect-It-Easy identifies ALL file formats (PE, ELF, Mach-O, archives, documents,
...) — it is not PE-only. The engine is a thin Go wrapper that shells out to the
prebuilt native Linux `diec` CLI, parses its `--json` output, and stores a
curated result in Elasticsearch under `plugins.exe.diec`.

## Engine

- **Backend:** Detect-It-Easy v3.21 `diec` (prebuilt native Qt5 Linux binary —
  the Linux build is C++/Qt, not .NET; the .NET description applies to the
  Windows/macOS builds).
- **Base image:** `ubuntu:20.04` (focal) — the exact target the prebuilt binary
  is built for (it links against focal's `libicu66` / `libdouble-conversion` /
  `libpcre2-16` sonames). The tarball is checksum-pinned in the Dockerfile.
- **Category:** `exe`
- **MIME:** `*` (all file types)

## Result document (`plugins.exe.diec`)

```json
{
  "filetype": "ELF64",
  "found": true,
  "status": "ok",
  "packed": false,
  "packers": [],
  "values": [
    { "name": "GCC", "type": "compiler", "version": "(GNU) 14.3.1 ...", "string": "Compiler: GCC(...)", "info": "" },
    { "name": "GLIBC", "type": "library", "version": "2.34", "string": "Library: GLIBC(2.34)[EXEC AMD64-64]", "info": "EXEC AMD64-64" }
  ],
  "info": { "Architecture": "AMD64", "Endianness": "LE", "File type": "ELF64", "MIME": "application/x-elf", "...": "..." },
  "entropy": { "max": 5.24, "packed": false, "records": [ { "entropy": 2.66, "name": "PT_LOAD(0)", "offset": 0, "size": 1560, "status": "not packed" } ] },
  "markdown": "#### DIEC\n..."
}
```

- `filetype` — primary identified file type (`detects[0].filetype`).
- `found` — diec identified the file (at least one detect).
- `status` — `ok` on success, or a short error/no-match description.
- `packed` / `packers` — true / names when a packer or protector signature matched.
- `values` — every detected value (compiler, library, packer, protector, tool, ...).
- `info` — file metadata from `diec --json -i` (architecture, endianness, MIME, ...).
- `entropy` — per-section entropy from `diec --json -e` (curated: max + records,
  capped at 1000 records).
- `markdown` — human-readable summary rendered by the malice UI.

The engine always writes a document (even `found:false` on error / no-match /
non-applicable input) so a scan is never left unwritten.

## Build

```
docker build --build-context pkgs=../malice-plugins -t malice/diec:latest .
```

## Usage

```
diec-scan [OPTIONS] <sha256>
  -t, --table          output as Markdown table
  -V, --verbose        verbose output
      --elasticsearch  elasticsearch url (env MALICE_ELASTICSEARCH_URL)
      --timeout        malice plugin timeout in seconds (env MALICE_TIMEOUT)
```
