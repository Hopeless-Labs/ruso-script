# Changelog

All notable changes to `ruso-script` (DSL parser + compiler) are documented
here. The format is based on [Keep a Changelog](https://keepachangelog.com/),
and the project aims to follow [Semantic Versioning](https://semver.org/).

## [0.1.0-beta.1] - 2026-05-30

First public beta.

### Added
- `family "…"`, `version "X.Y.Z"`, and `tags [...]` metadata fields.
- `HEAD` / `OPTIONS` HTTP methods and longer duration suffixes.
- A curated set of 8 example checks (two per protocol: HTTP, DNS, TCP, UDP),
  each verified against live Docker targets.
- Header values can now be matched with `regex` (runtime support landed in
  `ruso-runtime` 0.1.0-beta.1).

### Changed
- `mitigation` is a single free-text field; declaring it more than once is a
  compile error (`CompileError::DuplicateMitigation`).
- Hex payloads must be explicit: `payload bytes "…"` (a quoted string is sent
  verbatim as UTF-8, so `"\r\n"` is **not** unescaped to CRLF).

### Security
- The parser rejects pathologically nested input (`if`/`for`/`repeat`/`{}`)
  before handing it to `pest`. Without this, ~46 KiB of nested blocks — well
  under the registry's source cap — overflowed the parser stack and aborted
  the process (uncatchable), which a single hostile publish could trigger.

[0.1.0-beta.1]: https://github.com/Hopeless-Labs/ruso-script/releases/tag/v0.1.0-beta.1
