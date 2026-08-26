# ati -- Universal CTF Artifact & Binary Triage Engine

**Author: [dev-joshua-py](https://github.com/dev-joshua-py)** · License: MIT

A zero-dependency, CLI-based triage engine for arbitrary files: raw binaries,
disk images, PCAPs, executables, media, and archives. Pure Python standard
library (3.10+; optional Zstandard support on 3.14). Nothing to install.

## What this tool is

`ati` answers four questions about any file you point it at:

1. **What is it, really?** -- magic-byte + deep structural identification
2. **What's hiding inside it?** -- embedded archives, appended payloads, metadata/EXIF
3. **Which parts are packed or encrypted?** -- Shannon entropy mapping
4. **Does it leak anything interesting?** -- flags, credentials, keys, URLs, IPs

It is a *read-only* inspector: it never executes the file under analysis and
contains no offensive capability. Think `binwalk` + `strings` + `exiftool`
glued together with an interactive terminal UI.

```
   _   _ _____ _____   _____ ___ _   _ ___ ____  _____ ____
  /_\ | |_   _|_ _\ \ / /_ _/ __| | | |_ _|  _ \|_   _/ ___|
 / _ \| | | |  | | \ V / | |\__ \ |_| || || |_) | | |\___ \
/_/ \_\_| |_| |___| \_/  |___|___/\___/|___| .__/ |_| |___/
           universal artifact & binary triage        
```

## Safety, legality & responsible use

- **This tool only reads and parses files.** It does not execute, exploit,
  infect, or modify anything it analyzes, and it ships zero malicious code.
- It is built for **CTF competitions, malware-analysis coursework, forensics
  practice and authorized security testing** -- the same category as binwalk,
  ExifTool or `strings`.
- All bundled sample artifacts under `samples/` are **synthetically generated**
  (`tools/make_samples.py`): every IP is RFC1918/documentation space, every
  domain uses IANA-reserved `.example`/`.local` names, every key/token/flag is
  fake. Nothing in this repository is a real indicator of compromise.
- Only use `ati` on files you are legally permitted to analyze. The author is
  not responsible for misuse.

## Capabilities

| # | Capability | Module |
|---|------------|--------|
| 1 | Multi-format identification via 45+ magic signatures + deep structural parsing (ZIP/OOXML/JAR/APK, GZIP, TAR, PNG+chunks+tEXt, JPEG+EXIF/GPS, ELF, PE, Mach-O, PCAP/PCAPNG, RIFF/WAVE/AVI/WEBP, MP4, SQLite, PDF, ISO9660...) | `ati/identify.py` |
| 2 | Embedded content carving with per-format length measurement and recursive archive extraction (depth + byte-budget capped) | `ati/carver.py` |
| 3 | Shannon entropy profiling, sliding-window ASCII graphs, suspicious-region detection | `ati/entropy.py` |
| 4 | String extraction (ASCII + UTF-16LE) against a pattern DB: CTF flags, credentials, AWS keys, JWTs, private keys, IPs, URLs, validated Base64, paths, SQL, PowerShell | `ati/intel.py` |
| 5 | Interactive TUI: hex viewer w/ highlights, section navigator, strings filter, one-key export | `ati/tui.py` |

## Quick start

```text
python ati.py FILE                     full triage report (default command)
python ati.py info FILE                format ID + structural details + hashes
python ati.py entropy FILE [-w 1024]   entropy graph + suspicious regions
python ati.py strings FILE [-n 5]      extract strings (add --no-wide to skip UTF-16)
python ati.py find FILE [--json OUT]   pattern intelligence findings
python ati.py carve FILE [-o DIR]      extract embedded objects (recursive)
python ati.py hex FILE [--off N]       static hex dump
python ati.py tui FILE                 interactive terminal UI
```

Global flags: `--no-color`. Files default-report when the first argument is not
a known command. Exit codes: `0` ok, `1` runtime error, `2` usage error.

## Examples

```text
python ati.py samples/image_payload.png
python ati.py --no-color entropy samples/packed_stub.exe.bin -w 512
python ati.py find samples/capture.pcap --min-severity high
python ati.py carve samples/nested.tar.gz          # gz -> tar -> zip -> flag
```

Carving writes `<file>_carved/` with numbered artifacts (`001_off_<hex>_<fmt>`)
and extracts archive members into sibling `.d/` directories, recursing up to
`--depth 3` under a 256 MB budget.

## Interactive TUI keys

```text
1..6 / Tab   switch view (Overview Entropy Hex Strings Findings Carve)
up/down      move cursor or scroll hex        pgup/pgdn, home/end  paging
/            filter strings & findings        :        jump hex view to offset
n            (Findings) jump hit into Hex     x / a    (Carve) export selected/all
h or ?       help overlay                     q / esc  quit
```

## JSON reporting

`report --json PATH` writes identification details, hashes, entropy regions,
the embedded-object manifest, and all findings. `find --json PATH` exports
findings only.

## Development

```text
python -m unittest discover -s tests -v    # 42-test suite, no network needed
python tools/make_samples.py samples       # regenerate demo artifacts
```

Module layout: `identify` -> `carver` -> `report`; `intel`, `entropy`,
`hexview` are shared by both the CLI and the TUI. The TUI separates pure view
builders from key input, so it is unit-tested headlessly.

## Credits

Built by **[dev-joshua-py](https://github.com/dev-joshua-py)**.
Inspired by classic triage tooling (binwalk, ExifTool, Detect It Easy).

