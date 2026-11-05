# DKIM Bulk Signature Verifier

![Version](https://img.shields.io/badge/version-1.7.0-blue)
![Build](https://img.shields.io/badge/build-2026--11--05-lightgrey)
![Python](https://img.shields.io/badge/python-3-yellow)
[![License: Apache 2.0](https://img.shields.io/badge/code-Apache%202.0-blue.svg)](LICENSE)
[![License: CC BY 4.0](https://img.shields.io/badge/docs-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)

**Version 1.7.0** (build 2026-11-05)

A forensic triage tool that verifies the **DKIM signatures** of `.eml` files in bulk. For each message it recomputes the body hash, rebuilds the signed header block, verifies the cryptographic signature against the signing domain's public key, and records the outcome in a CSV ledger, with per-message logs, optional extracted artifacts and a folder of preserved public keys.

Built for investigators who need to show whether an email produced as evidence is an unaltered copy of what the signing mail server sent.

---

## Features

- **Bulk processing** of a folder of `.eml` files, with optional recursion into sub-folders
- **Evidence hashing** – MD5 and SHA-256 of every original file
- **Full DKIM verification** – body hash (`bh=`) and signature (`b=`) checks
  - `rsa-sha256` and `rsa-sha1`
  - `simple` and `relaxed` canonicalisation (headers and body), `l=` body length tag
- **Three public-key modes** – live DNS with local fallbacks, 1:1 sidecar key files, or N:1 shared key files
- **Key preservation** – keys retrieved from DNS are saved as `selector._domainkey.domain.key` for offline re-verification
- **Flexible key input** – DNS TXT records, zone-file lines, bare base64, PEM, DER or PKCS#1; revoked keys (empty `p=`) detected
- **Key provenance** – records which source supplied the key, the key file path, and the SHA-256 of the key used
- **Keyword alerts** – optional regex scanning of message bodies, with default fraud/phishing patterns and custom pattern files
- **Forensic artifacts** – canonicalised bodies and reconstructed signed header blocks saved for review
- **GUI or CLI** – Tkinter interface by default, `--no-gui` for scripted runs

---

## Requirements

| Component | Purpose | Notes |
|---|---|---|
| Python 3 | Runtime | |
| [`cryptography`](https://pypi.org/project/cryptography/) | Signature verification and key loading | Required |
| `tkinter` | Graphical interface | Included with most Windows/macOS Python installs; on Linux install `python3-tk`. Not needed with `--no-gui` |
| HTTPS access | Live DNS lookups (Mode 1 only) | Modes 2 and 3 work fully offline |

## Installation

```bash
git clone https://github.com/jjrboucher/DKIM-Validator.git
cd DKIM-Validator
pip install cryptography
```

---

## Usage

### Graphical interface (default)

```bash
python verify_dkim_bulk.py
```

Configure the run in the window, then click **LAUNCH TRIAGE PROCESSING LOOP**. Progress is shown in the console.

| Panel | Option | Default |
|---|---|---|
| Directory Workspace | Source Folder | Current directory |
| | Output Folder | `./forensic_analysis_out` |
| Scan & Output Toggles | Scan recursively | On |
| | Save canonicalised bodies (`bodies/`) | On |
| | Save signed header blocks (`signatures/`) | On |
| Public Key Mapping | Mode 1 / 2 / 3 | Mode 1 |
| | Global Manual Key Fallback (Mode 3 only) – paste or **Load Key File...** | None |
| Keyword Alerts | Enable body keyword flagging | Off |
| | Load Custom Keywords File (.txt) | – |

A status line under the global key button shows whether a key is registered and whether it was pasted or loaded from a file.

Before launching, every keyword pattern is compiled and any invalid regex is reported with its line number. In Mode 3 you are warned if no global key is registered and no `*_domainkey*.key` files are found.

### Command line

```bash
python verify_dkim_bulk.py --no-gui --src <source_folder> --out <output_folder> --mode <1|2|3>
```

| Argument | Description |
|---|---|
| `--no-gui` | Run without the graphical interface |
| `--src` | Folder containing `.eml` files (required with `--no-gui`) |
| `--out` | Output folder (required with `--no-gui`) |
| `--mode {1,2,3}` | Public key mode (required with `--no-gui`) |
| `-h`, `--help` | Show help, version, repository and license |

In CLI mode, recursion, artifact saving and DNS key saving are always **on**, keyword alerts are **off**, and the global manual key is not available.

```bash
# Live DNS with local fallbacks (retrieved keys saved to ./dkim_out/keys)
python verify_dkim_bulk.py --no-gui --src ./eml --out ./dkim_out --mode 1

# Fully offline using shared key files
python verify_dkim_bulk.py --no-gui --src ./eml --out ./dkim_out --mode 3
```

---

## Public key modes

DKIM keys are published at `<selector>._domainkey.<domain>`. Because domains rotate keys, the key that signed an older message may no longer be in DNS, so the tool supports preserved local keys.

| Mode | Key source | Lookup order |
|---|---|---|
| **1** – Live DNS | DNS-over-HTTPS (Google Public DNS) | Memory cache → live DNS → `<EmailName>.key` → `<selector>._domainkey.<domain>.key` |
| **2** – 1:1 sidecar | One key file per email | `<EmailName>.key` in the same folder as the `.eml` |
| **3** – N:1 nomenclature | One key file per selector/domain | `<selector>._domainkey.<domain>.key` in the same folder → global manual key |

```text
evidence/
├── msg001.eml                              (d=example.com; s=selector1)
├── msg002.eml                              (d=example.com; s=selector1)
├── msg003.eml
├── msg003.key                              ← Mode 2: key for msg003 only
└── selector1._domainkey.example.com.key    ← Mode 3: shared by msg001 and msg002
```

### Key preservation (`keys/` folder)

| Source | Saved as | Notes |
|---|---|---|
| Mode 1 – key retrieved from live DNS | `keys/<selector>._domainkey.<domain>.key` | Only DNS keys are saved; local fallback files are not copied |
| Mode 3 – global key **pasted** in the GUI | `keys/global_user_supplied.key` | Saved at launch |
| Mode 3 – global key **loaded from a file** (unedited) | *not copied* | The original file path is recorded in `Key_File_Path` |

- Files contain the key text exactly as used, so each file's SHA-256 matches `Key_SHA256` in the CSV.
- Existing files are **never overwritten**. If a different key is retrieved for a name that already exists, it is saved as `<selector>._domainkey.<domain>.<UTCstamp>.key`.
- Selector/domain values come from the email header. Unsafe characters are replaced with `_`, so a crafted header cannot write outside `keys/`.

> **Tip:** Copy the files from `keys/` next to the `.eml` files and re-run in Mode 3 for repeatable, offline results that don't depend on later key rotation.

> **Privacy note:** Mode 1 sends the selector and domain of each message to a third-party DNS resolver.

---

## Keyword alerts

When enabled, each message body is matched against one regular expression per line. Matches appear in the `Threat_Alerts` CSV column; otherwise the value is `CLEAN`. Alerts do not affect the DKIM result.

Default patterns cover payment/banking, cryptocurrency, credential-phishing and legal/sensitive terms, e.g.:

```text
(?i)(wire transfer|swift|routing number|bank account|invoice)
(?i)(bitcoin|crypto|usdt|wallet phrase|private key)
```

Patterns are matched against the **raw, undecoded** MIME body, so text inside base64 or quoted-printable parts will usually not match.

---

## Output

```text
<output_folder>/
├── dkim_bulk_verification_report.csv        # one row per .eml
├── keys/        <selector>._domainkey.<domain>.key, global_user_supplied.key
├── logs/        <email>_<UTCstamp>.log
├── bodies/      <email>_body_<UTCstamp>.txt
└── signatures/  <email>_dkim_signature_<UTCstamp>.txt
```

- Timestamps are UTC (`YYYYMMDDTHHMMSSZ`).
- The CSV is overwritten on each run to the same output folder; use a new folder per run to keep history.
- Logs and artifacts are written only for messages that reach the signature check. Logs include the key file path and key SHA-256.
- `keys/` is created only when a key is saved.

### CSV columns

| Column | Content |
|---|---|
| `EML_Filename` | Message file name |
| `MD5_Hash`, `SHA256_Hash` | Hashes of the original file |
| `DKIM_Domain`, `DKIM_Selector` | `d=` and `s=` tags |
| `Key_Source_Used` | `CACHE_MEMORY`, `LIVE_DNS_QUERY`, `FALLBACK_SIDECAR_FILE`, `FALLBACK_NOMENCLATURE_FILE`, `SIDECAR_FILE`, `N1_NOMENCLATURE_FILE`, `GLOBAL_USER_SUPPLIED_KEY`, `UNKNOWN` |
| `Key_File_Path` | Key file used (including `keys/` files for DNS and pasted global keys), or `N/A` |
| `Key_SHA256` | SHA-256 of the key text used |
| `Body_Hash_Result` | `MATCH` / `MISMATCH` / `ERROR` |
| `Signature_Result` | `VERIFIED` / `FAILED` / `ERROR` |
| `Overall_Status` | `PASS`, `FAIL`, `UNVERIFIED (No Signature)`, `UNVERIFIED (Missing Public Key)`, `RUNTIME_ERROR (...)` |
| `Threat_Alerts` | Matching patterns or `CLEAN` |

### Interpreting results

| Body hash | Signature | Likely meaning |
|---|---|---|
| MATCH | VERIFIED | Signed headers and body unchanged (**PASS**) |
| MISMATCH | VERIFIED | Body changed after signing (edit, or gateway footer/disclaimer) |
| MATCH | FAILED | Signed header changed, wrong/rotated key, or headers altered on export |
| MISMATCH | FAILED | Message modified, wrong key, or not a faithful copy |

A `FAIL` is not by itself proof of tampering. Mailing lists, security gateways, key rotation and re-encoding exports can all break a signature. Corroborate with other evidence.

---

## Known limitations (v1.7.0)

- Only the **first** `DKIM-Signature` header is verified.
- Header parsing and canonicalisation assume **CRLF** line endings; LF-only `.eml` files may fail.
- **Ed25519** signatures are verified over the raw header block rather than its SHA-256 digest (RFC 8463), so `ed25519-sha256` signatures are likely to report `FAILED`.
- The `x=` (expiry), `t=` (timestamp) and `i=` (identity) tags are not evaluated.
- DNS/network errors are not reported; a failed lookup is treated as "no answer" and the local fallbacks are used.
- No command-line option for a global key.

---

## Documentation

See **`DKIM_Bulk_Verifier_User_Guide_v1.7.0.pdf`** for the full user guide.

## Changelog

| Version | Date | Notes |
|---|---|---|
| 1.7.0 | 2026-11-05 | Mode 1 saves DNS-retrieved keys to `keys/` using the `selector._domainkey.domain.key` nomenclature (never overwrites; timestamped copy if a key changes); Mode 3 saves a GUI-pasted global key to `keys/global_user_supplied.key`; **Load Key File...** button and status line for the global key; fixed the Mode 1 DNS-over-HTTPS URL and parsing of multi-string TXT / CNAME answers; `Key_File_Path` populated for DNS and global keys; logs include key file and key SHA-256; filename sanitisation for header-derived names; Apache 2.0 notice in script header, GUI and `--help` |
| 1.6.2 | 2026-11-05 | Initial documented release |

## License

This project is free to use and is dual-licensed by component:

| Component | License |
|---|---|
| Software (`verify_dkim_bulk.py`) | [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) – see [`LICENSE`](LICENSE) |
| Documentation (`README.md`, user guide PDF) | [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/) |

**Suggested attribution for the documentation:**
*"DKIM Bulk Signature Verifier – User Guide (v1.7.0)" by Jacques Boucher, https://github.com/jjrboucher/DKIM-Validator, licensed under CC BY 4.0.*

## Disclaimer

This software and its documentation are provided **"AS IS", WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND**, express or implied, including any warranties of merchantability, fitness for a particular purpose, accuracy or non-infringement. In no event shall the author be liable for any claim, damages or other liability arising from the use of the tool or its results. Users are responsible for validating results and for the evidential weight they place on them.

## Author

**Jacques Boucher** – jjrboucher@gmail.com
Repository: https://github.com/jjrboucher/DKIM-Validator
