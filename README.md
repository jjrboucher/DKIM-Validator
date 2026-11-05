# DKIM Bulk Signature Verifier

![Version](https://img.shields.io/badge/version-1.7.2-blue)
![Build](https://img.shields.io/badge/build-2026--11--05-lightgrey)
![Python](https://img.shields.io/badge/python-3-yellow)
[![License: Apache 2.0](https://img.shields.io/badge/code-Apache%202.0-blue.svg)](LICENSE)
[![License: CC BY 4.0](https://img.shields.io/badge/docs-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)

**Version 1.7.2** (build 2026-11-05)

A forensic triage tool that verifies the **DKIM signatures** of `.eml` files in bulk. For every signature in every message it recomputes the body hash, rebuilds the signed header block, verifies the cryptographic signature against the signing domain's public key, and evaluates the signature's identity and time tags. Results go to CSV ledgers, with per-message logs, extracted artifacts and a preserved copy of every public key used.

Built for investigators who need to show whether an email produced as evidence is an unaltered copy of what the signing mail server sent.

---

## Features

- **Bulk processing** of a folder of `.eml` files, with optional recursion into sub-folders
- **Evidence hashing** – MD5 and SHA-256 of every original file
- **Every signature verified** – messages with several `DKIM-Signature` headers are fully assessed; the email passes if any signature passes
- **Full DKIM verification** – body hash (`bh=`) and signature (`b=`) checks
  - `rsa-sha256`, `rsa-sha1` (flagged as deprecated) and `ed25519-sha256` (RFC 8463)
  - `simple` and `relaxed` canonicalisation, `l=` body length tag
- **Signature tag evaluation** – `i=` must be within `d=`; `t=` and `x=` reported in UTC for every signature; optional strict expiry
- **Key record evaluation** – key size, testing mode (`t=y`), strict identity (`t=s`), permitted hashes (`h=`), service types (`s=`) and notes (`n=`)
- **Line-ending normalisation** – LF-only and mixed `.eml` files are converted to CRLF in memory before verification (original untouched)
- **Three public-key modes** – live DNS with local fallbacks, 1:1 sidecar key files, or N:1 shared key files
- **Key preservation** – every public key used is saved to `keys/` with a `keys_manifest.csv`
- **Keyword alerts** – optional regex scanning of message bodies
- **Forensic artifacts** – canonicalised bodies and reconstructed signed header blocks, per signature
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
| | Strict Expiry – treat expired signatures (`x=`) as FAIL | Off |
| Public Key Mapping | Mode 1 / 2 / 3 | Mode 1 |
| | Global Manual Key Fallback (Mode 3 only) | None |
| Keyword Alerts | Enable body keyword flagging | Off |
| | Load Custom Keywords File (.txt) | – |

Before launching, every keyword pattern is compiled and any invalid regex is reported with its line number. In Mode 3 you are warned if no global key is registered and no `*_domainkey*.key` files are found.

### Command line

```bash
python verify_dkim_bulk.py --no-gui --src <source_folder> --out <output_folder> --mode <1|2|3> [--strict-expiry]
```

| Argument | Description |
|---|---|
| `--no-gui` | Run without the graphical interface |
| `--src` | Folder containing `.eml` files (required with `--no-gui`) |
| `--out` | Output folder (required with `--no-gui`) |
| `--mode {1,2,3}` | Public key mode (required with `--no-gui`) |
| `--strict-expiry` | Treat signatures whose `x=` expiry has passed as `FAIL (Expired)` |
| `--version` | Print the version and build date |
| `-h`, `--help` | Show help |

In CLI mode, recursion and artifact saving are always **on**, keyword alerts are **off**, and the global manual key is not available.

```bash
# Live DNS with local fallbacks
python verify_dkim_bulk.py --no-gui --src ./eml --out ./dkim_out --mode 1

# Fully offline using shared key files, strict expiry
python verify_dkim_bulk.py --no-gui --src ./eml --out ./dkim_out --mode 3 --strict-expiry
```

---

## Public key modes

DKIM keys are published at `<selector>._domainkey.<domain>`. Because domains rotate keys, the key that signed an older message may no longer be in DNS, so the tool supports preserved local keys. Each signature resolves its own key.

| Mode | Key source | Lookup order |
|---|---|---|
| **1** – Live DNS | DNS-over-HTTPS (`https://dns.google/resolve`) | Memory cache → live DNS → `<EmailName>.key` → `<selector>._domainkey.<domain>.key` |
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

In Mode 1, DNS failures (network error, NXDOMAIN, no TXT record, no `p=` tag) are recorded in the `Notes` column before the local fallbacks are tried, and failed lookups are cached for the run.

> **Privacy note:** Mode 1 sends the selector and domain of each signature to a third-party DNS resolver, and retrieves *today's* key.

### Preserved keys

Every distinct public key used in a run – from DNS, a sidecar file, a nomenclature file or the global key – is saved to `<output>/keys/<selector>._domainkey.<domain>.key` and listed in `keys_manifest.csv`. If the same selector/domain yields different key material in one run (e.g. DNS differs from a local file), both are kept; the second is named `…__<12 hex of SHA-256>.key`. To reproduce a run offline later, copy the `keys/` files next to the emails and use Mode 3.

| Manifest column | Content |
|---|---|
| `Saved_Key_File`, `DNS_Name`, `DKIM_Selector`, `DKIM_Domain` | Saved file and the selector/domain it belongs to |
| `Key_Source_Used`, `Original_Key_File_Path` | Where the key came from |
| `First_Retrieved_UTC`, `Key_SHA256` | When it was obtained and its hash |
| `Key_Type`, `Key_Bits` | `rsa` / `ed25519` and key size (e.g. 1024, 2048, 256) |
| `Key_Testing_Mode` | `YES` if the record has `t=y` |
| `Key_Strict_Identity` | `YES` if the record has `t=s` |
| `Key_Hash_Algs` | `h=` list (e.g. `sha256`), or `ANY` |
| `Key_Service_Types`, `Key_Notes`, `Key_Flags_Raw` | `s=`, `n=` and the raw `t=` value |
| `Times_Used`, `Used_By` | How often it was used, and by which `email#sigN` |

> **Keys do not expire.** A DKIM key record has no expiry field. Expiry (`x=`) belongs to each **signature** and is reported in the signature columns (see [Signature expiry](#signature-expiry)). Domains retire keys by removing them from DNS or publishing an empty `p=` (revoked), which the tool reports.

---

## Messages with multiple DKIM signatures

Messages often carry several `DKIM-Signature` headers – the author's domain, an email service provider, a mailing list or gateway, or the same domain signing with both RSA and Ed25519. **Every signature is examined.** Each one is verified independently with its own key, canonicalisation, `h=` list, body hash and tags. As RFC 6376 requires, a failed signature does not cancel a valid one: the email is `PASS` if at least one signature passes.

- `Sig_Index 1` is the **top** signature (most recently added); the bottom one was usually applied first.
- `dkim_signature_details.csv` has one row per signature; the main CSV adds `Signature_Count`, `Signatures_Passed`, `Signatures_Expired`, `Reported_Signature` and an `All_Signatures` summary.
- Logs have a section per signature, artifacts are suffixed `_sig1`, `_sig2`…, and each signature's key is saved to `keys/`.
- Check **which domain** passed: a pass only for an intermediary (ESP or list) says less about the `From:` sender than a pass for the author's own domain.
- Use **Mode 3** (or Mode 1) for multi-signature messages. Mode 2 tries one sidecar key against every signature, so signatures made with other keys report `FAIL`.

---

## Tag evaluation

### Signature tags

| Tag | Check | Effect |
|---|---|---|
| `i=` | Domain must equal `d=` or be a subdomain of it (RFC 6376 §3.5); exactly `d=` if the key has `t=s` | Otherwise `FAIL (Invalid i= tag)` |
| `t=` | Converted to UTC; flagged if in the future | Log shows offset from the `Date:` header |
| `x=` | Must be later than `t=`; compared with verification time | Invalid → `FAIL (Invalid x= tag)`. Expired → reported; `FAIL (Expired)` only with Strict Expiry |

### Key record tags

| Tag | Effect |
|---|---|
| `t=y` | Testing mode – noted in `Key_Flags` and `Notes`; the result still stands but should carry less weight |
| `t=s` | `i=` must use exactly the `d=` domain |
| `h=` | Signature hash must be in the list, otherwise `FAIL (Key h= does not permit …)` |
| Key size | Reported in `Key_Bits`; RSA keys under 1024 bits are flagged (RFC 8301) |

### Signature expiry

Expiry is recorded for **every** signature, whether or not Strict Expiry is on:

| Where | What |
|---|---|
| `dkim_signature_details.csv` | `Sig_Timestamp_UTC`, `Sig_Expiry_UTC`, `Expiry_Status` per signature |
| Main CSV `All_Signatures` | Each signature's expiry, e.g. `2: d=mailer.example.net s=esp1 a=rsa-sha256 x=2026-10-30 10:20:03Z [EXPIRED] -> PASS` (`x=none` if no expiry) |
| Main CSV `Signatures_Expired` | Number of expired signatures in the email |
| Main CSV expiry columns | Expiry of the reported signature |
| Log | `Signed (t=)` and `Expires (x=) [status]` for each signature |

`Expiry_Status` is one of `NO EXPIRY`, `VALID (not expired)`, `EXPIRED (at verification time)` or `INVALID (...)`.

> Expired is not the same as altered. Many senders set `x=` only days after `t=`, so older evidence is often expired. Keep Strict Expiry off for forensic work.

---

## Keyword alerts

When enabled, each message body is matched against one regular expression per line. Matches appear in the `Threat_Alerts` CSV column; otherwise the value is `CLEAN`. Alerts do not affect the DKIM result.

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
├── dkim_signature_details.csv               # one row per DKIM signature
├── keys_manifest.csv                        # one row per preserved public key
├── keys/        <selector>._domainkey.<domain>.key
├── logs/        <email>_<UTCstamp>.log
├── bodies/      <email>_body[_sigN]_<UTCstamp>.txt
└── signatures/  <email>_dkim_signature[_sigN]_<UTCstamp>.txt
```

- Timestamps are UTC (`YYYYMMDDTHHMMSSZ`); `_sigN` is added when an email has more than one signature.
- All CSVs and `keys/` files are overwritten on each run to the same output folder; use a new folder per run to keep history.
- A log is written for every signed email; it lists each signature, the key record used and its flags, and the `t=` offset from the `Date:` header.

### Main report columns

Where an email has several signatures, the signature-specific columns describe the **reported signature**: the first that passed or, if none passed, the first that could be evaluated.

| Column | Content |
|---|---|
| `EML_Filename`, `MD5_Hash`, `SHA256_Hash` | File name and hashes of the original file |
| `Line_Endings` | `CRLF`, `LF (normalised to CRLF)` or `MIXED (normalised to CRLF)` |
| `Signature_Count`, `Signatures_Passed`, `Signatures_Expired` | Signatures found, passed, and with an expired `x=` |
| `Reported_Signature` | Which signature the following columns describe (e.g. `2 of 2`) |
| `DKIM_Domain`, `DKIM_Selector`, `DKIM_Algorithm` | `d=`, `s=`, `a=` |
| `DKIM_Identity`, `Identity_Check` | `i=` (or the `@d=` default) and whether it is valid |
| `Sig_Timestamp_UTC`, `Sig_Expiry_UTC`, `Expiry_Status` | `t=`, `x=` and expiry state |
| `Key_Source_Used`, `Key_File_Path`, `Key_SHA256` | Where the key came from, local file used, SHA-256 of the key text |
| `Saved_Key_File` | Preserved copy of the key in `keys/` |
| `Key_Bits`, `Key_Flags` | Key size and key record flags (`t=y`, `t=s`, `h=`, `s=`, `n=`), or `NONE` |
| `Body_Hash_Result` | `MATCH` / `MISMATCH` / `ERROR` / `N/A` |
| `Signature_Result` | `VERIFIED` / `FAILED` / `ERROR` / `N/A` |
| `Overall_Status` | See below |
| `All_Signatures` | Every signature with its expiry and status |
| `Threat_Alerts` | Matching patterns or `CLEAN` |
| `Notes` | DNS results, expiry, testing-mode keys, `l=` coverage, deprecated algorithm warnings |

`dkim_signature_details.csv` holds the same per-signature fields plus `Sig_Index`, `Canonicalization` and `Signature_Status`.

### Status values

| `Overall_Status` | Meaning |
|---|---|
| `PASS` | At least one signature passed every check |
| `FAIL` | No signature passed |
| `FAIL (Expired)` | Strict Expiry on; every evaluated signature would pass but has expired |
| `UNVERIFIED (No Signature)` | No `DKIM-Signature` header |
| `UNVERIFIED (Missing Public Key)` | No key found for any signature |
| `RUNTIME_ERROR (...)` | Processing error; reason included |

| `Signature_Status` | Meaning |
|---|---|
| `PASS` | Body hash matches, signature verified, tags and key flags satisfied |
| `FAIL` | Body hash mismatch and/or signature failed |
| `FAIL (Invalid i= tag)` / `FAIL (Invalid x= tag)` | Cryptographically valid but a tag is invalid |
| `FAIL (Key h= does not permit …)` | The key's `h=` list excludes the signature's hash |
| `FAIL (Expired)` | Strict Expiry only |
| `NO_KEY` | No key found for this signature |
| `ERROR (...)` | Could not be evaluated |

### Interpreting results

| Body hash | Signature | Likely meaning |
|---|---|---|
| MATCH | VERIFIED | Signed headers and body unchanged |
| MISMATCH | VERIFIED | Body changed after signing (edit, or gateway footer/disclaimer) |
| MATCH | FAILED | Signed header changed, wrong/rotated key, or headers altered on export |
| MISMATCH | FAILED | Message modified, wrong key, or not a faithful copy |

A `FAIL` is not by itself proof of tampering. Mailing lists, security gateways, key rotation and re-encoding exports can all break a signature. Corroborate with other evidence.

---

## Test packs

### `DKIM_MultiSig_TestPack.zip`

Five messages signed by three parties (bottom to top: `example.org` RSA, `mailer.example.net` RSA with a 7-day `x=`, `lists.example.com` Ed25519) and the three key files. Run with `--mode 3`.

| File | Expected | Passed |
|---|---|---|
| `01_multi_dkim_all_pass.eml` | PASS | 3 of 3 |
| `02_multi_dkim_list_modified.eml` – list tagged Subject, added footer, re-signed | PASS | 1 of 3 |
| `03_multi_dkim_body_tampered.eml` – amount changed | FAIL | 0 of 3 |
| `04_multi_dkim_LF_line_endings.eml` – LF-only copy of 01 | PASS | 3 of 3 |
| `05_multi_dkim_from_header_altered.eml` – From domain altered | FAIL | 0 of 3 |

### `DKIM_Expiry_TestPack.zip`

Eight messages with expired, valid and absent `x=` tags, and three key files: `example.org` (RSA 2048, `h=sha256`), `mailer.example.net` (RSA 1024, `t=y`, `n=` note) and `lists.example.com` (Ed25519). Run with `--mode 3`, then again with `--strict-expiry`.

| File | Signatures (top to bottom) | Default | Strict Expiry |
|---|---|---|---|
| `01_single_rsa_expired.eml` | RSA, expired | PASS (1/1) | FAIL (Expired) |
| `02_single_ed25519_expired.eml` | Ed25519, expired | PASS (1/1) | FAIL (Expired) |
| `03_single_rsa_not_expired_control.eml` | RSA, valid to 2027 | PASS (1/1) | PASS (1/1) |
| `04_single_expired_and_tampered.eml` | RSA, expired; amount altered | FAIL | FAIL |
| `05_multi_2sig_one_expired.eml` | ESP expired; author no `x=` | PASS (2/2) | PASS (1/2) |
| `06_multi_2sig_both_expired.eml` | ESP expired; author expired | PASS (2/2) | FAIL (Expired) |
| `07_multi_3sig_mixed.eml` | List valid; ESP expired; author no `x=` | PASS (3/3) | PASS (2/3) |
| `08_multi_only_expired_sig_verifies.eml` | ESP valid but Reply-To altered; author expired | PASS (1/2) | FAIL |

Sample 08 shows why Strict Expiry should stay off for forensic work: the only signature that still verifies is the expired one.

---

## Known limitations (v1.7.2)

- **Mode 2 with several signatures:** the single sidecar key is tried against every signature; signatures made with other keys report `FAIL`. Use Mode 3 for multi-signature messages.
- The keyword scan runs on the raw, undecoded body.
- The Mode 3 GUI pre-check only looks at the top level of the source folder.
- DMARC/SPF, From-domain alignment and whether `h=` includes `From` are not assessed.

---

## Documentation

See **`DKIM_Bulk_Verifier_User_Guide_v1.7.2.pdf`** for the full user guide.

## Changelog

### 1.7.2 – 2026-11-05
- **Added:** `All_Signatures` shows each signature's `x=` expiry and state; new `Signatures_Expired` column.
- **Added:** key record evaluation – `Key_Bits` and `Key_Flags` columns; `keys_manifest.csv` gains `Key_Bits`, `Key_Testing_Mode`, `Key_Strict_Identity`, `Key_Hash_Algs`, `Key_Service_Types`, `Key_Notes`, `Key_Flags_Raw`.
- **Added:** key flags enforced – `t=s` (exact `i=` domain) and `h=` (permitted hashes); `t=y` keys noted; RSA keys under 1024 bits flagged.
- **Changed:** log shows key size and flags, and the number of expired signatures; files processed in sorted order.
- **Docs:** signature expiry section; expiry test pack.

### 1.7.1 – 2026-11-05
- **Added:** every public key used is preserved in `keys/` with `keys_manifest.csv`; new `Saved_Key_File` column; `Key Preserved As` line in logs.
- **Changed:** key and DNS caches reset at the start of each run.
- **Docs:** guide section on messages with multiple DKIM signatures; multi-signature test pack.

### 1.7.0 – 2026-11-05
- **Fixed:** Mode 1 DNS-over-HTTPS URL; DNS errors reported in `Notes`; failed lookups cached; multi-string TXT records joined.
- **Added:** verification of **all** `DKIM-Signature` headers; `dkim_signature_details.csv`; signature count/summary columns.
- **Fixed:** LF-only and mixed line endings normalised to CRLF; new `Line_Endings` column.
- **Fixed:** Ed25519 signatures verified over the SHA-256 digest of the signed header block (RFC 8463).
- **Added:** `i=`, `t=` and `x=` evaluation; Strict Expiry option (GUI and `--strict-expiry`); `Notes` column; `--version`.

### 1.6.2 – 2026-11-05
- Initial documented release.

---

## License

This project is free to use and is licensed by component:

| Component | License |
|---|---|
| Software (`verify_dkim_bulk.py`) | [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) – see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) |
| Documentation (`README.md`, user guide PDF) | [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/) |

**Suggested attribution for the documentation:**
*"DKIM Bulk Signature Verifier – User Guide (v1.7.2)" by Jacques Boucher, https://github.com/jjrboucher/DKIM-Validator, licensed under CC BY 4.0.*

## Disclaimer

This software and its documentation are provided **"AS IS", WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND**, express or implied, including any warranties of merchantability, fitness for a particular purpose, accuracy or non-infringement. In no event shall the author be liable for any claim, damages or other liability arising from the use of the tool or its results. Users are responsible for validating results and for the evidential weight they place on them.

## Author

**Jacques Boucher** – jjrboucher@gmail.com
Repository: https://github.com/jjrboucher/DKIM-Validator
