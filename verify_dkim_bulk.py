#!/usr/bin/env python3
# DKIM Bulk Signature Verifier
# Copyright 2026 Jacques Boucher
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Repository: https://github.com/jjrboucher/DKIM-Validator
"""
DKIM Bulk Signature Verifier with Advanced Forensic Toggles, Target Controls, and Regex Validation.

v1.7.2 changes
  * All_Signatures summary now shows each signature's x= expiry and expiry state.
  * New Signatures_Expired column in the main report.
  * Key record flags parsed and reported: key size (bits), t=y (testing mode), t=s (strict
    identity), h= (permitted hashes), s= (service types), n= (notes). New Key_Bits and
    Key_Flags columns; keys_manifest.csv extended accordingly.
  * Key flags enforced per RFC 6376: t=s requires i= to use exactly the d= domain; a key h=
    list restricts the hash algorithms the key may be used with. Testing-mode keys are noted.

v1.7.1 changes
  * Every public key used is preserved in the output keys/ folder as
    <selector>._domainkey.<domain>.key, with keys_manifest.csv recording source, retrieval time,
    SHA-256 and the emails/signatures that used each key. New Saved_Key_File column.

v1.7.0 changes
  * Mode 1 live DNS: corrected DNS-over-HTTPS URL; lookup errors reported; negative results cached;
    multi-string TXT records joined.
  * All DKIM-Signature headers are verified; per-signature details in dkim_signature_details.csv.
  * LF-only and mixed line endings normalised to CRLF (working copy only) before verification.
  * Ed25519 (ed25519-sha256, RFC 8463) verified over the SHA-256 digest of the signed header block.
  * t= (timestamp), x= (expiry) and i= (identity) tags evaluated; optional strict expiry mode.
"""
import argparse
import base64
import csv
import datetime
import email.utils
import hashlib
import json
import os
import re
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request

try:
    from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_public_key
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.exit("The 'cryptography' package is required: pip install cryptography")

# Tool Metadata
__version__ = "1.7.2"
BUILD_DATE = "2026-11-05"
__tool_name__ = "DKIM Bulk Signature Verifier"
__author__ = "Jacques Boucher"
__email__ = "jjrboucher@gmail.com"
__repository__ = "https://github.com/jjrboucher/DKIM-Validator"

LATIN1 = "latin-1"
DOH_ENDPOINT = "https://dns.google/resolve"
DNS_TIMEOUT = 5

# Default Forensic Tactical Alerts Mapping
DEFAULT_KEYWORDS = [
    r'(?i)(wire transfer|swift|routing number|bank account|invoice)',
    r'(?i)(bitcoin|crypto|usdt|wallet phrase|private key)',
    r'(?i)(password reset|verify your account|login expired|microsoft team)',
    r'(?i)(subpoena|warrant|investigation|court notice|classified)'
]

KEY_MEMORY_CACHE = {}        # selector._domainkey.domain -> TXT record text
DNS_NEGATIVE_CACHE = {}      # selector._domainkey.domain -> reason the lookup failed
SAVED_KEYS = {}              # (selector._domainkey.domain, key sha256) -> manifest record

CSV_HEADERS = [
    "EML_Filename", "MD5_Hash", "SHA256_Hash", "Line_Endings",
    "Signature_Count", "Signatures_Passed", "Signatures_Expired", "Reported_Signature",
    "DKIM_Domain", "DKIM_Selector", "DKIM_Algorithm", "DKIM_Identity",
    "Identity_Check", "Sig_Timestamp_UTC", "Sig_Expiry_UTC", "Expiry_Status",
    "Key_Source_Used", "Key_File_Path", "Key_SHA256", "Saved_Key_File", "Key_Bits", "Key_Flags",
    "Body_Hash_Result", "Signature_Result", "Overall_Status",
    "All_Signatures", "Threat_Alerts", "Notes"
]

DETAIL_HEADERS = [
    "EML_Filename", "SHA256_Hash", "Sig_Index", "DKIM_Domain", "DKIM_Selector",
    "DKIM_Algorithm", "Canonicalization", "DKIM_Identity", "Identity_Check",
    "Sig_Timestamp_UTC", "Sig_Expiry_UTC", "Expiry_Status",
    "Key_Source_Used", "Key_File_Path", "Key_SHA256", "Saved_Key_File", "Key_Bits", "Key_Flags",
    "Body_Hash_Result", "Signature_Result", "Signature_Status", "Notes"
]

MANIFEST_HEADERS = [
    "Saved_Key_File", "DKIM_Selector", "DKIM_Domain", "DNS_Name", "Key_Source_Used",
    "Original_Key_File_Path", "First_Retrieved_UTC", "Key_SHA256", "Key_Type", "Key_Bits",
    "Key_Testing_Mode", "Key_Strict_Identity", "Key_Hash_Algs", "Key_Service_Types", "Key_Notes",
    "Key_Flags_Raw", "Times_Used", "Used_By"
]


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------
def _record_text(blob):
    """Strip zone-file prefix and join quoted TXT chunks."""
    text = blob.strip()
    text = re.sub(r'(?im)^\s*\S+\s+(?:\d+\s+)?(?:IN\s+)?TXT\s+', '', text)
    chunks = re.findall(r'"([^"]*)"', text)
    return "".join(chunks) if chunks else text


def extract_key_material(blob):
    if not blob or not blob.strip():
        raise ValueError("No key material supplied.")
    text = blob.strip()
    if "BEGIN PUBLIC KEY" in text or "BEGIN RSA PUBLIC KEY" in text:
        return "pem", text
    text = _record_text(text)
    m = re.search(r'(?:^|;)\s*k\s*=\s*([A-Za-z0-9]+)', text)
    key_type = m.group(1).lower() if m else None
    m = re.search(r'(?:^|;)\s*p\s*=\s*([A-Za-z0-9+/=\s]*)', text)
    if m:
        b64 = m.group(1)
        if not b64.strip():
            raise ValueError("The record contains an empty 'p=' tag indicating revocation.")
    else:
        b64 = text
    b64 = re.sub(r'\s+', '', b64)
    return key_type, b64


def parse_key_record(blob):
    """Return the tags of a DKIM key record (lower-case names). Empty for PEM / bare base64 keys."""
    if not blob or "BEGIN" in blob:
        return {}
    text = _record_text(blob)
    if not re.search(r'(?:^|;)\s*p\s*=', text):
        return {}
    tags = {}
    for part in text.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def key_flag_info(tags):
    """Interpret key record flags. Returns dict of readable values."""
    t_flags = [f.strip().lower() for f in tags.get("t", "").split(":") if f.strip()]
    h_algs = [a.strip().lower() for a in tags.get("h", "").split(":") if a.strip()]
    info = {
        "testing": "y" in t_flags,
        "strict": "s" in t_flags,
        "hash_algs": h_algs,
        "services": tags.get("s", ""),
        "notes": tags.get("n", ""),
        "raw_t": tags.get("t", ""),
    }
    parts = []
    if info["testing"]:
        parts.append("t=y (testing mode)")
    if info["strict"]:
        parts.append("t=s (strict identity)")
    if h_algs:
        parts.append("h=" + ":".join(h_algs))
    if info["services"] and info["services"] != "*":
        parts.append("s=" + info["services"])
    if info["notes"]:
        parts.append("n=" + info["notes"])
    info["summary"] = "; ".join(parts) if parts else "NONE"
    return info


def load_public_key(blob, algo_hint=None):
    """Return (key_object, note). algo_hint is the a= tag, used when the record has no k= tag."""
    key_type, material = extract_key_material(blob)
    if key_type == "pem":
        return load_pem_public_key(material.encode()), "Parsed as PEM."
    try:
        der = base64.b64decode(material, validate=True)
    except Exception as exc:
        raise ValueError(f"Key data is not valid base64: {exc}")
    if key_type == "ed25519" or (key_type is None and len(der) == 32 and
                                 (algo_hint or "").lower().startswith("ed25519")):
        return ed25519.Ed25519PublicKey.from_public_bytes(der), "Parsed as Ed25519 raw public key."
    try:
        return load_der_public_key(der), "Parsed as DER SubjectPublicKeyInfo."
    except Exception:
        pass
    pem = ("-----BEGIN RSA PUBLIC KEY-----\n" + "\n".join(textwrap.wrap(material, 64)) +
           "\n-----END RSA PUBLIC KEY-----\n")
    return load_pem_public_key(pem.encode()), "Parsed as PKCS#1 RSAPublicKey."


def key_bits(key_obj):
    if isinstance(key_obj, rsa.RSAPublicKey):
        return str(key_obj.key_size)
    if isinstance(key_obj, ed25519.Ed25519PublicKey):
        return "256"
    return "N/A"


def query_dns_key(domain, selector):
    """Query the DKIM TXT record over DNS-over-HTTPS. Returns (record_text or None, note)."""
    name = f"{selector}._domainkey.{domain}"
    url = f"{DOH_ENDPOINT}?name={urllib.parse.quote(name)}&type=TXT"
    try:
        req = urllib.request.Request(url, headers={'Accept': 'application/dns-json',
                                                   'User-Agent': f"{__tool_name__}/{__version__}"})
        with urllib.request.urlopen(req, timeout=DNS_TIMEOUT) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.URLError as exc:
        return None, f"DNS lookup failed for {name}: network error ({exc.reason})"
    except Exception as exc:
        return None, f"DNS lookup failed for {name}: {exc}"

    status = data.get("Status")
    if status == 3:
        return None, f"DNS: {name} does not exist (NXDOMAIN)"
    if status not in (0, None):
        return None, f"DNS: query for {name} returned RCODE {status}"

    records = []
    for ans in data.get("Answer", []):
        if ans.get("type") != 16:
            continue
        raw = ans.get("data", "")
        chunks = re.findall(r'"([^"]*)"', raw)
        records.append("".join(chunks) if chunks else raw.strip().strip('"'))
    if not records:
        return None, f"DNS: no TXT record published at {name}"
    dkim_records = [r for r in records if re.search(r'(?:^|;)\s*p\s*=', r)]
    if not dkim_records:
        return None, f"DNS: TXT record(s) at {name} contain no p= tag"
    note = f"DNS: key retrieved from {name}"
    if len(dkim_records) > 1:
        note += f" ({len(dkim_records)} key records published; first used)"
    return dkim_records[0], note


def preserve_key(output_root, domain, selector, key_blob, source, key_path, eml_name, sig_index):
    """Save the key used for a signature to <output>/keys/ (once per distinct key) and track its use.
    Returns the saved file name relative to the output folder."""
    dns_name = f"{selector}._domainkey.{domain}"
    sha = hashlib.sha256(key_blob.encode(LATIN1, errors="replace")).hexdigest()
    rec = SAVED_KEYS.get((dns_name, sha))
    if rec is None:
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', dns_name)
        k_dir = os.path.join(output_root, "keys")
        os.makedirs(k_dir, exist_ok=True)
        clash = any(n == dns_name for n, _ in SAVED_KEYS)
        fname = f"{safe}__{sha[:12]}.key" if clash else f"{safe}.key"
        with open(os.path.join(k_dir, fname), "w", encoding="utf-8", newline="\n") as kf:
            kf.write(key_blob.strip() + "\n")
        try:
            k_type = extract_key_material(key_blob)[0] or "rsa (default)"
        except ValueError as exc:
            k_type = f"UNUSABLE ({exc})"
        try:
            bits = key_bits(load_public_key(key_blob)[0])
        except Exception:
            bits = "N/A"
        flags = key_flag_info(parse_key_record(key_blob))
        rec = {"Saved_Key_File": os.path.join("keys", fname), "DKIM_Selector": selector, "DKIM_Domain": domain,
               "DNS_Name": dns_name, "Key_Source_Used": source, "Original_Key_File_Path": key_path,
               "First_Retrieved_UTC": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
               "Key_SHA256": sha, "Key_Type": k_type, "Key_Bits": bits,
               "Key_Testing_Mode": "YES" if flags["testing"] else "NO",
               "Key_Strict_Identity": "YES" if flags["strict"] else "NO",
               "Key_Hash_Algs": ":".join(flags["hash_algs"]) or "ANY",
               "Key_Service_Types": flags["services"] or "* (default)",
               "Key_Notes": flags["notes"] or "N/A", "Key_Flags_Raw": flags["raw_t"] or "N/A",
               "Times_Used": 0, "_used_by": []}
        SAVED_KEYS[(dns_name, sha)] = rec
    rec["Times_Used"] += 1
    rec["_used_by"].append(f"{eml_name}#sig{sig_index}")
    return rec["Saved_Key_File"]


def write_key_manifest(output_root):
    path = os.path.join(output_root, "keys_manifest.csv")
    with open(path, "w", newline="", encoding="utf-8") as mf:
        w = csv.DictWriter(mf, fieldnames=MANIFEST_HEADERS, extrasaction="ignore")
        w.writeheader()
        for rec in sorted(SAVED_KEYS.values(), key=lambda r: r["Saved_Key_File"]):
            row = dict(rec)
            row["Used_By"] = "; ".join(rec["_used_by"])
            w.writerow(row)
    return path


def read_key_file(path):
    with open(path, "r", errors="replace") as kf:
        return kf.read()


def resolve_key(eml_path, mode, domain, selector, global_key_blob):
    """Locate the public key for one signature. Returns (blob, source, path, notes)."""
    notes = []
    sidecar = os.path.splitext(eml_path)[0] + ".key"
    n1_path = os.path.join(os.path.dirname(eml_path), f"{selector}._domainkey.{domain}.key")
    cache_key = f"{selector}._domainkey.{domain}"

    if mode == 1:
        if cache_key in KEY_MEMORY_CACHE:
            return KEY_MEMORY_CACHE[cache_key], "CACHE_MEMORY", "N/A", notes
        if cache_key in DNS_NEGATIVE_CACHE:
            notes.append(DNS_NEGATIVE_CACHE[cache_key] + " (cached result)")
        else:
            blob, dns_note = query_dns_key(domain, selector)
            notes.append(dns_note)
            if blob:
                KEY_MEMORY_CACHE[cache_key] = blob
                return blob, "LIVE_DNS_QUERY", "N/A", notes
            DNS_NEGATIVE_CACHE[cache_key] = dns_note
        if os.path.exists(sidecar):
            return read_key_file(sidecar), "FALLBACK_SIDECAR_FILE", sidecar, notes
        if os.path.exists(n1_path):
            return read_key_file(n1_path), "FALLBACK_NOMENCLATURE_FILE", n1_path, notes
    elif mode == 2:
        if os.path.exists(sidecar):
            return read_key_file(sidecar), "SIDECAR_FILE", sidecar, notes
    elif mode == 3:
        if os.path.exists(n1_path):
            return read_key_file(n1_path), "N1_NOMENCLATURE_FILE", n1_path, notes
        if global_key_blob:
            return global_key_blob, "GLOBAL_USER_SUPPLIED_KEY", "N/A", notes
    return None, "UNKNOWN", "N/A", notes


# ---------------------------------------------------------------------------
# Message parsing and canonicalisation
# ---------------------------------------------------------------------------
def normalise_line_endings(raw):
    """Return (crlf_bytes, description). Bare LF -> CRLF on a working copy; original is untouched."""
    crlf = raw.count(b"\r\n")
    bare_lf = raw.count(b"\n") - crlf
    if bare_lf == 0:
        return raw, "CRLF"
    fixed = re.sub(rb"(?<!\r)\n", b"\r\n", raw)
    if crlf == 0:
        return fixed, "LF (normalised to CRLF)"
    return fixed, "MIXED (normalised to CRLF)"


def split_message(raw):
    sep = raw.find(b"\r\n\r\n")
    if sep < 0:
        if raw.endswith(b"\r\n"):
            return raw[:-2], b""
        raise ValueError("No header/body separator found.")
    return raw[:sep], raw[sep + 4:]


def split_fields(header_block):
    fields, cur = [], []
    for line in header_block.split(b"\r\n"):
        if line[:1] in (b" ", b"\t") and cur:
            cur.append(line)
        else:
            if cur:
                fields.append(b"\r\n".join(cur))
            cur = [line]
    if cur:
        fields.append(b"\r\n".join(cur))
    return [(f.split(b":", 1)[0].strip().lower(), f) for f in fields if b":" in f]


def parse_tags(field):
    out = {}
    for part in field.split(b":", 1)[1].split(b";"):
        part = part.strip()
        if b"=" in part:
            k, v = part.split(b"=", 1)
            out[k.strip().decode(LATIN1)] = re.sub(rb"\s+", b"", v).decode(LATIN1)
    return out


def canon_header_relaxed(field):
    name, value = field.split(b":", 1)
    value = re.sub(rb"\r\n[ \t]+", b" ", value)
    value = re.sub(rb"[ \t]+", b" ", value).strip()
    return name.strip().lower() + b":" + value


def canon_body_relaxed(body):
    lines = body.split(b"\r\n")
    if lines and lines[-1] == b"":
        lines.pop()
    out = [re.sub(rb"[ \t]+", b" ", ln).rstrip(b" \t") for ln in lines]
    while out and out[-1] == b"":
        out.pop()
    return b"\r\n".join(out) + b"\r\n" if out else b""


def canon_body_simple(body):
    if not body:
        return b"\r\n"
    while body.endswith(b"\r\n\r\n"):
        body = body[:-2]
    if not body.endswith(b"\r\n"):
        body += b"\r\n"
    return body


def build_signed_block(named, sig_field, tags):
    hdr_mode = tags.get("c", "simple/simple").split("/")[0]
    canon = canon_header_relaxed if hdr_mode == "relaxed" else (lambda x: x)
    pool = {}
    for name, field in named:
        pool.setdefault(name, []).append(field)
    for k in pool:
        pool[k] = list(reversed(pool[k]))
    parts = []
    for raw_name in tags.get("h", "").split(":"):
        name = raw_name.strip().lower().encode(LATIN1)
        if name in pool and pool[name]:
            parts.append(canon(pool[name].pop(0)) + b"\r\n")
    sig_canon = canon(sig_field)
    sig_canon = re.sub(rb"(^|;)(\s*b\s*=)[^;]*", rb"\1\2", sig_canon)
    parts.append(sig_canon)
    return b"".join(parts)


# ---------------------------------------------------------------------------
# Tag evaluation (t=, x=, i=)
# ---------------------------------------------------------------------------
def fmt_epoch(value):
    try:
        return datetime.datetime.fromtimestamp(int(value), datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    except (ValueError, OverflowError, OSError):
        return f"INVALID ({value})"


def evaluate_identity(tags, strict=False):
    """RFC 6376 s3.5: the domain of i= must be the same as, or a subdomain of, d=.
    With key flag t=s (s3.6.1) the i= domain must be exactly d=."""
    d = tags.get("d", "").lower().rstrip(".")
    i = tags.get("i")
    if i is None:
        return f"@{d}", "DEFAULT (@d=)", True
    i_domain = i.split("@", 1)[1].lower().rstrip(".") if "@" in i else ""
    if i_domain == d:
        return i, "OK (same as d=)", True
    if i_domain.endswith("." + d):
        if strict:
            return i, "INVALID (key t=s requires i= domain to equal d=)", False
        return i, "OK (subdomain of d=)", True
    return i, f"INVALID (i= domain '{i_domain}' not within d= '{d}')", False


def evaluate_times(tags, now_epoch):
    """Returns (t_str, x_str, expiry_status, expired_flag, structural_ok, notes)."""
    notes = []
    t_val = None
    t_str = x_str = "N/A"
    if "t" in tags:
        t_str = fmt_epoch(tags["t"])
        try:
            t_val = int(tags["t"])
            if t_val > now_epoch + 300:
                notes.append("t= is in the future relative to verification time")
        except ValueError:
            notes.append("t= is not a valid integer")
    if "x" not in tags:
        return t_str, x_str, "NO EXPIRY", False, True, notes
    x_str = fmt_epoch(tags["x"])
    try:
        x_val = int(tags["x"])
    except ValueError:
        return t_str, x_str, "INVALID (x= not an integer)", False, False, notes
    if t_val is not None and x_val <= t_val:
        return t_str, x_str, "INVALID (x= not later than t=)", False, False, notes
    if x_val < now_epoch:
        return t_str, x_str, "EXPIRED (at verification time)", True, True, notes
    return t_str, x_str, "VALID (not expired)", False, True, notes


def expiry_short(d):
    status = d["Expiry_Status"]
    if status == "NO EXPIRY":
        return "x=none"
    tag = status.split(" ")[0]
    return f"x={d['Sig_Expiry_UTC']} [{tag}]"


def header_date_epoch(named):
    for name, field in named:
        if name == b"date":
            try:
                value = field.split(b":", 1)[1].decode(LATIN1).strip()
                return int(email.utils.parsedate_to_datetime(value).timestamp())
            except Exception:
                return None
    return None


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
def verify_signature(index, sig_field, named, body, eml_path, mode, global_key_blob, strict_expiry, now_epoch,
                     output_root=None):
    tags = parse_tags(sig_field)
    algo = tags.get("a", "rsa-sha256").lower()
    canon_str = tags.get("c", "simple/simple")
    res = {
        "Sig_Index": index, "DKIM_Domain": tags.get("d", "unknown"), "DKIM_Selector": tags.get("s", "unknown"),
        "DKIM_Algorithm": algo, "Canonicalization": canon_str, "DKIM_Identity": "N/A", "Identity_Check": "N/A",
        "Sig_Timestamp_UTC": "N/A", "Sig_Expiry_UTC": "N/A", "Expiry_Status": "N/A",
        "Key_Source_Used": "UNKNOWN", "Key_File_Path": "N/A", "Key_SHA256": "N/A", "Saved_Key_File": "N/A",
        "Key_Bits": "N/A", "Key_Flags": "N/A",
        "Body_Hash_Result": "ERROR", "Signature_Result": "ERROR", "Signature_Status": "ERROR",
        "Notes": "", "_canon_body": None, "_block": None, "_key_record": None, "_expired": False,
    }
    notes = []
    try:
        if algo not in ("rsa-sha256", "rsa-sha1", "ed25519-sha256"):
            raise ValueError(f"Unsupported signature algorithm a={algo}")

        t_str, x_str, exp_status, expired, time_ok, t_notes = evaluate_times(tags, now_epoch)
        res["Sig_Timestamp_UTC"], res["Sig_Expiry_UTC"], res["Expiry_Status"] = t_str, x_str, exp_status
        res["_expired"] = expired
        notes.extend(t_notes)

        key_blob, source, key_path, key_notes = resolve_key(
            eml_path, mode, res["DKIM_Domain"], res["DKIM_Selector"], global_key_blob)
        notes.extend(key_notes)
        flags = key_flag_info(parse_key_record(key_blob)) if key_blob else key_flag_info({})
        identity, id_check, id_ok = evaluate_identity(tags, strict=flags["strict"])
        res["DKIM_Identity"], res["Identity_Check"] = identity, id_check
        if not key_blob:
            res["Signature_Status"] = "NO_KEY"
            res["Body_Hash_Result"] = res["Signature_Result"] = "N/A"
            return res, notes
        res["Key_Source_Used"], res["Key_File_Path"] = source, key_path
        res["Key_SHA256"] = hashlib.sha256(key_blob.encode(LATIN1, errors="replace")).hexdigest()
        res["Key_Flags"] = flags["summary"]
        res["_key_record"] = key_blob
        if output_root:
            res["Saved_Key_File"] = preserve_key(output_root, res["DKIM_Domain"], res["DKIM_Selector"], key_blob,
                                                 source, key_path, os.path.basename(eml_path), index)
        if flags["testing"]:
            notes.append("Key is in testing mode (t=y): the domain is testing DKIM; give the result less weight")

        # Body hash
        body_mode = (canon_str.split("/") + ["simple"])[1]
        hasher = hashlib.sha1 if algo == "rsa-sha1" else hashlib.sha256
        canon_body = (canon_body_relaxed if body_mode == "relaxed" else canon_body_simple)(body)
        if "l" in tags:
            limit = int(tags["l"])
            if limit < len(canon_body):
                notes.append(f"l={limit}: only the first {limit} body bytes are signed "
                             f"({len(canon_body) - limit} unsigned bytes follow)")
                canon_body = canon_body[:limit]
        res["_canon_body"] = canon_body
        bh_ok = base64.b64encode(hasher(canon_body).digest()).decode() == tags.get("bh")
        res["Body_Hash_Result"] = "MATCH" if bh_ok else "MISMATCH"

        # Signature
        block = build_signed_block(named, sig_field, tags)
        res["_block"] = block
        signature = base64.b64decode(tags.get("b", ""))
        key_obj, _ = load_public_key(key_blob, algo)
        res["Key_Bits"] = key_bits(key_obj)
        sig_ok = False
        try:
            if algo.startswith("rsa"):
                if not isinstance(key_obj, rsa.RSAPublicKey):
                    raise ValueError(f"a={algo} but the public key is not an RSA key")
                key_obj.verify(signature, block, padding.PKCS1v15(),
                               hashes.SHA1() if algo == "rsa-sha1" else hashes.SHA256())
            else:
                if not isinstance(key_obj, ed25519.Ed25519PublicKey):
                    raise ValueError(f"a={algo} but the public key is not an Ed25519 key")
                # RFC 8463 s3: Ed25519 signs the SHA-256 hash of the canonicalised header block
                key_obj.verify(signature, hashlib.sha256(block).digest())
            sig_ok = True
        except InvalidSignature:
            pass
        res["Signature_Result"] = "VERIFIED" if sig_ok else "FAILED"
        if algo == "rsa-sha1":
            notes.append("rsa-sha1 is deprecated (RFC 8301)")
        if res["Key_Bits"] != "N/A" and algo.startswith("rsa") and int(res["Key_Bits"]) < 1024:
            notes.append(f"RSA key is only {res['Key_Bits']} bits (RFC 8301 requires at least 1024)")
        sig_hash = algo.split("-")[-1]
        hash_ok = not flags["hash_algs"] or sig_hash in flags["hash_algs"]

        # Overall per-signature status
        if not (bh_ok and sig_ok):
            res["Signature_Status"] = "FAIL"
        elif not hash_ok:
            res["Signature_Status"] = f"FAIL (Key h= does not permit {sig_hash})"
        elif not id_ok:
            res["Signature_Status"] = "FAIL (Invalid i= tag)"
        elif not time_ok:
            res["Signature_Status"] = "FAIL (Invalid x= tag)"
        elif expired and strict_expiry:
            res["Signature_Status"] = "FAIL (Expired)"
        else:
            res["Signature_Status"] = "PASS"
            if expired:
                notes.append("Signature expired (x=) at verification time; cryptographically valid")
    except Exception as err:
        res["Signature_Status"] = f"ERROR ({err})"
    return res, notes


def verify_single_eml(eml_path, mode, output_root, save_bodies, save_signatures, global_key_blob,
                      keyword_compiled_list, strict_expiry=False):
    row = {h: "" for h in CSV_HEADERS}
    row.update({
        "EML_Filename": os.path.basename(eml_path), "Line_Endings": "N/A",
        "Signature_Count": 0, "Signatures_Passed": 0, "Signatures_Expired": 0, "Reported_Signature": "N/A",
        "DKIM_Domain": "N/A", "DKIM_Selector": "N/A", "DKIM_Algorithm": "N/A", "DKIM_Identity": "N/A",
        "Identity_Check": "N/A", "Sig_Timestamp_UTC": "N/A", "Sig_Expiry_UTC": "N/A", "Expiry_Status": "N/A",
        "Key_Source_Used": "UNKNOWN", "Key_File_Path": "N/A", "Key_SHA256": "N/A", "Saved_Key_File": "N/A",
        "Key_Bits": "N/A", "Key_Flags": "N/A",
        "Body_Hash_Result": "ERROR", "Signature_Result": "ERROR", "Overall_Status": "FAIL",
        "All_Signatures": "N/A", "Threat_Alerts": "CLEAN", "Notes": ""
    })
    details = []
    try:
        with open(eml_path, "rb") as f:
            raw = f.read()
        row["MD5_Hash"] = hashlib.md5(raw).hexdigest()
        row["SHA256_Hash"] = hashlib.sha256(raw).hexdigest()

        work, row["Line_Endings"] = normalise_line_endings(raw)
        header_block, body = split_message(work)

        detected = [p.pattern.decode(LATIN1, errors="replace") for p in keyword_compiled_list or [] if p.search(body)]
        row["Threat_Alerts"] = ", ".join(detected) if detected else "CLEAN"

        named = split_fields(header_block)
        sigs = [f for n, f in named if n == b"dkim-signature"]
        row["Signature_Count"] = len(sigs)
        if not sigs:
            row["Overall_Status"] = "UNVERIFIED (No Signature)"
            return row, details

        now_epoch = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        email_notes = []
        for idx, sig_field in enumerate(sigs, 1):
            res, notes = verify_signature(idx, sig_field, named, body, eml_path, mode,
                                          global_key_blob, strict_expiry, now_epoch, output_root)
            res["Notes"] = "; ".join(notes)
            details.append(res)
            for n in notes:
                tagged = f"[sig {idx}] {n}" if len(sigs) > 1 else n
                if tagged not in email_notes:
                    email_notes.append(tagged)

        passed = [d for d in details if d["Signature_Status"] == "PASS"]
        with_key = [d for d in details if d["Signature_Status"] != "NO_KEY"]
        row["Signatures_Passed"] = len(passed)
        row["Signatures_Expired"] = sum(1 for d in details if d["_expired"])
        reported = passed[0] if passed else (with_key[0] if with_key else details[0])
        row["Reported_Signature"] = f"{reported['Sig_Index']} of {len(sigs)}"
        for col in ("DKIM_Domain", "DKIM_Selector", "DKIM_Algorithm", "DKIM_Identity", "Identity_Check",
                    "Sig_Timestamp_UTC", "Sig_Expiry_UTC", "Expiry_Status", "Key_Source_Used",
                    "Key_File_Path", "Key_SHA256", "Saved_Key_File", "Key_Bits", "Key_Flags",
                    "Body_Hash_Result", "Signature_Result"):
            row[col] = reported[col]
        row["All_Signatures"] = " | ".join(
            f"{d['Sig_Index']}: d={d['DKIM_Domain']} s={d['DKIM_Selector']} a={d['DKIM_Algorithm']} "
            f"{expiry_short(d)} -> {d['Signature_Status']}"
            for d in details)

        if passed:
            row["Overall_Status"] = "PASS"
        elif not with_key:
            row["Overall_Status"] = "UNVERIFIED (Missing Public Key)"
        elif all(d["Signature_Status"].startswith("ERROR") for d in with_key):
            row["Overall_Status"] = f"RUNTIME_ERROR {with_key[0]['Signature_Status'][6:]}"
        elif all(d["Signature_Status"] in ("FAIL (Expired)", "NO_KEY") for d in details):
            row["Overall_Status"] = "FAIL (Expired)"
        else:
            row["Overall_Status"] = "FAIL"
        if len(sigs) > 1:
            summary = f"{len(sigs)} DKIM signatures found; {len(passed)} passed"
            if row["Signatures_Expired"]:
                summary += f"; {row['Signatures_Expired']} expired"
            email_notes.insert(0, summary)
        row["Notes"] = "; ".join(email_notes)

        write_artifacts(eml_path, output_root, save_bodies, save_signatures, row, details,
                        header_date_epoch(named))
    except Exception as err:
        row["Overall_Status"] = f"RUNTIME_ERROR ({err})"
    return row, details


def write_artifacts(eml_path, output_root, save_bodies, save_signatures, row, details, date_epoch):
    if not details:
        return
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base_name = os.path.basename(eml_path)
    multi = len(details) > 1
    for d in details:
        if d["_block"] is None:
            continue
        suffix = f"_sig{d['Sig_Index']}" if multi else ""
        if save_bodies:
            b_dir = os.path.join(output_root, "bodies")
            os.makedirs(b_dir, exist_ok=True)
            with open(os.path.join(b_dir, f"{base_name}_body{suffix}_{stamp}.txt"), "wb") as bf:
                bf.write(d["_canon_body"])
        if save_signatures:
            s_dir = os.path.join(output_root, "signatures")
            os.makedirs(s_dir, exist_ok=True)
            with open(os.path.join(s_dir, f"{base_name}_dkim_signature{suffix}_{stamp}.txt"), "wb") as sf:
                sf.write(d["_block"])

    l_dir = os.path.join(output_root, "logs")
    os.makedirs(l_dir, exist_ok=True)
    bar = "=" * 72
    with open(os.path.join(l_dir, f"{base_name}_{stamp}.log"), "w", encoding="utf-8") as lf:
        lf.write(f"{bar}\n  FORENSIC RECONSTRUCTION ANALYSIS REPORT\n{bar}\n")
        lf.write(f"Tool             : {__tool_name__}\n")
        lf.write(f"Version          : {__version__}\n")
        lf.write(f"Build Date       : {BUILD_DATE}\n")
        lf.write(f"Author           : {__author__}\n")
        lf.write(f"Author Info      : {__email__}\n")
        lf.write(f"Execution Target : {base_name}\n")
        lf.write(f"SHA256 Reference : {row['SHA256_Hash']}\n")
        lf.write(f"Line Endings     : {row['Line_Endings']}\n")
        lf.write(f"Date Header (UTC): {fmt_epoch(date_epoch) if date_epoch is not None else 'N/A'}\n")
        lf.write(f"Overall Result   : {row['Overall_Status']}\n")
        lf.write(f"Signatures       : {row['Signature_Count']} found, {row['Signatures_Passed']} passed, "
                 f"{row['Signatures_Expired']} expired\n")
        lf.write(f"Threat Flagging  : {row['Threat_Alerts']}\n")
        for d in details:
            lf.write(f"{'-' * 72}\n  SIGNATURE {d['Sig_Index']} of {len(details)}\n{'-' * 72}\n")
            lf.write(f"Domain (d=)      : {d['DKIM_Domain']}\n")
            lf.write(f"Selector (s=)    : {d['DKIM_Selector']}\n")
            lf.write(f"Algorithm (a=)   : {d['DKIM_Algorithm']}\n")
            lf.write(f"Canon (c=)       : {d['Canonicalization']}\n")
            lf.write(f"Identity (i=)    : {d['DKIM_Identity']}  [{d['Identity_Check']}]\n")
            lf.write(f"Signed (t=)      : {d['Sig_Timestamp_UTC']}\n")
            lf.write(f"Expires (x=)     : {d['Sig_Expiry_UTC']}  [{d['Expiry_Status']}]\n")
            if date_epoch is not None and d["Sig_Timestamp_UTC"] != "N/A" \
                    and not d["Sig_Timestamp_UTC"].startswith("INVALID"):
                t_epoch = int(datetime.datetime.strptime(d["Sig_Timestamp_UTC"], "%Y-%m-%d %H:%M:%SZ")
                              .replace(tzinfo=datetime.timezone.utc).timestamp())
                lf.write(f"t= minus Date    : {t_epoch - date_epoch:+d} seconds\n")
            lf.write(f"Key Mapping Route: {d['Key_Source_Used']}\n")
            lf.write(f"Key File         : {d['Key_File_Path']}\n")
            lf.write(f"Key SHA256       : {d['Key_SHA256']}\n")
            lf.write(f"Key Size (bits)  : {d['Key_Bits']}\n")
            lf.write(f"Key Flags        : {d['Key_Flags']}\n")
            lf.write(f"Key Preserved As : {d['Saved_Key_File']}\n")
            if d["_key_record"]:
                lf.write(f"Key Record       : {d['_key_record'].strip()}\n")
            lf.write(f"Body Hash        : {d['Body_Hash_Result']}\n")
            lf.write(f"Crypto Signature : {d['Signature_Result']}\n")
            lf.write(f"Signature Status : {d['Signature_Status']}\n")
            if d["Notes"]:
                lf.write(f"Notes            : {d['Notes']}\n")
        lf.write(f"{bar}\n")


# ---------------------------------------------------------------------------
# Bulk loop
# ---------------------------------------------------------------------------
def run_bulk_processing(src_dir, out_dir, mode, recursive, save_bodies, save_sigs, global_key,
                        raw_keywords_list, strict_expiry=False):
    if not os.path.exists(src_dir):
        print(f"Error: Source directory does not exist: {src_dir}")
        return
    os.makedirs(out_dir, exist_ok=True)
    csv_report_path = os.path.join(out_dir, "dkim_bulk_verification_report.csv")
    csv_detail_path = os.path.join(out_dir, "dkim_signature_details.csv")
    KEY_MEMORY_CACHE.clear()
    DNS_NEGATIVE_CACHE.clear()
    SAVED_KEYS.clear()

    compiled_regexes = []
    for pattern_str in raw_keywords_list or []:
        if pattern_str.strip():
            compiled_regexes.append(re.compile(pattern_str.strip().encode(LATIN1, errors="replace")))

    eml_targets = []
    if recursive:
        for root, _, files in os.walk(src_dir):
            for file in files:
                if file.lower().endswith(".eml"):
                    eml_targets.append(os.path.join(root, file))
    else:
        for file in os.listdir(src_dir):
            if file.lower().endswith(".eml"):
                eml_targets.append(os.path.join(src_dir, file))
    eml_targets.sort()
    if not eml_targets:
        print("No .eml files identified inside the designated scope target.")
        return

    print(f"\n{__tool_name__} v{__version__}")
    print(f"Initiating processing loop for {len(eml_targets)} targets (mode {mode}"
          f"{', strict expiry' if strict_expiry else ''})...")
    with open(csv_report_path, "w", newline="", encoding="utf-8") as csv_f, \
            open(csv_detail_path, "w", newline="", encoding="utf-8") as det_f:
        writer = csv.DictWriter(csv_f, fieldnames=CSV_HEADERS)
        det_writer = csv.DictWriter(det_f, fieldnames=DETAIL_HEADERS, extrasaction="ignore")
        writer.writeheader()
        det_writer.writeheader()
        for idx, eml_path in enumerate(eml_targets, 1):
            sys.stdout.write(f"\rAnalyzing items: [{idx}/{len(eml_targets)}] - {os.path.basename(eml_path)[:40]}... ")
            sys.stdout.flush()
            row, details = verify_single_eml(eml_path, mode, out_dir, save_bodies, save_sigs, global_key,
                                             compiled_regexes, strict_expiry)
            writer.writerow(row)
            for d in details:
                d = dict(d)
                d["EML_Filename"] = row["EML_Filename"]
                d["SHA256_Hash"] = row["SHA256_Hash"]
                det_writer.writerow(d)
    print("\n\nProcessing sequence completed successfully.")
    print(f"Master Analytical Ledger Saved: {csv_report_path}")
    print(f"Per-Signature Detail Ledger   : {csv_detail_path}")
    if SAVED_KEYS:
        print(f"Public Keys Preserved         : {len(SAVED_KEYS)} key(s) in {os.path.join(out_dir, 'keys')}")
        print(f"Key Manifest                  : {write_key_manifest(out_dir)}")


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
def launch_gui_panel():
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext

    root = tk.Tk()
    root.title(f"{__tool_name__} - v{__version__}")
    root.geometry("720x710")
    root.resizable(False, False)

    src_path_var = tk.StringVar(value=os.getcwd())
    out_path_var = tk.StringVar(value=os.path.join(os.getcwd(), "forensic_analysis_out"))
    mode_var = tk.IntVar(value=1)
    recursive_var = tk.BooleanVar(value=True)
    bodies_var = tk.BooleanVar(value=True)
    sigs_var = tk.BooleanVar(value=True)
    strict_var = tk.BooleanVar(value=False)
    alerts_enabled_var = tk.BooleanVar(value=False)
    global_key_buffer = {"text": None}

    tk.Label(root, text="DKIM Bulk Verification Engine", font=("Helvetica", 12, "bold")).pack(pady=10)

    f_paths = tk.LabelFrame(root, text=" Directory Workspace Configurations ", padx=10, pady=10)
    f_paths.pack(fill="x", padx=15, pady=5)
    tk.Label(f_paths, text="Source Folder:").grid(row=0, column=0, sticky="w")
    tk.Entry(f_paths, textvariable=src_path_var, width=58).grid(row=0, column=1, padx=5, pady=2)
    tk.Button(f_paths, text="Browse...", command=lambda: src_path_var.set(
        filedialog.askdirectory() or src_path_var.get())).grid(row=0, column=2, pady=2)
    tk.Label(f_paths, text="Output Folder:").grid(row=1, column=0, sticky="w")
    tk.Entry(f_paths, textvariable=out_path_var, width=58).grid(row=1, column=1, padx=5, pady=2)
    tk.Button(f_paths, text="Browse...", command=lambda: out_path_var.set(
        filedialog.askdirectory() or out_path_var.get())).grid(row=1, column=2, pady=2)

    f_opts = tk.LabelFrame(root, text=" Directory Scan & Output Sub-Artifact Toggles ", padx=10, pady=5)
    f_opts.pack(fill="x", padx=15, pady=5)
    tk.Checkbutton(f_opts, text="Scan Target Folder Recursively (Include Sub-directories)",
                   variable=recursive_var).pack(anchor="w")
    tk.Checkbutton(f_opts, text="Extract & Save Canonicalized Body Artifacts Folder (bodies/*)",
                   variable=bodies_var).pack(anchor="w")
    tk.Checkbutton(f_opts, text="Extract & Save Cryptographic Header Blocks Folder (signatures/*)",
                   variable=sigs_var).pack(anchor="w")
    tk.Checkbutton(f_opts, text="Strict Expiry: Treat Expired Signatures (x= tag) as FAIL (RFC 6376 behaviour)",
                   variable=strict_var).pack(anchor="w")

    f_mode = tk.LabelFrame(root, text=" Public Key Mapping Strategy Lane Routing ", padx=10, pady=5)
    f_mode.pack(fill="x", padx=15, pady=5)
    tk.Radiobutton(f_mode, text="Mode 1: Automated Live DNS Resolution Query (w/ Local Cascading Fallbacks)",
                   variable=mode_var, value=1).pack(anchor="w")
    tk.Radiobutton(f_mode, text="Mode 2: Local 1:1 Sidecar File Matching Pattern (TargetFile.eml -> TargetFile.key)",
                   variable=mode_var, value=2).pack(anchor="w")
    tk.Radiobutton(f_mode, text="Mode 3: Local N:1 Mapping Model ([selector]._domainkey.[domain].key)",
                   variable=mode_var, value=3).pack(anchor="w")

    def prompt_master_key_dialog():
        k_win = tk.Toplevel(root)
        k_win.title("Supply Global Fallback Key")
        k_win.geometry("540x320")
        tk.Label(k_win, text="Paste raw key material or full TXT record context below:").pack(pady=5, padx=10, anchor="w")
        txt_box = scrolledtext.ScrolledText(k_win, height=12, width=62)
        txt_box.pack(padx=10, pady=5)

        def save_and_close():
            global_key_buffer["text"] = txt_box.get("1.0", "end").strip()
            k_win.destroy()
        tk.Button(k_win, text="Register Key Context", command=save_and_close, width=22).pack(pady=5)

    tk.Button(f_mode, text="Configure Global Manual Key Fallback (Optional Mode 3)",
              command=prompt_master_key_dialog, font=("Helvetica", 8, "italic")).pack(anchor="w", padx=20, pady=2)

    f_alerts = tk.LabelFrame(root, text=" Content Threat Keyword Alerts Configuration ", padx=10, pady=5)
    f_alerts.pack(fill="x", padx=15, pady=5)
    kw_box = scrolledtext.ScrolledText(f_alerts, height=5, width=74, font=("Courier", 9))
    f_btn_bar = tk.Frame(f_alerts)

    def toggle_keyword_visibility():
        if alerts_enabled_var.get():
            kw_box.pack(fill="x", pady=5)
            f_btn_bar.pack(fill="x")
            if not kw_box.get("1.0", "end").strip():
                kw_box.insert("1.0", "\n".join(DEFAULT_KEYWORDS))
        else:
            kw_box.pack_forget()
            f_btn_bar.pack_forget()

    tk.Checkbutton(f_alerts, text="Enable Advanced Body Content Keyword Flagging Alerts",
                   variable=alerts_enabled_var, command=toggle_keyword_visibility).pack(anchor="w")

    def load_keywords_file():
        fp = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if fp:
            try:
                with open(fp, "r", errors="replace") as kf:
                    kw_box.insert("end", "\n" + kf.read().strip())
            except Exception as e:
                messagebox.showerror("Error loading file", str(e))

    tk.Button(f_btn_bar, text="Load Custom Keywords File (.txt)...", font=("Helvetica", 8),
              command=load_keywords_file).pack(side="left", pady=2)

    def execute_triage_loop():
        src, out, m = src_path_var.get(), out_path_var.get(), mode_var.get()
        k = global_key_buffer["text"]
        keywords_list = []
        if alerts_enabled_var.get():
            raw_text = kw_box.get("1.0", "end").strip()
            if raw_text:
                keywords_list = [line.strip() for line in raw_text.splitlines() if line.strip()]
            for idx, pattern in enumerate(keywords_list, 1):
                try:
                    re.compile(pattern)
                except re.error as regex_err:
                    messagebox.showerror("Regex Syntax Failure",
                                         f'Broken Expression Found on Entry Line {idx}:\n"{pattern}"\n\nDetails: {regex_err}')
                    return
        if m == 3 and not k:
            nomenclature_found = any(f.lower().endswith(".key") and "_domainkey" in f
                                     for f in os.listdir(src)) if os.path.exists(src) else False
            if not nomenclature_found:
                if not messagebox.askyesno("Key Configuration Warning",
                                           "Mode 3 selected but no fallback key registered, and no nomenclature "
                                           "keys found in directory. Proceed anyway?"):
                    return
        root.destroy()
        run_bulk_processing(src, out, m, recursive_var.get(), bodies_var.get(), sigs_var.get(), k,
                            keywords_list, strict_var.get())

    tk.Button(root, text="LAUNCH TRIAGE PROCESSING LOOP", font=("Helvetica", 10, "bold"), bg="#1a7f37",
              fg="white", command=execute_triage_loop, height=2, width=34).pack(pady=15)
    tk.Label(root, text=f"Tool: {__tool_name__} | Version: {__version__} | Author: {__author__} ({__email__})",
             font=("Helvetica", 7), fg="gray").pack(side="bottom", pady=5)
    root.mainloop()


def main():
    ap = argparse.ArgumentParser(description=f"{__tool_name__} v{__version__} - DKIM Bulk Signature Forensic Triaging Suite.")
    ap.add_argument("--src", help="Source folder targeting raw EML streams.")
    ap.add_argument("--out", help="Output folder targeting artifact storage layouts.")
    ap.add_argument("--mode", type=int, choices=[1, 2, 3], help="Public key verification mapping track lane.")
    ap.add_argument("--strict-expiry", action="store_true",
                    help="Treat signatures whose x= expiry has passed as FAIL (RFC 6376 behaviour).")
    ap.add_argument("--no-gui", action="store_true",
                    help="Force command-line parsing options, skipping GUI window parameters.")
    ap.add_argument("--version", action="version", version=f"{__tool_name__} {__version__} ({BUILD_DATE})")
    args = ap.parse_args()
    if args.no_gui:
        if not args.src or not args.out or not args.mode:
            sys.exit("Error: CLI execution via --no-gui requires --src, --out, and --mode options configured explicitly.")
        run_bulk_processing(args.src, args.out, args.mode, recursive=True, save_bodies=True, save_sigs=True,
                            global_key=None, raw_keywords_list=[], strict_expiry=args.strict_expiry)
    else:
        launch_gui_panel()


if __name__ == "__main__":
    main()
