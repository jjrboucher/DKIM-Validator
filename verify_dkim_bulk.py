#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DKIM Bulk Signature Verifier with Advanced Forensic Toggles, Target Controls, and Regex Validation.

Repository : https://github.com/jjrboucher/DKIM-Validator
Author     : Jacques Boucher (jjrboucher@gmail.com)

Copyright 2026 Jacques Boucher

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This tool is free to use and is provided without warranty of any kind.
Users are responsible for validating its results before relying on them.
The accompanying documentation (README and user guide) is licensed under
Creative Commons Attribution 4.0 International (CC BY 4.0).
"""
import argparse
import base64
import binascii
import csv
import datetime
import getpass
import hashlib
import json
import os
import platform
import re
import socket
import sys
import textwrap
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
__version__ = "1.7.0"
BUILD_DATE = "2026-11-05"
__tool_name__ = "DKIM Bulk Signature Verifier"
__author__ = "Jacques Boucher"
__email__ = "jjrboucher@gmail.com"
__license__ = "Apache-2.0"
__url__ = "https://github.com/jjrboucher/DKIM-Validator"
LATIN1 = "latin-1"
KEYS_SUBDIR = "keys"
GLOBAL_KEY_FILENAME = "global_user_supplied.key"
# Default Forensic Tactical Alerts Mapping
DEFAULT_KEYWORDS = [
    r'(?i)(wire transfer|swift|routing number|bank account|invoice)',
    r'(?i)(bitcoin|crypto|usdt|wallet phrase|private key)',
    r'(?i)(password reset|verify your account|login expired|microsoft team)',
    r'(?i)(subpoena|warrant|investigation|court notice|classified)'
]
KEY_MEMORY_CACHE = {}
# Maps "selector._domainkey.domain" -> path of the key file saved to the keys folder (Mode 1)
KEY_SAVED_PATHS = {}
def extract_key_material(blob):
    if not blob or not blob.strip():
        raise ValueError("No key material supplied.")
    text = blob.strip()
    if "BEGIN PUBLIC KEY" in text or "BEGIN RSA PUBLIC KEY" in text:
        return "pem", text
    text = re.sub(r'(?im)^\s*\S+\s+\d+\s+IN\s+TXT\s+', '', text)
    chunks = re.findall(r'"([^"]*)"', text)
    if chunks:
        text = "".join(chunks)
    m = re.search(r'(?:^|;)\s*k\s*=\s*([A-Za-z0-9]+)', text)
    key_type = m.group(1).lower() if m else "rsa"
    m = re.search(r'(?:^|;)\s*p\s*=\s*([A-Za-z0-9+/=\s]*)', text)
    if m:
        b64 = m.group(1)
        if not b64.strip():
            raise ValueError("The record contains an empty 'p=' tag indicating revocation.")
    else:
        b64 = text
    b64 = re.sub(r'\s+', '', b64)
    return key_type, b64
def load_public_key(blob):
    key_type, material = extract_key_material(blob)
    if key_type == "pem":
        return load_pem_public_key(material.encode()), ["Parsed as PEM."]
    try:
        der = base64.b64decode(material, validate=True)
    except Exception as exc:
        raise ValueError(f"Key data is not valid base64: {exc}")
    if key_type == "ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(der), ["Parsed as Ed25519."]
    try:
        return load_der_public_key(der), ["Parsed as DER SubjectPublicKeyInfo."]
    except Exception:
        pass
    pem = "-----BEGIN RSA PUBLIC KEY-----\n" + "\n".join(textwrap.wrap(material, 64)) + "\n-----END RSA PUBLIC KEY-----\n"
    return load_pem_public_key(pem.encode()), ["Parsed as PKCS#1 RSAPublicKey."]
def _join_txt_strings(data):
    """DNS JSON returns long TXT records as several quoted strings; join them into one record."""
    chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    return "".join(chunks) if chunks else data.strip()
def query_dns_key(domain, selector):
    query_str = f"{selector}._domainkey.{domain}"
    try:
        url = "https://dns.google/resolve?name=" + urllib.parse.quote(query_str) + "&type=TXT"
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            records = [_join_txt_strings(ans.get("data", "")) for ans in data.get("Answer", []) if ans.get("type") == 16]
            records = [r for r in records if r]
            # Prefer the record that actually carries a DKIM public key tag
            for rec in records:
                if re.search(r'(?:^|;)\s*p\s*=', rec):
                    return rec
            if records:
                return records[0]
    except Exception:
        pass
    return None
def safe_filename_component(value):
    """Restrict selector/domain values taken from email headers to filename-safe characters."""
    cleaned = re.sub(r'[^A-Za-z0-9._-]', '_', value or "unknown").strip(".")
    return cleaned or "unknown"
def save_key_file(keys_dir, filename, key_blob):
    """Write key text exactly as used (so the file's SHA-256 equals Key_SHA256 in the CSV).
    An existing file with identical content is reused; a different existing file is never
    overwritten - the new key is saved with a UTC timestamp suffix instead."""
    os.makedirs(keys_dir, exist_ok=True)
    data = key_blob.encode(LATIN1, errors="replace")
    path = os.path.join(keys_dir, filename)
    if os.path.exists(path):
        with open(path, "rb") as ef:
            if ef.read() == data:
                return path
        stem = filename[:-4] if filename.lower().endswith(".key") else filename
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = os.path.join(keys_dir, f"{stem}.{stamp}.key")
    with open(path, "wb") as kf:
        kf.write(data)
    return path
def split_message(raw):
    sep = raw.find(b"\r\n\r\n")
    if sep < 0:
        sep = raw.find(b"\n\n")
        if sep < 0:
            raise ValueError("No header/body separator found.")
        return raw[:sep], raw[sep + 2:]
    return raw[:sep], raw[sep + 4:]
def split_fields(header_block):
    fields, cur = [], []
    for line in header_block.split(b"\r\n"):
        if line[:1] in (b" ", b"\t") and cur:
            cur.append(line)
        else:
            if cur: fields.append(b"\r\n".join(cur))
            cur = [line]
    if cur: fields.append(b"\r\n".join(cur))
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
    if lines and lines[-1] == b"": lines.pop()
    out = [re.sub(rb"[ \t]+", b" ", ln).rstrip(b" \t") for ln in lines]
    while out and out[-1] == b"": out.pop()
    return b"\r\n".join(out) + b"\r\n" if out else b""
def canon_body_simple(body):
    if not body: return b"\r\n"
    while body.endswith(b"\r\n\r\n"): body = body[:-2]
    if not body.endswith(b"\r\n"): body += b"\r\n"
    return body
def build_signed_block(named, sig_field, tags):
    hdr_mode = tags.get("c", "simple/simple").split("/")[0]
    canon = canon_header_relaxed if hdr_mode == "relaxed" else lambda x: x
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
def verify_single_eml(eml_path, mode, output_root, save_bodies, save_signatures, global_key_blob, keyword_compiled_list,
                      global_key_path="N/A"):
    result_row = {
        "EML_Filename": os.path.basename(eml_path),
        "MD5_Hash": "", "SHA256_Hash": "", "DKIM_Domain": "N/A", "DKIM_Selector": "N/A",
        "Key_Source_Used": "UNKNOWN", "Key_File_Path": "N/A", "Key_SHA256": "N/A",
        "Body_Hash_Result": "ERROR", "Signature_Result": "ERROR", "Overall_Status": "FAIL",
        "Threat_Alerts": "CLEAN"
    }
    try:
        with open(eml_path, "rb") as f:
            raw = f.read()
        result_row["MD5_Hash"] = hashlib.md5(raw).hexdigest()
        result_row["SHA256_Hash"] = hashlib.sha256(raw).hexdigest()
        header_block, body = split_message(raw)
        detected_alerts = []
        if keyword_compiled_list:
            for pattern in keyword_compiled_list:
                if pattern.search(body):
                    detected_alerts.append(pattern.pattern.decode(LATIN1, errors="replace"))
        result_row["Threat_Alerts"] = ", ".join(detected_alerts) if detected_alerts else "CLEAN"
        named = split_fields(header_block)
        sigs = [f for n, f in named if n == b"dkim-signature"]
        if not sigs:
            result_row["Overall_Status"] = "UNVERIFIED (No Signature)"
            return result_row
        sig_field = sigs[0]
        tags = parse_tags(sig_field)
        domain = tags.get("d", "unknown")
        selector = tags.get("s", "unknown")
        result_row["DKIM_Domain"] = domain
        result_row["DKIM_Selector"] = selector
        key_blob = None
        key_source = "UNKNOWN"
        key_file_path = "N/A"
        cache_key = f"{selector}._domainkey.{domain}"
        if mode == 1:
            if cache_key in KEY_MEMORY_CACHE:
                key_blob = KEY_MEMORY_CACHE[cache_key]
                key_source = "CACHE_MEMORY"
                key_file_path = KEY_SAVED_PATHS.get(cache_key, "N/A")
            else:
                key_blob = query_dns_key(domain, selector)
                if key_blob:
                    KEY_MEMORY_CACHE[cache_key] = key_blob
                    key_source = "LIVE_DNS_QUERY"
                    # Preserve the retrieved record using the N:1 nomenclature so it can be reused in Mode 3
                    try:
                        saved = save_key_file(
                            os.path.join(output_root, KEYS_SUBDIR),
                            f"{safe_filename_component(selector)}._domainkey.{safe_filename_component(domain)}.key",
                            key_blob)
                        KEY_SAVED_PATHS[cache_key] = saved
                        key_file_path = saved
                    except OSError as save_err:
                        print(f"\nWarning: could not save retrieved key for {cache_key}: {save_err}")
                else:
                    # Cascade Fallback 1: 1:1 local sidecar key file
                    sidecar = os.path.splitext(eml_path)[0] + ".key"
                    if os.path.exists(sidecar):
                        with open(sidecar, "r", errors="replace") as kf:
                            key_blob = kf.read()
                        key_source = "FALLBACK_SIDECAR_FILE"
                        key_file_path = sidecar
                    else:
                        # Cascade Fallback 2: Local domain-wide nomenclature file
                        n1_filename = f"{selector}._domainkey.{domain}.key"
                        n1_path = os.path.join(os.path.dirname(eml_path), n1_filename)
                        if os.path.exists(n1_path):
                            with open(n1_path, "r", errors="replace") as kf:
                                key_blob = kf.read()
                            key_source = "FALLBACK_NOMENCLATURE_FILE"
                            key_file_path = n1_path
        elif mode == 2:
            sidecar = os.path.splitext(eml_path)[0] + ".key"
            if os.path.exists(sidecar):
                with open(sidecar, "r", errors="replace") as kf:
                    key_blob = kf.read()
                key_source = "SIDECAR_FILE"
                key_file_path = sidecar
        elif mode == 3:
            n1_filename = f"{selector}._domainkey.{domain}.key"
            n1_path = os.path.join(os.path.dirname(eml_path), n1_filename)
            if os.path.exists(n1_path):
                with open(n1_path, "r", errors="replace") as kf:
                    key_blob = kf.read()
                key_source = "N1_NOMENCLATURE_FILE"
                key_file_path = n1_path
            elif global_key_blob:
                key_blob = global_key_blob
                key_source = "GLOBAL_USER_SUPPLIED_KEY"
                key_file_path = global_key_path
        if not key_blob:
            result_row["Overall_Status"] = "UNVERIFIED (Missing Public Key)"
            return result_row
        result_row["Key_Source_Used"] = key_source
        result_row["Key_File_Path"] = key_file_path
        result_row["Key_SHA256"] = hashlib.sha256(key_blob.encode(LATIN1, errors="replace")).hexdigest()
        body_mode = (tags.get("c", "simple/simple").split("/") + ["simple"])[1]
        algo_name = "sha1" if "sha1" in tags.get("a", "") else "sha256"
        hasher = hashlib.sha1 if algo_name == "sha1" else hashlib.sha256
        canon_body = (canon_body_relaxed if body_mode == "relaxed" else canon_body_simple)(body)
        if "l" in tags:
            limit = int(tags["l"])
            if limit < len(canon_body): canon_body = canon_body[:limit]
        computed_bh = base64.b64encode(hasher(canon_body).digest()).decode()
        bh_ok = computed_bh == tags.get("bh")
        result_row["Body_Hash_Result"] = "MATCH" if bh_ok else "MISMATCH"
        block = build_signed_block(named, sig_field, tags)
        signature = base64.b64decode(tags.get("b", ""))
        key_obj, _ = load_public_key(key_blob)
        sig_ok = False
        try:
            if isinstance(key_obj, rsa.RSAPublicKey):
                key_obj.verify(signature, block, padding.PKCS1v15(), hashes.SHA1() if algo_name == "sha1" else hashes.SHA256())
                sig_ok = True
            else:
                key_obj.verify(signature, block)
                sig_ok = True
        except InvalidSignature:
            pass
        result_row["Signature_Result"] = "VERIFIED" if sig_ok else "FAILED"
        result_row["Overall_Status"] = "PASS" if (bh_ok and sig_ok) else "FAIL"
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        base_name = os.path.basename(eml_path)
        if save_bodies:
            b_dir = os.path.join(output_root, "bodies")
            os.makedirs(b_dir, exist_ok=True)
            with open(os.path.join(b_dir, f"{base_name}_body_{stamp}.txt"), "wb") as bf:
                bf.write(canon_body)
        if save_signatures:
            s_dir = os.path.join(output_root, "signatures")
            os.makedirs(s_dir, exist_ok=True)
            with open(os.path.join(s_dir, f"{base_name}_dkim_signature_{stamp}.txt"), "wb") as sf:
                sf.write(block)
        l_dir = os.path.join(output_root, "logs")
        os.makedirs(l_dir, exist_ok=True)
        log_file = os.path.join(l_dir, f"{base_name}_{stamp}.log")
        with open(log_file, "w", encoding="utf-8") as lf:
            lf.write(f"========================================================================\n")
            lf.write(f"  FORENSIC RECONSTRUCTION ANALYSIS REPORT\n")
            lf.write(f"========================================================================\n")
            lf.write(f"Tool             : {__tool_name__}\n")
            lf.write(f"Version          : {__version__}\n")
            lf.write(f"Build Date       : {BUILD_DATE}\n")
            lf.write(f"Author           : {__author__}\n")
            lf.write(f"Author Info      : {__email__}\n")
            lf.write(f"Execution Target : {base_name}\n")
            lf.write(f"SHA256 Reference : {result_row['SHA256_Hash']}\n")
            lf.write(f"Overall Result   : {result_row['Overall_Status']}\n")
            lf.write(f"Body Hash        : {result_row['Body_Hash_Result']}\n")
            lf.write(f"Crypto Signature : {result_row['Signature_Result']}\n")
            lf.write(f"Threat Flagging  : {result_row['Threat_Alerts']}\n")
            lf.write(f"Key Mapping Route: {key_source}\n")
            lf.write(f"Key File         : {key_file_path}\n")
            lf.write(f"Key SHA256       : {result_row['Key_SHA256']}\n")
            lf.write(f"========================================================================\n")
    except Exception as err:
        result_row["Overall_Status"] = f"RUNTIME_ERROR ({str(err)})"
    return result_row
def run_bulk_processing(src_dir, out_dir, mode, recursive, save_bodies, save_sigs, global_key, raw_keywords_list,
                        global_key_origin="pasted", global_key_source_path=None):
    """global_key_origin: 'pasted' (typed/pasted into the GUI - saved to the keys folder)
    or 'file' (loaded from a key file - referenced at its original path, not copied)."""
    if not os.path.exists(src_dir):
        print(f"Error: Source directory does not exist: {src_dir}")
        return
    os.makedirs(out_dir, exist_ok=True)
    csv_report_path = os.path.join(out_dir, "dkim_bulk_verification_report.csv")
    keys_dir = os.path.join(out_dir, KEYS_SUBDIR)
    compiled_regexes = []
    if raw_keywords_list:
        for pattern_str in raw_keywords_list:
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
    if not eml_targets:
        print(f"No .eml files identified inside the designated scope target.")
        return
    # Mode 3: preserve a pasted global key in the keys folder; a key loaded from file keeps its original path
    global_key_path = "N/A"
    if mode == 3 and global_key:
        if global_key_origin == "file" and global_key_source_path:
            global_key_path = global_key_source_path
        else:
            try:
                global_key_path = save_key_file(keys_dir, GLOBAL_KEY_FILENAME, global_key)
                print(f"Global key saved: {global_key_path}")
            except OSError as save_err:
                print(f"Warning: could not save global key: {save_err}")
    print(f"\n🚀 Initiating processing loop for {len(eml_targets)} targets...")
    csv_headers = [
        "EML_Filename", "MD5_Hash", "SHA256_Hash", "DKIM_Domain", "DKIM_Selector",
        "Key_Source_Used", "Key_File_Path", "Key_SHA256", "Body_Hash_Result",
        "Signature_Result", "Overall_Status", "Threat_Alerts"
    ]
    with open(csv_report_path, "w", newline="", encoding="utf-8") as csv_f:
        writer = csv.DictWriter(csv_f, fieldnames=csv_headers)
        writer.writeheader()
        for idx, eml_path in enumerate(eml_targets, 1):
            sys.stdout.write(f"\rAnalyzing items: [{idx}/{len(eml_targets)}] - {os.path.basename(eml_path)[:40]}... ")
            sys.stdout.flush()
            metrics = verify_single_eml(eml_path, mode, out_dir, save_bodies, save_sigs, global_key, compiled_regexes,
                                        global_key_path)
            writer.writerow(metrics)
    print(f"\n\nProcessing sequence completed successfully.")
    print(f"Master Analytical Ledger Saved: {csv_report_path}")
    if mode == 1 and KEY_SAVED_PATHS:
        print(f"Retrieved DNS keys saved ({len(KEY_SAVED_PATHS)}): {keys_dir}")
def launch_gui_panel():
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext
    root = tk.Tk()
    root.title(f"{__tool_name__} - v{__version__}")
    root.geometry("720x700")
    root.resizable(False, False)
    src_path_var = tk.StringVar(value=os.getcwd())
    out_path_var = tk.StringVar(value=os.path.join(os.getcwd(), "forensic_analysis_out"))
    mode_var = tk.IntVar(value=1)
    recursive_var = tk.BooleanVar(value=True)
    bodies_var = tk.BooleanVar(value=True)
    sigs_var = tk.BooleanVar(value=True)
    alerts_enabled_var = tk.BooleanVar(value=False)
    global_key_buffer = {"text": None, "origin": None, "path": None}
    global_key_status_var = tk.StringVar(value="Global key: none registered")
    tk.Label(root, text="DKIM Bulk Verification Engine", font=("Helvetica", 12, "bold")).pack(pady=10)
    f_paths = tk.LabelFrame(root, text=" Directory Workspace Configurations ", padx=10, pady=10)
    f_paths.pack(fill="x", padx=15, pady=5)
    tk.Label(f_paths, text="Source Folder:").grid(row=0, column=0, sticky="w")
    tk.Entry(f_paths, textvariable=src_path_var, width=58).grid(row=0, column=1, padx=5, pady=2)
    tk.Button(f_paths, text="Browse...", command=lambda: src_path_var.set(filedialog.askdirectory() or src_path_var.get())).grid(row=0, column=2, pady=2)
    tk.Label(f_paths, text="Output Folder:").grid(row=1, column=0, sticky="w")
    tk.Entry(f_paths, textvariable=out_path_var, width=58).grid(row=1, column=1, padx=5, pady=2)
    tk.Button(f_paths, text="Browse...", command=lambda: out_path_var.set(filedialog.askdirectory() or out_path_var.get())).grid(row=1, column=2, pady=2)
    f_opts = tk.LabelFrame(root, text=" Directory Scan & Output Sub-Artifact Toggles ", padx=10, pady=5)
    f_opts.pack(fill="x", padx=15, pady=5)
    tk.Checkbutton(f_opts, text="Scan Target Folder Recursively (Include Sub-directories)", variable=recursive_var).pack(anchor="w")
    tk.Checkbutton(f_opts, text="Extract & Save Canonicalized Body Artifacts Folder (bodies/*)", variable=bodies_var).pack(anchor="w")
    tk.Checkbutton(f_opts, text="Extract & Save Cryptographic Header Blocks Folder (signatures/*)", variable=sigs_var).pack(anchor="w")
    f_mode = tk.LabelFrame(root, text=" Public Key Mapping Strategy Lane Routing ", padx=10, pady=5)
    f_mode.pack(fill="x", padx=15, pady=5)
    tk.Radiobutton(f_mode, text="Mode 1: Automated Live DNS Resolution Query (w/ Local Cascading Fallbacks)", variable=mode_var, value=1).pack(anchor="w")
    tk.Radiobutton(f_mode, text="Mode 2: Local 1:1 Sidecar File Matching Pattern (TargetFile.eml -> TargetFile.key)", variable=mode_var, value=2).pack(anchor="w")
    tk.Radiobutton(f_mode, text="Mode 3: Local N:1 Mapping Model ([selector]._domainkey.[domain].key)", variable=mode_var, value=3).pack(anchor="w")
    def prompt_master_key_dialog():
        k_win = tk.Toplevel(root)
        k_win.title("Supply Global Fallback Key")
        k_win.geometry("540x350")
        tk.Label(k_win, text="Paste raw key material or full TXT record context below, or load a key file:").pack(pady=5, padx=10, anchor="w")
        txt_box = scrolledtext.ScrolledText(k_win, height=12, width=62)
        txt_box.pack(padx=10, pady=5)
        loaded = {"path": None, "text": None}
        if global_key_buffer["text"]:
            txt_box.insert("1.0", global_key_buffer["text"])
            if global_key_buffer["origin"] == "file":
                loaded.update(path=global_key_buffer["path"], text=global_key_buffer["text"])
        def load_key_file():
            fp = filedialog.askopenfilename(parent=k_win, filetypes=[("Key files", "*.key *.txt *.pem"), ("All files", "*.*")])
            if fp:
                try:
                    with open(fp, "r", errors="replace") as kf:
                        content = kf.read()
                except Exception as e:
                    messagebox.showerror("Error loading key file", str(e), parent=k_win)
                    return
                txt_box.delete("1.0", "end")
                txt_box.insert("1.0", content)
                loaded.update(path=fp, text=content.strip())
        def save_and_close():
            text = txt_box.get("1.0", "end").strip()
            if not text:
                global_key_buffer.update(text=None, origin=None, path=None)
                global_key_status_var.set("Global key: none registered")
            elif loaded["path"] and text == loaded["text"]:
                # Loaded from file and unchanged: reference the original file, do not copy it
                global_key_buffer.update(text=text, origin="file", path=loaded["path"])
                global_key_status_var.set(f"Global key: loaded from {os.path.basename(loaded['path'])}")
            else:
                # Pasted or edited in the GUI: will be saved to <Output>/keys/ at launch
                global_key_buffer.update(text=text, origin="pasted", path=None)
                global_key_status_var.set(f"Global key: pasted (will be saved to {KEYS_SUBDIR}/{GLOBAL_KEY_FILENAME})")
            k_win.destroy()
        f_kbtn = tk.Frame(k_win)
        f_kbtn.pack(pady=5)
        tk.Button(f_kbtn, text="Load Key File...", command=load_key_file, width=16).pack(side="left", padx=5)
        tk.Button(f_kbtn, text="Register Key Context", command=save_and_close, width=22).pack(side="left", padx=5)
    tk.Button(f_mode, text="Configure Global Manual Key Fallback (Optional Mode 3)", command=prompt_master_key_dialog, font=("Helvetica", 8, "italic")).pack(anchor="w", padx=20, pady=2)
    tk.Label(f_mode, textvariable=global_key_status_var, font=("Helvetica", 8), fg="gray").pack(anchor="w", padx=22)
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
    tk.Checkbutton(f_alerts, text="Enable Advanced Body Content Keyword Flagging Alerts", variable=alerts_enabled_var, command=toggle_keyword_visibility).pack(anchor="w")
    def load_keywords_file():
        fp = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if fp:
            try:
                with open(fp, "r", errors="replace") as kf:
                    kw_box.insert("end", "\n" + kf.read().strip())
            except Exception as e:
                messagebox.showerror("Error loading file", str(e))
    tk.Button(f_btn_bar, text="Load Custom Keywords File (.txt)...", font=("Helvetica", 8), command=load_keywords_file).pack(side="left", pady=2)
    def execute_triage_loop():
        src = src_path_var.get()
        out = out_path_var.get()
        m = mode_var.get()
        r = recursive_var.get()
        b = bodies_var.get()
        s = sigs_var.get()
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
                    messagebox.showerror("Regex Syntax Failure", f'Broken Expression Found on Entry Line {idx}:\n"{pattern}"\n\nDetails: {str(regex_err)}')
                    return
        if m == 3 and not k:
            nomenclature_found = any(f.lower().endswith(".key") and "_domainkey" in f for f in os.listdir(src)) if os.path.exists(src) else False
            if not nomenclature_found:
                if not messagebox.askyesno("Key Configuration Warning", "Mode 3 selected but no fallback key registered, and no nomenclature keys found in directory. Proceed anyway?"):
                    return
        root.destroy()
        run_bulk_processing(src, out, m, r, b, s, k, keywords_list,
                            global_key_origin=global_key_buffer["origin"] or "pasted",
                            global_key_source_path=global_key_buffer["path"])
    tk.Button(root, text="LAUNCH TRIAGE PROCESSING LOOP", font=("Helvetica", 10, "bold"), bg="#1a7f37", fg="white", command=execute_triage_loop, height=2, width=34).pack(pady=15)
    tk.Label(root, text=f"Tool: {__tool_name__} | Version: {__version__} | Author: {__author__} ({__email__}) | License: {__license__}", font=("Helvetica", 7), fg="gray").pack(side="bottom", pady=5)
    root.mainloop()
def main():
    ap = argparse.ArgumentParser(description="DKIM Bulk Signature Forensic Triaging Suite.",
                                 epilog=f"v{__version__} | {__url__} | Licensed under the Apache License 2.0")
    ap.add_argument("--src", help="Source folder targeting raw EML streams.")
    ap.add_argument("--out", help="Output folder targeting artifact storage layouts.")
    ap.add_argument("--mode", type=int, choices=[1, 2, 3], help="Public key verification mapping track lane.")
    ap.add_argument("--no-gui", action="store_true", help="Force command-line parsing options, skipping GUI window parameters.")
    args = ap.parse_args()
    if args.no_gui:
        if not args.src or not args.out or not args.mode:
            sys.exit("Error: CLI execution via --no-gui requires --src, --out, and --mode options configured explicitly.")
        run_bulk_processing(args.src, args.out, args.mode, recursive=True, save_bodies=True, save_sigs=True, global_key=None, raw_keywords_list=[])
    else:
        launch_gui_panel()
if __name__ == "__main__":
    main()
