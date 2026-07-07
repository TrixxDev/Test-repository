#!/usr/bin/env python3
"""Generate user/ca_roots.h from a directory of trusted root certificates.

Phase 15.5.2: turns "update the trust store" into "update the certs in
tools/trust_roots/, then re-run this script" instead of hand-editing a byte
array. The generated header is committed like any other generated source
(kernel/embedded_user.c is the existing precedent) -- regenerate and diff
rather than hand-patch it.

Each file in the input directory must be a single PEM certificate that is:
  - self-issued (subject == issuer): a trust anchor, not a chain link;
  - basicConstraints CA:TRUE;
  - RSA, or ECDSA on P-256/P-384 -- the only public-key types Aurora's x509/
    crypto stack implements (see x509/x509.h's X509_PK_* enum). Anything else
    (P-521, Ed25519, ...) is rejected outright rather than silently included
    as a root nothing can ever actually verify against.
Any check failure aborts with a nonzero exit and no output written, so a bad
update can't ship quietly.

Usage: python3 tools/gen_ca_roots.py [trust_roots_dir] [output_header]
Defaults: tools/trust_roots -> user/ca_roots.h
"""
import glob
import os
import subprocess
import sys


def run_text(args):
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"error: {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout


def run_bytes(args):
    r = subprocess.run(args, capture_output=True)
    if r.returncode != 0:
        sys.exit(f"error: {' '.join(args)} failed: {r.stderr.decode(errors='replace').strip()}")
    return r.stdout


def field(pem_path, *args):
    return run_text(["openssl", "x509", "-in", pem_path, "-noout", *args]).strip()


def cn_of(subject_line):
    """'subject=C = US, O = ..., OU = Foo Root CA - R3, CN = Foo' -> a display
    name for the table comment/entry. Almost always just CN ('ISRG Root X1'),
    but some issuers (GlobalSign's R3) put the actual distinguishing name in
    OU and leave CN a bare, ambiguous org name -- fall back to OU when CN
    doesn't even mention "root" but an OU does."""
    dn = subject_line.split("=", 1)[1]
    cn = ou = ""
    for part in dn.split(", "):
        part = part.strip()
        if part.startswith("CN =") and not cn:
            cn = part[len("CN ="):].strip().strip('"')
        elif part.startswith("OU =") and not ou:
            ou = part[len("OU ="):].strip().strip('"')
    if cn and "root" not in cn.lower() and ou and "root" in ou.lower():
        return ou
    return cn or dn.strip()


def classify_key(text, pem_path):
    if "Public Key Algorithm: rsaEncryption" in text:
        return "RSA"
    if "Public Key Algorithm: id-ecPublicKey" in text:
        if "NIST CURVE: P-256" in text:
            return "EC P-256"
        if "NIST CURVE: P-384" in text:
            return "EC P-384"
        sys.exit(f"error: {pem_path}: unsupported EC curve (Aurora only implements P-256/P-384)")
    sys.exit(f"error: {pem_path}: unsupported public key algorithm (Aurora only implements RSA/ECDSA)")


def load_root(pem_path):
    subj = field(pem_path, "-subject")
    iss = field(pem_path, "-issuer")
    if subj.split("=", 1)[1] != iss.split("=", 1)[1]:
        sys.exit(f"error: {pem_path}: not self-issued (subject != issuer) -- "
                 f"a trust anchor must be one, not a link in a chain")
    text = field(pem_path, "-text")
    if "CA:TRUE" not in text:
        sys.exit(f"error: {pem_path}: not a CA (basicConstraints CA:TRUE missing)")
    kind = classify_key(text, pem_path)
    der = run_bytes(["openssl", "x509", "-in", pem_path, "-outform", "DER"])
    return cn_of(subj), der, kind


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "tools/trust_roots"
    out = sys.argv[2] if len(sys.argv) > 2 else "user/ca_roots.h"
    pems = sorted(glob.glob(os.path.join(src, "*.pem")))
    if not pems:
        sys.exit(f"error: no .pem files found in {src}")

    entries = [load_root(pem) for pem in pems]

    lines = [
        "/* Curated public CA roots for user/httpsget -- GENERATED, do not hand-edit.",
        " *",
        " * Regenerate with: python3 tools/gen_ca_roots.py",
        " * (reads the PEM certs in tools/trust_roots, writes this file -- see",
        " * that script's header for the acceptance checks every root must pass: self-issued,",
        " * CA:TRUE, RSA or ECDSA P-256/P-384). Public certificates -- safe to",
        " * commit; no private keys are ever involved. Phase 15.5. */",
        "#pragma once",
    ]
    for i, (name, der, kind) in enumerate(entries):
        lines.append(f"static const unsigned char ca_root_{i}[] = {{ /* {name} ({kind}, {len(der)}B) */")
        for j in range(0, len(der), 12):
            chunk = der[j:j + 12]
            lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
        lines.append("};")
    lines.append("static const struct { const unsigned char *der; unsigned len; const char *name; } ca_roots[] = {")
    for i, (name, _der, _kind) in enumerate(entries):
        lines.append(f'    {{ ca_root_{i}, sizeof ca_root_{i}, "{name}" }},')
    lines.append("};")
    lines.append("#define CA_ROOTS_N (sizeof ca_roots / sizeof ca_roots[0])")

    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")

    rsa = sum(1 for _, _, k in entries if k == "RSA")
    p256 = sum(1 for _, _, k in entries if k == "EC P-256")
    p384 = sum(1 for _, _, k in entries if k == "EC P-384")
    print(f"wrote {out}: {len(entries)} roots ({rsa} RSA, {p256} EC P-256, {p384} EC P-384)")


if __name__ == "__main__":
    main()
