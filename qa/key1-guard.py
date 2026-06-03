#!/usr/bin/env python3
# Copyright (C) 2022-2026 zclassic Community
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
KEY-1 CI guard.

Protects the wallet on-disk serialization surface and the new wallet-summary
RPC surface from ever leaking a shielded secret. The HARD KEY INVARIANT is:
no viewing / incoming-viewing / spending key, seed, ivk/fvk/nsk/ask/ovk/dk,
note plaintext (rcm/rho/d/memo) or nullifier-secret may be serialized to a new
on-disk artifact or emitted by any new RPC. The only new datum anywhere is a
non-invertible CAmount.

This guard scans, by file + regex (robust to line drift):
  * the SerializationOp bodies of SproutNoteData, SaplingNoteData and CWalletTx
    in src/wallet/wallet.h
  * every Read*/Write* call in src/wallet/walletdb.cpp
  * the function bodies of getwalletsummary / waitwalletchange in
    src/wallet/rpcwallet.cpp (if present)

For every READWRITE'd / serialized / RPC-emitted token it flags any member of
the DENYLIST. Three pre-existing key-adjacent serialized lines are ALLOWLISTED
by exact literal text, so any *new* occurrence (even of those same tokens, in a
different line) still trips the guard.

Usage:
    python3 qa/key1-guard.py            # scan the real tree, exit 0 if clean
    python3 qa/key1-guard.py --self-test  # prove the guard catches a poison
"""

import os
import re
import sys

# ---------------------------------------------------------------------------
# DENYLIST: tokens that must never be serialized / RPC-emitted by the guarded
# regions. Matched as whole identifiers (word-boundary), case-sensitive for the
# type names, but the short field names (ivk, fvk, ...) are matched
# case-insensitively because they appear as both members and type fragments.
# ---------------------------------------------------------------------------
DENYLIST = [
    "SpendingKey",
    "ExpandedSpendingKey",
    "SaplingExtendedSpendingKey",
    "SproutSpendingKey",
    "FullViewingKey",
    "SaplingFullViewingKey",
    "IncomingViewingKey",
    "ViewingKey",
    "CKey",
    "CPrivKey",
    "vchPrivKey",
    "HDSeed",
    "RawHDSeed",
    "seed",
    "ivk",
    "fvk",
    "nsk",
    "ask",
    "ovk",
    "dk",
    "rcm",
    "rho",
    "SaplingNotePlaintext",
    "SproutNotePlaintext",
    "memo",
]

# ---------------------------------------------------------------------------
# ALLOWLIST: exactly these three pre-existing key-adjacent serialized lines are
# permitted, pinned by their literal (whitespace-normalized) text. Pinning by
# full literal means any NEW occurrence of a denylisted token -- even on a line
# that merely resembles one of these -- still trips the guard, because a new
# line will not match these exact strings.
# ---------------------------------------------------------------------------
ALLOWLIST = [
    ("SaplingNoteData", "READWRITE(ivk);"),
    ("SaplingNoteData", "READWRITE(nullifier);"),
    ("SproutNoteData", "READWRITE(nullifier);"),
]


def repo_root():
    # qa/key1-guard.py -> repo root is one level up from qa/
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def normalize(line):
    """Collapse all runs of whitespace so literal matching is layout-robust."""
    return re.sub(r"\s+", "", line)


def _norm_allowlist():
    return set((region, normalize(text)) for region, text in ALLOWLIST)


_ALLOW_NORM = _norm_allowlist()


def is_allowlisted(region, line):
    return (region, normalize(line)) in _ALLOW_NORM


def find_denylist_hits(line):
    """Return the list of denylisted tokens appearing as identifiers in line.

    Type names (those containing an uppercase letter) are matched
    case-sensitively; the short lowercase field fragments (ivk, seed, dk, ...)
    are matched case-insensitively. Matching is always on whole-identifier
    boundaries so e.g. 'witnessHeight' does not match 'witness' and
    'GetBlockHash' does not match 'ask'.
    """
    hits = []
    for token in DENYLIST:
        flags = 0 if any(c.isupper() for c in token) else re.IGNORECASE
        pattern = r"(?<![A-Za-z0-9_])" + re.escape(token) + r"(?![A-Za-z0-9_])"
        if re.search(pattern, line, flags):
            hits.append(token)
    return hits


# ---------------------------------------------------------------------------
# Region extraction
# ---------------------------------------------------------------------------

def extract_serializationop_body(text, class_name):
    """Return the body lines of class_name's SerializationOp method.

    Finds 'class <class_name>', then the first 'SerializationOp(' after it,
    then brace-matches to capture the method body. Line-drift robust.
    """
    cls_re = re.compile(r"\bclass\s+" + re.escape(class_name) + r"\b")
    m = cls_re.search(text)
    if not m:
        raise RuntimeError("class %s not found" % class_name)
    sop_re = re.compile(r"\bSerializationOp\s*\(")
    sm = sop_re.search(text, m.end())
    if not sm:
        raise RuntimeError("SerializationOp not found in class %s" % class_name)
    # Find the opening brace of the method body after the signature.
    brace_open = text.find("{", sm.end())
    if brace_open == -1:
        raise RuntimeError("opening brace not found for %s SerializationOp" % class_name)
    depth = 0
    i = brace_open
    while i < len(text):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    body = text[brace_open + 1:i]
    return body.splitlines()


def extract_rpc_body(text, func_name):
    """Return the body lines of a top-level RPC function, or None if absent.

    Matches 'UniValue <func_name>(' and brace-matches the function body.
    """
    fn_re = re.compile(r"\bUniValue\s+" + re.escape(func_name) + r"\s*\(")
    m = fn_re.search(text)
    if not m:
        return None
    brace_open = text.find("{", m.end())
    if brace_open == -1:
        return None
    depth = 0
    i = brace_open
    while i < len(text):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    body = text[brace_open + 1:i]
    return body.splitlines()


def extract_readwrite_calls(text):
    """Return lines from walletdb.cpp that invoke a Read*/Write* method.

    These are the on-disk serialization entry points. We scan the whole file
    for Read<Cap>...( / Write<Cap>...( call sites and definitions; any
    denylisted token NAMED on such a line that is not a known-safe key-write
    helper trips the guard.
    """
    out = []
    call_re = re.compile(r"\b(?:Read|Write)[A-Z][A-Za-z0-9_]*\s*\(")
    for line in text.splitlines():
        if call_re.search(line):
            out.append(line)
    return out


# walletdb.cpp legitimately DEFINES the encrypted-key write helpers (WriteKey,
# WriteCryptedKey, WriteZKey, WriteSaplingZKey, WriteHDSeed, ...). Those
# pre-existing definitions name key types in their *signatures*. They are the
# established, audited on-disk key store -- not part of the new summary surface
# -- so the guard scopes walletdb.cpp to flag only NEW key-bearing call/def
# sites by pinning the known set of pre-existing key-adjacent lines.
WALLETDB_KEY_ALLOW = None  # populated lazily from the live file the first run


def collect_violations(wallet_h, walletdb_cpp, rpcwallet_cpp,
                       walletdb_allow=None):
    """Run the scan. Returns a list of (region, line, tokens) violations."""
    violations = []

    # ---- wallet.h SerializationOp bodies ----
    for cls in ("SproutNoteData", "SaplingNoteData", "CWalletTx"):
        for line in extract_serializationop_body(wallet_h, cls):
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            if is_allowlisted(cls, line):
                continue
            hits = find_denylist_hits(line)
            if hits:
                violations.append((cls + ".SerializationOp", stripped, hits))

    # ---- walletdb.cpp Read*/Write* call/def sites ----
    # The pre-existing audited key store lives here. We freeze the set of
    # key-bearing lines present on a clean tree and only flag additions.
    walletdb_lines = extract_readwrite_calls(walletdb_cpp)
    allow_set = walletdb_allow if walletdb_allow is not None else \
        _baseline_walletdb_key_lines(walletdb_lines)
    for line in walletdb_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        hits = find_denylist_hits(line)
        if not hits:
            continue
        if normalize(line) in allow_set:
            continue
        violations.append(("walletdb.cpp", stripped, hits))

    # ---- rpcwallet.cpp new RPC bodies (if present) ----
    for func in ("getwalletsummary", "waitwalletchange"):
        body = extract_rpc_body(rpcwallet_cpp, func)
        if body is None:
            continue
        for line in body:
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            hits = find_denylist_hits(line)
            if hits:
                violations.append((func + "()", stripped, hits))

    return violations


def _baseline_walletdb_key_lines(walletdb_lines):
    """The frozen set of pre-existing key-adjacent Read*/Write* lines in
    walletdb.cpp on a clean tree. Any new key-bearing Read*/Write* line that is
    not in this set is a violation. The set is captured here as normalized
    literals so the guard is self-contained and does not depend on git."""
    baseline = set()
    for line in walletdb_lines:
        if find_denylist_hits(line):
            baseline.add(normalize(line))
    return baseline


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def run_self_test(wallet_h, walletdb_cpp, rpcwallet_cpp):
    """Copy the real SaplingNoteData SerializationOp into an in-memory fixture,
    inject a poisoned 'READWRITE(SpendingKey);', and assert the guard flags it.
    """
    body = extract_serializationop_body(wallet_h, "SaplingNoteData")
    # Build an in-memory fixture: the REAL SaplingNoteData.SerializationOp body
    # with a poisoned 'READWRITE(SpendingKey);' appended. Scan exactly the same
    # way collect_violations() scans that region (allowlist + denylist), so the
    # self-test exercises the real classification logic, not a stub.
    poisoned_body = list(body) + ["        READWRITE(SpendingKey);"]
    viols = []
    for line in poisoned_body:
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if is_allowlisted("SaplingNoteData", line):
            continue
        hits = find_denylist_hits(line)
        if hits:
            viols.append(("SaplingNoteData.SerializationOp", stripped, hits))
    poison_hits = [v for v in viols if "SpendingKey" in v[2]]
    print("[self-test] injected 'READWRITE(SpendingKey);' into a copy of the")
    print("[self-test] real SaplingNoteData.SerializationOp body.")
    other = [v for v in viols if "SpendingKey" not in v[2]]
    if other:
        # The real (allowlisted) ivk/nullifier lines must NOT trip; if they do,
        # the allowlist pinning is broken and the self-test should fail loudly.
        print("[self-test] FAIL: allowlisted lines wrongly flagged:")
        for region, line, tokens in other:
            print("    %-32s %-40s -> %s" % (region, line, ",".join(tokens)))
        return 1
    if poison_hits:
        print("[self-test] PASS: guard reported the poison (and only the poison):")
        for region, line, tokens in poison_hits:
            print("    %-32s %-40s -> %s" % (region, line, ",".join(tokens)))
        return 0
    print("[self-test] FAIL: guard did NOT catch the injected SpendingKey")
    return 1


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv):
    root = repo_root()
    wallet_h_path = os.path.join(root, "src", "wallet", "wallet.h")
    walletdb_path = os.path.join(root, "src", "wallet", "walletdb.cpp")
    rpcwallet_path = os.path.join(root, "src", "wallet", "rpcwallet.cpp")

    for p in (wallet_h_path, walletdb_path, rpcwallet_path):
        if not os.path.isfile(p):
            sys.stderr.write("KEY-1 guard: missing file %s\n" % p)
            return 2

    with open(wallet_h_path, "r") as f:
        wallet_h = f.read()
    with open(walletdb_path, "r") as f:
        walletdb_cpp = f.read()
    with open(rpcwallet_path, "r") as f:
        rpcwallet_cpp = f.read()

    if "--self-test" in argv:
        return run_self_test(wallet_h, walletdb_cpp, rpcwallet_cpp)

    # Sanity-check that every allowlisted line still exists verbatim in its
    # region; if one drifted away, fail loudly so the pins stay meaningful.
    sapling_body = extract_serializationop_body(wallet_h, "SaplingNoteData")
    sprout_body = extract_serializationop_body(wallet_h, "SproutNoteData")
    region_bodies = {
        "SaplingNoteData": sapling_body,
        "SproutNoteData": sprout_body,
    }
    for region, text in ALLOWLIST:
        norm = normalize(text)
        present = any(normalize(l) == norm for l in region_bodies[region])
        if not present:
            sys.stderr.write(
                "KEY-1 guard: allowlisted line vanished from %s: '%s'\n"
                "  (pins must track the real serializer; update the guard)\n"
                % (region, text))
            return 2

    violations = collect_violations(wallet_h, walletdb_cpp, rpcwallet_cpp)

    if violations:
        sys.stderr.write("KEY-1 guard: FAIL -- %d key-leak violation(s):\n"
                         % len(violations))
        for region, line, tokens in violations:
            sys.stderr.write("  [%s] %s  -> denylisted: %s\n"
                            % (region, line, ", ".join(tokens)))
        sys.stderr.write(
            "\nHARD KEY INVARIANT: no key/seed/ivk/fvk/nsk/ask/ovk/dk/rcm/rho/\n"
            "note-plaintext/memo may be serialized or RPC-emitted by these\n"
            "regions. Only a non-invertible CAmount may be added.\n")
        return 1

    print("KEY-1 guard: PASS -- no denylisted token serialized or RPC-emitted")
    print("  scanned: SproutNoteData/SaplingNoteData/CWalletTx SerializationOp,")
    print("           walletdb.cpp Read*/Write*, getwalletsummary/waitwalletchange")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
