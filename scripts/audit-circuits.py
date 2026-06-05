#!/usr/bin/env python3
"""
Reusable zk-SNARK circuit soundness auditor for Zclassic's shielded circuits.

Operationalizes the "find under-constrained circuit elements" methodology (the
class of bug behind the June-2026 Zcash Orchard counterfeiting flaw) across every
shielded-circuit source file Zclassic actually compiles:

  - Sprout C++ circuit (libsnark/R1CS, legacy BCTV14 verify path): src/zcash/circuit/*.tcc
  - Sprout Rust circuit (bellman/Groth16, ACTIVE path for new JoinSplits) and the
    Sapling Spend/Output circuit + supporting gadgets, both bundled inside the
    pinned librustzcash source tarball under depends/sources/.

For each file it builds a soundness-audit prompt tailored to that file's proving
system (the assign/copy-constraint pattern differs between halo2, bellman, and
libsnark), then either:

  --emit  (default) writes one ready-to-run prompt per file + a manifest and a
          SOUND/GAP checklist. No network, no API key. Feed the prompts to
          Claude Code agents (or paste them in) and record verdicts in the
          checklist. This is the safe default.

  --run   calls the Claude API (Opus 4.8, adaptive thinking, streaming, effort
          high) once per file and collects a structured SOUND / GAP_FOUND /
          INCONCLUSIVE verdict into a JSON report. Requires `pip install anthropic`
          and ANTHROPIC_API_KEY (or `ant auth login`). Read-only: it only reads
          circuit source; it never edits the repo.

This does NOT prove a circuit correct. A SOUND verdict means no missing-constraint
(Orchard-class) gap was found in that file. It does not cover the proving-system
parameters / trusted setup, the bellman/libsnark verifier internals, or non-circuit
bugs.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
MODEL = "claude-opus-4-8"

# ---------------------------------------------------------------------------
# Per-proving-system description of the soundness-bug pattern. The class is the
# same everywhere (a value is witnessed but never constrained); the *mechanism*
# differs, so the prompt names the exact thing to look for.
# ---------------------------------------------------------------------------
SYSTEMS = {
    "libsnark": (
        "libsnark R1CS (C++ protoboard gadgets). The bug pattern is a value set in "
        "`generate_r1cs_witness()` with no matching constraint added in "
        "`generate_r1cs_constraints()` (e.g. a `pb.val(x) = ...` or `fill_with_bits` "
        "whose variable is never pinned by an `add_r1cs_constraint` / "
        "`generate_boolean_r1cs_constraint`). Check parity between the two methods of "
        "every gadget."
    ),
    "bellman": (
        "bellman R1CS / Groth16 over Jubjub. The bug pattern is a variable produced by "
        "`AllocatedNum::alloc` / `AllocatedBit::alloc` / `.get_value()` with no matching "
        "`cs.enforce(...)` binding it (a coordinate computed but not constrained on-curve, "
        "a conditional select whose result isn't enforced, scalar bits not boolean-"
        "constrained, a doubling/addition output coordinate witnessed but not pinned). "
        "This is the bellman analog of Orchard's halo2 assign_advice-without-copy_advice."
    ),
    "halo2": (
        "halo2 PLONKish (advice columns + permutation copy constraints). The exact "
        "Orchard bug: `assign_advice()` used where `copy_advice()` was required, so a "
        "value isn't bound by an equality/permutation constraint."
    ),
}

PROMPT_TEMPLATE = """\
You are auditing a zk-SNARK circuit for SOUNDNESS bugs — the class that lets a
malicious prover satisfy the circuit with values that should be impossible,
enabling counterfeiting or double-spends. This file is part of {role}.

Proving system: {system_label}
Bug pattern to hunt: {system_desc}

Context: the June-2026 Zcash Orchard counterfeiting flaw was an under-constrained
element of the variable-base scalar-multiplication gadget — the diversified-address
integrity check pk_d = [ivk]·g_d could be satisfied for arbitrary inputs, so a note
could be spent repeatedly under different nullifiers. Find the analog here, if any.

For EACH gadget / function in the file:
  1. List every variable that is ALLOCATED or whose witness value is computed.
  2. List every constraint actually added.
  3. Check parity: is every witnessed value bound by a constraint? Are points kept
     on-curve? Are bit decompositions boolean-constrained? Are conditional selects /
     sign negations ENFORCED (not merely witnessed)? Are summed values range-bounded
     so the field sum cannot wrap (the classic inflation bug)?
  4. Flag any value used downstream but NOT constrained — that is the bug.

Priorities: in-circuit EC scalar multiplication; range/overflow guards on value
balance; booleanity of every bit. Spend authority, nullifier derivation, note-
commitment binding, and Merkle membership (correctly gated for dummy/zero-value
inputs) must each be constrained.

Be rigorous and skeptical — do NOT assume correctness because it is upstream code.
But do NOT invent bugs: if a value is correctly constrained, say so and cite the
exact constraint line as evidence. Quote file:line for every claim. Do not modify
any file.

FILE: {path}
--------------------------------------------------------------------------------
{source}
--------------------------------------------------------------------------------

End with a final line of strict JSON (no prose after it) matching:
{{"file": "...", "proving_system": "{system}", "verdict": "SOUND"|"GAP_FOUND"|"INCONCLUSIVE",
 "findings": [{{"gadget": "...", "location": "file:line", "witnessed": "...",
   "constrained": true|false, "confidence": "low"|"medium"|"high", "note": "..."}}],
 "summary": "..."}}
"""

VERDICT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "file": {"type": "string"},
        "proving_system": {"type": "string"},
        "verdict": {"type": "string", "enum": ["SOUND", "GAP_FOUND", "INCONCLUSIVE"]},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "gadget": {"type": "string"},
                    "location": {"type": "string"},
                    "witnessed": {"type": "string"},
                    "constrained": {"type": "boolean"},
                    "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                    "note": {"type": "string"},
                },
                "required": ["gadget", "location", "witnessed", "constrained", "confidence", "note"],
            },
        },
        "summary": {"type": "string"},
    },
    "required": ["file", "proving_system", "verdict", "findings", "summary"],
}


class Circuit:
    def __init__(self, name: str, path: Path, system: str, role: str):
        self.name = name
        self.path = path
        self.system = system
        self.role = role

    @property
    def system_label(self) -> str:
        return {"libsnark": "libsnark/R1CS", "bellman": "bellman/Groth16", "halo2": "halo2/PLONKish"}[self.system]


def extract_rust_circuits(workdir: Path) -> Optional[Path]:
    """Extract sapling-crypto/src/circuit/** from the pinned librustzcash tarball.

    Returns the extracted sapling-crypto/src/circuit dir, or None if the tarball
    is absent (e.g. a clean checkout that hasn't fetched depends sources)."""
    tarballs = glob.glob(str(REPO_ROOT / "depends/sources/librustzcash-*.tar.gz"))
    if not tarballs:
        return None
    tarball = Path(sorted(tarballs)[-1])
    base = tarball.name[: -len(".tar.gz")]
    circuit_dir = workdir / base / "sapling-crypto" / "src" / "circuit"
    if not circuit_dir.exists():
        with tarfile.open(tarball, "r:gz") as tf:
            prefix = f"{base}/sapling-crypto/src/"
            members = [m for m in tf.getmembers() if m.name.startswith(prefix)]
            # Defensive: skip any path-traversing members.
            safe = [m for m in members if ".." not in Path(m.name).parts]
            tf.extractall(workdir, members=safe)
    return circuit_dir if circuit_dir.exists() else None


def classify_rust(rel: str) -> tuple[str, str]:
    """Map a sapling-crypto circuit/*.rs path to (system, role)."""
    if rel.startswith("sapling/"):
        return "bellman", "the Sapling Spend/Output circuit (bellman/Groth16)"
    if rel.startswith("sprout/"):
        return "bellman", "the ACTIVE Groth16 Sprout JoinSplit circuit (new-note verify path)"
    return "bellman", "a load-bearing Sapling circuit gadget (bellman/Groth16)"


def discover(workdir: Path) -> List[Circuit]:
    circuits: List[Circuit] = []

    # 1. Sprout C++ libsnark circuit — in-repo, complete.
    sprout_cpp = sorted((REPO_ROOT / "src/zcash/circuit").glob("*.tcc"))
    for p in sprout_cpp:
        circuits.append(
            Circuit(
                name=f"sprout-cpp/{p.name}",
                path=p,
                system="libsnark",
                role="the Sprout JoinSplit circuit (libsnark/BCTV14, legacy verify path)",
            )
        )

    # 2. Rust circuits (Sapling + Groth16 Sprout) from the pinned tarball.
    circuit_dir = extract_rust_circuits(workdir)
    if circuit_dir is not None:
        for p in sorted(circuit_dir.rglob("*.rs")):
            rel = p.relative_to(circuit_dir).as_posix()
            if rel.startswith("test/") or rel.endswith("/test/mod.rs"):
                continue  # skip the test harness
            system, role = classify_rust(rel)
            circuits.append(Circuit(name=f"rust/{rel}", path=p, system=system, role=role))

    return circuits


def build_prompt(c: Circuit) -> str:
    source = c.path.read_text(errors="replace")
    return PROMPT_TEMPLATE.format(
        role=c.role,
        system=c.system,
        system_label=c.system_label,
        system_desc=SYSTEMS[c.system],
        path=c.name,
        source=source,
    )


# ---------------------------------------------------------------------------
# --emit : write prompt-packs + manifest + checklist (no API).
# ---------------------------------------------------------------------------
def emit(circuits: List[Circuit], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    manifest = []
    for c in circuits:
        slug = c.name.replace("/", "__")
        prompt_path = out / f"{slug}.prompt.md"
        prompt_path.write_text(build_prompt(c))
        manifest.append(
            {
                "name": c.name,
                "source_path": str(c.path),
                "proving_system": c.system,
                "role": c.role,
                "prompt": str(prompt_path),
                "verdict": None,  # fill in after auditing
            }
        )
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    lines = ["# Circuit soundness audit checklist", ""]
    lines.append("Run each prompt through Opus 4.8 (a Claude Code agent, or `--run`), record the verdict.")
    lines.append("")
    by_sys: Dict[str, List[dict]] = {}
    for m in manifest:
        by_sys.setdefault(m["proving_system"], []).append(m)
    for sysname, items in by_sys.items():
        lines.append(f"## {sysname} ({len(items)} files)")
        for m in items:
            lines.append(f"- [ ] `{m['name']}` — {m['role']}  → prompt: `{m['prompt']}`")
        lines.append("")
    if not any(c.system == "halo2" for c in circuits):
        lines.append("## halo2 (Orchard)")
        lines.append("- n/a — no halo2/Orchard code in this codebase (pre-NU5). The Orchard bug class does not apply.")
        lines.append("")
    (out / "CHECKLIST.md").write_text("\n".join(lines))

    print(f"Wrote {len(circuits)} prompt(s) + manifest.json + CHECKLIST.md to {out}")
    print("Next: feed each *.prompt.md to an Opus 4.8 agent, or rerun with --run to call the API.")


# ---------------------------------------------------------------------------
# --run : call the Claude API per file, collect structured verdicts.
# ---------------------------------------------------------------------------
def run(circuits: List[Circuit], out: Path, effort: str) -> int:
    try:
        import anthropic
    except ImportError:
        print("error: --run needs the Anthropic SDK. Install with: pip install anthropic", file=sys.stderr)
        return 2

    client = anthropic.Anthropic()  # ANTHROPIC_API_KEY / ant auth profile from env
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for c in circuits:
        print(f"[audit] {c.name} ({c.system}) ...", file=sys.stderr, flush=True)
        prompt = build_prompt(c)
        # Stream (large circuit + reasoning), adaptive thinking, effort high,
        # structured output for the verdict.
        with client.messages.stream(
            model=MODEL,
            max_tokens=64000,
            thinking={"type": "adaptive"},
            output_config={"effort": effort, "format": {"type": "json_schema", "schema": VERDICT_SCHEMA}},
            messages=[{"role": "user", "content": prompt}],
        ) as stream:
            message = stream.get_final_message()
        text = next((b.text for b in message.content if b.type == "text"), "")
        try:
            verdict = json.loads(text)
        except json.JSONDecodeError:
            verdict = {"file": c.name, "proving_system": c.system, "verdict": "INCONCLUSIVE",
                       "findings": [], "summary": "could not parse model JSON output"}
        verdict.setdefault("file", c.name)
        results.append(verdict)
        v = verdict.get("verdict", "INCONCLUSIVE")
        gaps = [f for f in verdict.get("findings", []) if f.get("constrained") is False]
        print(f"         -> {v}" + (f"  ({len(gaps)} unconstrained finding(s))" if gaps else ""), file=sys.stderr)

    (out / "report.json").write_text(json.dumps(results, indent=2) + "\n")

    print("\n== Circuit soundness audit ==")
    for r in results:
        flag = "" if r["verdict"] == "SOUND" else "  <-- REVIEW"
        print(f"{r['verdict']:13} {r['file']}{flag}")
    any_gap = any(r["verdict"] == "GAP_FOUND" for r in results)
    print(f"\nReport: {out / 'report.json'}")
    print("VERDICT: " + ("GAP(S) FOUND — review report.json" if any_gap else
                          "no Orchard-class soundness gap found in the audited circuits"))
    return 1 if any_gap else 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--emit", action="store_true", help="Write prompt-packs + manifest (default; no API).")
    mode.add_argument("--run", action="store_true", help="Call the Claude API per file and collect verdicts.")
    p.add_argument("--out", default=str(REPO_ROOT / "circuit-audit"), help="Output directory.")
    p.add_argument("--workdir", default=None, help="Where to extract the Rust tarball (default: a temp dir).")
    p.add_argument("--only", action="append", default=[], help="Substring filter on circuit name (repeatable).")
    p.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"],
                   help="Effort for --run (default high).")
    p.add_argument("--list", action="store_true", help="List discovered circuits and exit.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    workdir = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="zcl-circuit-audit-"))
    workdir.mkdir(parents=True, exist_ok=True)

    circuits = discover(workdir)
    if args.only:
        circuits = [c for c in circuits if any(s in c.name for s in args.only)]
    if not circuits:
        print("error: no circuit files found (is depends/sources fetched?).", file=sys.stderr)
        return 2

    if args.list:
        for c in circuits:
            print(f"{c.system:9} {c.name}\t{c.path}")
        return 0

    out = Path(args.out)
    if args.run:
        return run(circuits, out, args.effort)
    emit(circuits, out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
