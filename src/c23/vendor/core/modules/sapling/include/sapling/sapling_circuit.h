/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Ported from librustzcash / bellman / sapling-crypto
 * (The Zcash developers / Electric Coin Company), pinned commit
 * 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5, MIT / Apache-2.0. Reimplemented in
 * C23; no reference code is linked into the production binary.
 *
 * Sapling spend and output circuit synthesis.
 * Generates R1CS constraints and witness for Groth16 proving. */

#ifndef ZCL_SAPLING_SAPLING_CIRCUIT_H
#define ZCL_SAPLING_SAPLING_CIRCUIT_H

#include "sapling/groth16_prover.h"
#include "sapling/fr.h"
#include <stdint.h>
#include <stdbool.h>

#define SAPLING_MERKLE_DEPTH 32

/* ── Spend Circuit ──────────────────────────────────────────────── */

/* Private witness for a Sapling spend */
struct sapling_spend_witness {
    /* Spending key components */
    uint8_t ak[32];           /* spend validating key (Jubjub compressed) */
    uint8_t nsk[32];          /* nullifier private key (Fs scalar) */

    /* Re-randomization */
    uint8_t ar[32];           /* randomness for rk = ak + ar*G */

    /* Note being spent */
    uint64_t value;           /* note value in zatoshis */
    uint8_t diversifier[11];  /* payment address diversifier */
    uint8_t pk_d[32];         /* diversified transmission key */
    uint8_t rcm[32];          /* note commitment randomness (Fs) */

    /* Merkle tree proof */
    uint8_t auth_path[SAPLING_MERKLE_DEPTH][32]; /* sibling hashes */
    bool auth_path_bits[SAPLING_MERKLE_DEPTH];   /* position bits */

    /* Value commitment randomness */
    uint8_t rcv[32];          /* value commitment randomness (Fs) */
};

/* Public inputs for a Sapling spend (computed from witness) */
struct sapling_spend_inputs {
    uint8_t rk[32];           /* randomized verification key */
    uint8_t cv[32];           /* value commitment */
    uint8_t anchor[32];       /* Merkle root */
    uint8_t nullifier[32];    /* nullifier */
};

/* Synthesize a Sapling spend circuit.
 * Populates cs with all constraints and witness values.
 * Returns true if synthesis succeeds. */
bool sapling_spend_synthesize(struct constraint_system *cs,
                               const struct sapling_spend_witness *wit,
                               const struct sapling_spend_inputs *pub);

/* Derive the four public inputs a witness implies: rk, cv, the anchor its
 * authentication path folds to, and its nullifier. Writes `pub` in full and
 * also fills `wit->pk_d` with the DERIVED [ivk] g_d (the circuit computes pk_d
 * itself, so a caller-supplied one is ignored by synthesis and only a derived
 * one keeps the note commitment consistent).
 *
 * Every one of the four is CONSTRAINED against the circuit: sections 5, 14, 22
 * and 28 bind them to public-input slots, so a witness paired with public
 * inputs from anywhere else yields an unsatisfiable R1CS. Callers that build a
 * spend by hand should go through here rather than assembling `pub` themselves.
 * Returns false (logged) if the witness cannot produce them — an invalid
 * diversifier, or an authentication-path element that is not a canonical Fr
 * element. */
bool sapling_spend_derive_public(struct sapling_spend_witness *wit,
                                 struct sapling_spend_inputs *pub);

/* ── Spend-circuit port introspection (H3 lane, test-only surface) ──────────
 *
 * The spend circuit is being ported gadget-by-gadget to match bellman's
 * Spend::synthesize order (variable-allocation order is load-bearing for QAP
 * alignment against the trusted-setup proving key). The traced entry point
 * records a shape checkpoint after each ported section and, optionally, the
 * variable indices of a few key wires, so a shape/parity test can assert the
 * running (constraint,var,input) counts equal the reference trace's cumulative
 * counts for the ported prefix and that intermediate wires (rk, nk) carry the
 * reference-correct values. This does NOT change the production entry point
 * (sapling_spend_synthesize forwards here with NULL out-params). */
struct spend_section_shape {
    const char *name;         /* human-readable section label */
    size_t num_constraints;   /* cs->num_constraints after this section */
    size_t num_vars;          /* cs->num_vars after this section */
    size_t num_inputs;        /* cs->num_inputs after this section */
};

/* Variable indices of key intermediate wires (SIZE_MAX if not yet synthesized).
 * The witness value at these indices can be compared against out-of-circuit
 * reference derivations for a per-wire correctness gate. */
struct spend_wire_probe {
    size_t ak_x, ak_y;   /* witnessed spend-authority key (section 1) */
    size_t rk_x, rk_y;   /* re-randomized key rk = ak + [ar] G (section 4) */
    size_t nk_x, nk_y;   /* nullifier deriving key [nsk] G_proof (section 7) */
    size_t gd_x, gd_y;   /* witnessed g_d = GH("Zcash_gd", d) (section 11) */
    size_t pkd_x, pkd_y; /* pk_d = [ivk] g_d (section 13) */
    size_t cv_x, cv_y;   /* cv = [value] G_v + [rcv] G_rcv (section 14) */
    /* The windowed Pedersen hash of the 576 note-content bits (section 17) and
     * the note commitment that randomizes it, cm = note_hash + [rcm] G_rcm
     * (section 20). Both are full Jubjub points, so a reader can diff x AND y
     * against the out-of-circuit sapling_compute_cm() path; the protocol's
     * `cmu` is just this point's x-coordinate. */
    size_t note_hash_x, note_hash_y; /* PedersenHash(NoteCommitment, note) (17) */
    size_t cm_x, cm_y;               /* cm = note_hash + [rcm] G_rcm    (20) */
    /* The anchor section 21 folds cm.x up to. Published so ONE synthesis run
     * can be checked end to end — the note commitment the circuit computed is
     * the same value that entered the tree fold, which two separately-proven
     * sections cannot establish between them. */
    size_t anchor;                   /* Merkle root over cm.x           (21) */
    /* The 64 little-endian value bits section 14 booleanizes; they also open
     * the note in section 17, so a wrong bit order there is a silent divergence
     * this makes visible. SIZE_MAX-filled when not yet synthesized. */
    size_t value_bit[64];
    /* EdwardsPoint::repr bit wires — 256 boolean variable indices each, in
     * little-endian order. Because Jubjub's compressed encoding is y with x's
     * low bit in the top bit, these bits ARE the bits of the point's 32-byte
     * compressed encoding; that makes them checkable against ground truth
     * rather than merely counted. SIZE_MAX-filled when not yet synthesized. */
    size_t ak_repr[256]; /* representation of ak   (section 8) */
    size_t nk_repr[256]; /* representation of nk   (section 9) */
    size_t gd_repr[256]; /* representation of g_d  (section 15) */
    size_t pkd_repr[256];/* representation of pk_d (section 16) */

    /* blake2s(CRH^ivk) output bit wires (section 10), 256 little-endian bits.
     * bellman's blake2s returns `Boolean`s, which may be a NEGATED view of a
     * wire — so a reader MUST apply `ivk_bit_negated[i]` to the wire's
     * assignment to recover the logical bit:
     *     bit = ivk_bit_negated[i] ? !witness[ivk_bit[i]] : witness[ivk_bit[i]]
     * Ignoring the flag silently inverts bits and the differential fails for a
     * reason that has nothing to do with the circuit. SIZE_MAX-filled when the
     * section has not been synthesized. */
    size_t ivk_bit[256];
    bool   ivk_bit_negated[256];
};

/* bellman truncates the 256-bit blake2s digest to Jubjub `Fs::CAPACITY` bits
 * before using it as a scalar ("drop_5" — 256 - 251), so only the low 251 bits
 * of section 10's output feed section 13. The truncation costs no constraints. */
#define SPEND_IVK_TRUNCATED_BITS 251u

/* Traced synthesis. `sections`/`probe` may be NULL. Writes at most
 * `max_sections` checkpoints and the count reached via `n_sections_out`. */
bool sapling_spend_synthesize_traced(struct constraint_system *cs,
                                      const struct sapling_spend_witness *wit,
                                      const struct sapling_spend_inputs *pub,
                                      struct spend_section_shape *sections,
                                      size_t max_sections,
                                      size_t *n_sections_out,
                                      struct spend_wire_probe *probe);

/* ── Native spend-prover sovereignty status (honest, typed, named) ──────────
 * bellman's Spend::synthesize is 28 sections / 98777 constraints. Counts come
 * from a canonical synthesis; `roundtrip_ready` comes only from the positive
 * native proof -> independent consensus-verifier self-test. */
#define SPEND_CIRCUIT_TOTAL_SECTIONS    28u
#define SPEND_CIRCUIT_TOTAL_CONSTRAINTS 98777u

struct spend_prover_native_status {
    size_t sections_ported;      /* sections synthesized natively today */
    size_t sections_total;       /* SPEND_CIRCUIT_TOTAL_SECTIONS */
    size_t constraints_ported;   /* num_constraints from a canonical synthesis */
    size_t constraints_total;    /* SPEND_CIRCUIT_TOTAL_CONSTRAINTS */
    bool   roundtrip_ready;      /* native circuit -> verifier round-trips? */
    const char *next_blocker;    /* NAME of the next unimplemented section, or
                                    "port complete" when the prefix is whole */
};

/* Report the native spend-prover port coverage. Honest by construction:
 * `roundtrip_ready` stays false while the port is a partial prefix. Runs a
 * canonical (non-secret) synthesis to derive the ported counts — no proving
 * key, no secret material. */
void sapling_spend_prover_native_status(struct spend_prover_native_status *out);

/* Parse a caller-supplied Sapling merkle authentication path into
 * the auth_path / auth_path_bits fields of `wit`. Wire layout:
 *     depth (1) || 32 × (sibling (32) || bit (1))  = 1057 bytes
 * Returns false if `witness_len` is below the fixed 1057-byte layout
 * or the depth byte is not 32. The bounds check is load-bearing:
 * callers route untrusted-length buffers (RPC JSON, wallet blobs,
 * fuzz harnesses) into this path. */
bool sapling_spend_parse_witness(const uint8_t *witness,
                                  size_t witness_len,
                                  struct sapling_spend_witness *wit);

/* ── Output Circuit ─────────────────────────────────────────────── */

/* Private witness for a Sapling output */
struct sapling_output_witness {
    uint64_t value;           /* note value in zatoshis */
    uint8_t diversifier[11];  /* recipient diversifier */
    uint8_t pk_d[32];         /* recipient diversified transmission key */
    uint8_t rcm[32];          /* note commitment randomness (Fs) */
    uint8_t esk[32];          /* ephemeral secret key (Fs) */
    uint8_t rcv[32];          /* value commitment randomness (Fs) */
};

/* Public inputs for a Sapling output */
struct sapling_output_inputs {
    uint8_t cv[32];           /* value commitment */
    uint8_t epk[32];          /* ephemeral public key */
    uint8_t cm[32];           /* note commitment */
};

/* Synthesize a Sapling output circuit. */
bool sapling_output_synthesize(struct constraint_system *cs,
                                const struct sapling_output_witness *wit,
                                const struct sapling_output_inputs *pub);

/* ── Full Proving Interface ─────────────────────────────────────── */

/* Create a Sapling spend proof.
 * Loads proving key, synthesizes circuit, generates proof.
 * pk_data/pk_len: raw sapling-spend.params file contents.
 * Returns proof as 192 bytes (A:48 + B:96 + C:48 compressed). */
bool sapling_create_spend_proof(const uint8_t *pk_data, size_t pk_len,
                                 const struct sapling_spend_witness *wit,
                                 const struct sapling_spend_inputs *pub,
                                 uint8_t proof_out[192]);

/* Create a Sapling output proof. */
bool sapling_create_output_proof(const uint8_t *pk_data, size_t pk_len,
                                  const struct sapling_output_witness *wit,
                                  const struct sapling_output_inputs *pub,
                                  uint8_t proof_out[192]);

#endif
