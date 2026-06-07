// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// NFT SELL pillar — public declarations so the gtest can drive the REAL offer
// verifier (E-1) instead of hand-rolling a copy of prod logic. The dispatchers
// and the local-store helpers stay file-static in rpc/nftoffer.cpp; only the
// load-bearing decode+verify core (CNftOfferBlob / NftVerifyResult / NftVerify)
// is exposed here. The verifier's signature + logic are UNCHANGED — this header
// only un-hides them.
//
// NON-consensus overlay; ENABLE_WALLET only (the verifier reads pcoinsTip and
// the wallet-side ZSLP store).

#ifndef BITCOIN_RPC_NFTOFFER_H
#define BITCOIN_RPC_NFTOFFER_H

#ifdef ENABLE_WALLET

#include "amount.h"
#include "primitives/transaction.h"   // CMutableTransaction, CScript via deps
#include "script/script.h"            // CScript
#include "serialize.h"                // ADD_SERIALIZE_METHODS / READWRITE
#include "uint256.h"

#include <ios>
#include <string>
#include <vector>

class CZSLPStore;

// ── offer blob format (base64; §4) ──────────────────────────────────
//
// Self-describing, versioned. The header is ADVISORY only — NftVerify always
// re-derives every field from offerHex and ignores a header that lies.
static const unsigned char NFT_OFFER_MAGIC[4] = { 'Z', 'N', 'F', 'T' };
static const unsigned char NFT_OFFER_VERSION  = 0x01;

class CNftOfferBlob
{
public:
    uint256 tokenId;          //!< internal order (render reversed)
    int64_t priceZat;
    std::string payoutAddr;
    std::string buyerNftAddr;
    uint32_t expiryHeight;
    std::string offerHex;     //!< the partial ALL|ANYONECANPAY tx hex

    CNftOfferBlob() : priceZat(0), expiryHeight(0) { tokenId.SetNull(); }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        for (int i = 0; i < 4; ++i) {
            unsigned char m = NFT_OFFER_MAGIC[i];
            READWRITE(m);
            if (ser_action.ForRead() && m != NFT_OFFER_MAGIC[i])
                throw std::ios_base::failure("offer blob: bad magic");
        }
        unsigned char ver = NFT_OFFER_VERSION;
        READWRITE(ver);
        if (ser_action.ForRead() && ver != NFT_OFFER_VERSION)
            throw std::ios_base::failure("offer blob: unsupported version");
        READWRITE(tokenId);
        READWRITE(priceZat);
        READWRITE(payoutAddr);
        READWRITE(buyerNftAddr);
        READWRITE(expiryHeight);
        READWRITE(offerHex);
    }

    std::string ToBase64() const;

    // offerId = first 8 bytes of SHA256(blob) hex; stable content fingerprint.
    std::string OfferId() const;

    bool FromBase64(const std::string& b64, std::string& err);
};

// The result of decoding + verifying a partial offer tx (the core safety logic).
// Fills `reasons` with one string per failed check; ok == reasons.empty(). Also
// fills the derived (truth) fields so callers can echo them.
struct NftVerifyResult {
    bool ok;
    uint256 tokenId;
    int64_t priceZat;
    std::string payoutAddr;
    std::string buyerNftAddr;
    uint32_t expiryHeight;
    CMutableTransaction tx;     //!< the decoded partial tx (for takeoffer)
    CScript nftPrevScript;      //!< vin[0]'s prevout scriptPubKey (live)
    CAmount nftPrevValue;       //!< vin[0]'s prevout value (live)
    std::vector<std::string> reasons;
    NftVerifyResult() : ok(false), priceZat(0), expiryHeight(0), nftPrevValue(0)
    { tokenId.SetNull(); }
};

// Re-derive every advertised field from offerHex and re-run the real indexer
// parse + conservation check + a live-UTXO check (incl. the seller's
// ALL|ANYONECANPAY signature) on vin[0]. Used by nft_verifyoffer (read-only),
// nft_takeoffer (refuse-if-not-ok), and nft_makeoffer's self-validate. Requires
// cs_main held. De-static (E-1) so test_nftoffer.cpp can exercise the REAL
// function; signature + logic unchanged.
void NftVerify(CZSLPStore* store, const CNftOfferBlob& blob, NftVerifyResult& r);

#endif // ENABLE_WALLET

#endif // BITCOIN_RPC_NFTOFFER_H
