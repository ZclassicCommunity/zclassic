// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_WALLET_H
#define BITCOIN_WALLET_WALLET_H

#include "amount.h"
#include "asyncrpcoperation.h"
#include "coins.h"
#include "key.h"
#include "keystore.h"
#include "main.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "tinyformat.h"
#include "ui_interface.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validationinterface.h"
#include "wallet/sendjournal.h"
#include "wallet/crypter.h"
#include "wallet/tokenguard.h"
#include "wallet/wallet_ismine.h"
#include "wallet/walletdb.h"
#include "wallet/rpcwallet.h"
#include "zcash/Address.hpp"
#include "zcash/zip32.h"
#include "base58.h"

#include <algorithm>
#include <atomic>
#include <map>
#include <set>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include <boost/shared_ptr.hpp>

/**
 * Settings
 */
extern CFeeRate payTxFee;
extern CAmount maxTxFee;
extern unsigned int nTxConfirmTarget;
extern bool bSpendZeroConfChange;
extern bool fSendFreeTransactions;
//! Wallet token guard switch (-tokenguard, default on). Off: ordinary spend paths treat token-bearing outputs as plain coins.
extern bool fTokenGuard;
extern bool fPayAtLeastCustomFee;

//! -paytxfee default
static const CAmount DEFAULT_TRANSACTION_FEE = 0;
//! -paytxfee will warn if called with a higher fee than this amount (in satoshis) per KB
static const CAmount nHighTransactionFeeWarning = 0.01 * COIN;
//! -maxtxfee default
static const CAmount DEFAULT_TRANSACTION_MAXFEE = 0.1 * COIN;
//! -txconfirmtarget default
static const unsigned int DEFAULT_TX_CONFIRM_TARGET = 2;
//! -maxtxfee will warn if called with a higher fee than this amount (in satoshis)
static const CAmount nHighTransactionMaxFeeWarning = 100 * nHighTransactionFeeWarning;
//! Largest (in bytes) free transaction we're willing to create
static const unsigned int MAX_FREE_TRANSACTION_CREATE_SIZE = 1000;
//! Size of witness cache
//  Should be large enough that we can expect not to reorg beyond our cache
//  unless there is some exceptional network disruption.
static const unsigned int WITNESS_CACHE_SIZE = MAX_REORG_LENGTH + 1;
/**
 * How many witnesses (the newest ones) a retired Sapling note keeps in wallet.dat, with witnessHeight -1.
 *
 * Why any: released binaries (v2.1.2-beta12 and before) erase the nullifier of a note whose witness list is
 * empty whenever a rescan looks at its transaction (z_importkey, importwallet), and the spent note then reads
 * as unspent. They move the height of a note to the tip with every connected block (and copy one witness per
 * block, never below one) and pop one witness per disconnected block, so a record with W witnesses survives
 * W - 1 disconnects that come before any connect. Four survive the orphaned tips and short reorgs that a node
 * sees in practice (up to three blocks); one survived none (measured: disconnect, then rescan, 347 notes
 * instead of 107).
 *
 * The cost: about 0.78 KiB per witness, 3.1 KiB per retired note on top of the record (a retired record
 * weighs about 4.7 KiB, a live one 77 KiB). The limit that is left: an older binary whose first events after
 * a downgrade are FOUR or more disconnects, followed by a rescan from below the note, counts those spent
 * notes as unspent until it runs with -rescan or this build opens the wallet again and repairs it.
 * Invariant that older binaries assert (nWitnessCacheSize >= the witness count of every note, retired ones
 * included): a sweep retires a note only when it holds this many witnesses, and from then on
 * DecrementNoteWitnesses cuts the frozen witnesses of every retired note to the new cache size at each
 * disconnect (the cache size drops with each one), ReconcileNoteState raises the size to cover them, and
 * ClearNoteWitnessCache resets both. So after a deep operator unwind (97 or more disconnects that reach no
 * retired spend) the frozen list can be SHORTER than this; it then survives fewer disconnects-first (see
 * doc/wallet-crash-consistency.md).
 */
static const size_t RETIRED_WITNESSES_KEPT = 4;
/** A block update looks for newly retirable notes (CWallet::RetireSpentNotes) every this many blocks. */
static const unsigned int RETIRE_SWEEP_INTERVAL = 10;
//! Most new tips at which the wallet re-offers its transactions after a disconnect (CWallet::UpdatedBlockTip)
static const int REACCEPT_TIPS_AFTER_UNWIND = 20;
//! nReacceptTipsLeft after a start-up (import, rescan) offer that refused some: the
//! REACCEPT_TIPS_AFTER_UNWIND retries begin once the tip has reached the best known header,
//! so a node that starts behind the network does not spend them on tips far behind
static const int REACCEPT_WHEN_CAUGHT_UP = -1;

//! Size of HD seed in bytes
static const size_t HD_WALLET_SEED_LENGTH = 32;

class CBlockIndex;
class CCoinControl;
class COutput;
class CReserveKey;
class CScript;
class CTxMemPool;
class CWalletTx;

/** (client) version numbers for particular wallet features */
enum WalletFeature
{
    FEATURE_BASE = 10500, // the earliest version new wallets supports (only useful for getinfo's clientversion output)

    FEATURE_WALLETCRYPT = 40000, // wallet encryption
    FEATURE_COMPRPUBKEY = 60000, // compressed public keys

    FEATURE_LATEST = 60000
};


/** A key pool entry */
class CKeyPool
{
public:
    int64_t nTime;
    CPubKey vchPubKey;

    CKeyPool();
    CKeyPool(const CPubKey& vchPubKeyIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(nTime);
        READWRITE(vchPubKey);
    }
};

/** Address book data */
class CAddressBookData
{
public:
    std::string name;
    std::string purpose;

    CAddressBookData()
    {
        purpose = "unknown";
    }

    typedef std::map<std::string, std::string> StringMap;
    StringMap destdata;
};

struct CRecipient
{
    CScript scriptPubKey;
    CAmount nAmount;
    bool fSubtractFeeFromAmount;
};

typedef std::map<std::string, std::string> mapValue_t;


static void ReadOrderPos(int64_t& nOrderPos, mapValue_t& mapValue)
{
    if (!mapValue.count("n"))
    {
        nOrderPos = -1; // TODO: calculate elsewhere
        return;
    }
    nOrderPos = atoi64(mapValue["n"].c_str());
}


static void WriteOrderPos(const int64_t& nOrderPos, mapValue_t& mapValue)
{
    if (nOrderPos == -1)
        return;
    mapValue["n"] = i64tostr(nOrderPos);
}

struct COutputEntry
{
    CTxDestination destination;
    CAmount amount;
    int vout;
};

/** A note outpoint */
class JSOutPoint
{
public:
    // Transaction hash
    uint256 hash;
    // Index into CTransaction.vjoinsplit
    uint64_t js;
    // Index into JSDescription fields of length ZC_NUM_JS_OUTPUTS
    uint8_t n;

    JSOutPoint() { SetNull(); }
    JSOutPoint(uint256 h, uint64_t js, uint8_t n) : hash {h}, js {js}, n {n} { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(hash);
        READWRITE(js);
        READWRITE(n);
    }

    void SetNull() { hash.SetNull(); }
    bool IsNull() const { return hash.IsNull(); }

    friend bool operator<(const JSOutPoint& a, const JSOutPoint& b) {
        return (a.hash < b.hash ||
                (a.hash == b.hash && a.js < b.js) ||
                (a.hash == b.hash && a.js == b.js && a.n < b.n));
    }

    friend bool operator==(const JSOutPoint& a, const JSOutPoint& b) {
        return (a.hash == b.hash && a.js == b.js && a.n == b.n);
    }

    friend bool operator!=(const JSOutPoint& a, const JSOutPoint& b) {
        return !(a == b);
    }

    std::string ToString() const;
};

class SproutNoteData
{
public:
    libzcash::SproutPaymentAddress address;

    /**
     * Cached note nullifier. May not be set if the wallet was not unlocked when
     * this was SproutNoteData was created. If not set, we always assume that the
     * note has not been spent.
     *
     * It's okay to cache the nullifier in the wallet, because we are storing
     * the spending key there too, which could be used to derive this.
     * If the wallet is encrypted, this means that someone with access to the
     * locked wallet cannot spend notes, but can connect received notes to the
     * transactions they are spent in. This is the same security semantics as
     * for transparent addresses.
     */
    boost::optional<uint256> nullifier;

    /**
     * Cached incremental witnesses for spendable Notes.
     * Beginning of the list is the most recent witness.
     */
    std::list<SproutWitness> witnesses;

    /**
     * Block height corresponding to the most current witness.
     *
     * When we first create a SproutNoteData in CWallet::FindMySproutNotes, this is set to
     * -1 as a placeholder. The next time CWallet::ChainTip is called, we can
     * determine what height the witness cache for this note is valid for (even
     * if no witnesses were cached), and so can set the correct value in
     * CWallet::IncrementNoteWitnesses and CWallet::DecrementNoteWitnesses.
     */
    int witnessHeight;

    /**
     * The note's plaintext value, cached so balance reads do not re-decrypt.
     * Non-invertible CAmount only; never any key material.
     *
     * MEMORY-ONLY by design: it is intentionally NOT serialized (it is absent
     * from SerializationOp below). SproutNoteData has NO serialization version,
     * so adding it to the wire format would silently break the on-disk layout
     * and every existing wallet.dat. It is populated when a note is decrypted
     * (FindMySproutNotes); boost::none until then, in which case balance readers
     * decrypt-and-fill on demand. Sprout is legacy / low-volume, so a memory-only
     * cache rebuilt on load is the correct trade-off (same as Sapling's value).
     */
    boost::optional<CAmount> value;

    /**
     * The note was spent by a wallet transaction buried deeper than WITNESS_CACHE_SIZE
     * blocks (see CWallet::RetireSpentNotes). Its witnessHeight is -1, its witness list holds at
     * most RETIRED_WITNESSES_KEPT frozen witnesses (Sapling; none for Sprout and for test-build wallets), and no block
     * update touches it. MEMORY-ONLY, like 'value': never serialized, so wallet.dat keeps the
     * same layout (a retired note is stored as one witness or none, witnessHeight=-1, nullifier
     * kept) and the flag is rebuilt from the chain at load.
     */
    bool fRetired {false};

    SproutNoteData() : address(), nullifier(), witnessHeight {-1}, value(boost::none) { }
    SproutNoteData(libzcash::SproutPaymentAddress a) :
            address {a}, nullifier(), witnessHeight {-1}, value(boost::none) { }
    SproutNoteData(libzcash::SproutPaymentAddress a, uint256 n) :
            address {a}, nullifier {n}, witnessHeight {-1}, value(boost::none) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(address);
        READWRITE(nullifier);
        READWRITE(witnesses);
        READWRITE(witnessHeight);
        // 'value' is deliberately NOT serialized (memory-only cache). Unlike
        // SaplingNoteData there is no version field here, so the on-disk layout
        // MUST stay exactly address/nullifier/witnesses/witnessHeight.
    }

    friend bool operator<(const SproutNoteData& a, const SproutNoteData& b) {
        return (a.address < b.address ||
                (a.address == b.address && a.nullifier < b.nullifier));
    }

    friend bool operator==(const SproutNoteData& a, const SproutNoteData& b) {
        return (a.address == b.address && a.nullifier == b.nullifier);
    }

    friend bool operator!=(const SproutNoteData& a, const SproutNoteData& b) {
        return !(a == b);
    }
};

class SaplingNoteData
{
public:
    /**
     * We initialize the height to -1 for the same reason as we do in SproutNoteData.
     * See the comment in that class for a full description.
     */
    SaplingNoteData() : witnessHeight {-1}, nullifier(), value(boost::none) { }
    SaplingNoteData(libzcash::SaplingIncomingViewingKey ivk) : ivk {ivk}, witnessHeight {-1}, nullifier(), value(boost::none) { }
    SaplingNoteData(libzcash::SaplingIncomingViewingKey ivk, uint256 n) : ivk {ivk}, witnessHeight {-1}, nullifier(n), value(boost::none) { }

    std::list<SaplingWitness> witnesses;
    int witnessHeight;
    libzcash::SaplingIncomingViewingKey ivk;
    boost::optional<uint256> nullifier;
    /**
     * The note's plaintext value, cached so balance reads do not re-decrypt.
     * Non-invertible CAmount only; never any key material.
     *
     * MEMORY-ONLY by design: it is intentionally NOT serialized to wallet.dat,
     * so the on-disk SaplingNoteData layout is byte-for-byte unchanged — old and
     * new wallets interoperate with ZERO risk and no CLIENT_VERSION bump. It is
     * populated when a note is decrypted (FindMySaplingNotes, and the per-block
     * UpdateSaplingNullifierNoteMapWithTx backfill); boost::none until then, in
     * which case balance readers decrypt-and-fill on demand. The user-visible
     * startup balance is already instant via the GUI's cached-balance paint, so
     * persistence buys only one first-decrypt per launch — not worth a wallet.dat
     * format change. (Sprout's cache is memory-only for the same reason.)
     */
    boost::optional<CAmount> value;
    /**
     * The payment address the note was received at (ivk + the decrypted
     * diversifier). Recovering it costs a full note decryption plus two
     * Jubjub scalar multiplications, which made every address-filtered balance
     * or note listing O(all wallet notes) decryptions. A payment address is
     * public data, not key material. MEMORY-ONLY exactly like 'value': never
     * serialized, boost::none until the note is first decrypted.
     */
    boost::optional<libzcash::SaplingPaymentAddress> address;

    /** Memory-only, see SproutNoteData::fRetired. */
    bool fRetired {false};

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(nVersion);
        }
        READWRITE(ivk);
        READWRITE(nullifier);
        READWRITE(witnesses);
        READWRITE(witnessHeight);
        // 'value' and 'address' are deliberately NOT serialized (memory-only cache) — keeps the
        // on-disk layout identical to pre-cache wallets.
    }

    friend bool operator==(const SaplingNoteData& a, const SaplingNoteData& b) {
        return (a.ivk == b.ivk && a.nullifier == b.nullifier && a.witnessHeight == b.witnessHeight);
    }

    friend bool operator!=(const SaplingNoteData& a, const SaplingNoteData& b) {
        return !(a == b);
    }
};

typedef std::map<JSOutPoint, SproutNoteData> mapSproutNoteData_t;
typedef std::map<SaplingOutPoint, SaplingNoteData> mapSaplingNoteData_t;

/**
 * Result of trial-decrypting a single Sapling output against the wallet's
 * incoming viewing keys. A plain value type with NO key-derivation material:
 * the ivk is the matching incoming viewing key (already in the wallet), the
 * value is the note's non-invertible plaintext CAmount, and address is the
 * note's payment address (recovered from the diversifier). Used to carry the
 * outcome of the (parallel) rescan trial-decryption back to the serial
 * note-data assembly, so the expensive ka_agree trial-decryption can run off
 * the wallet-apply thread. KEY-1: holds only an ivk the wallet already owns;
 * never serialized, never leaves the process.
 */
struct SaplingOutputMatch
{
    libzcash::SaplingIncomingViewingKey ivk;
    CAmount value;
    boost::optional<libzcash::SaplingPaymentAddress> address;
};

/** Decrypted note, its location in a transaction, and number of confirmations. */
struct CSproutNotePlaintextEntry
{
    JSOutPoint jsop;
    libzcash::SproutPaymentAddress address;
    libzcash::SproutNotePlaintext plaintext;
    int confirmations;
};

/** Sapling note, its location in a transaction, and number of confirmations. */
struct SaplingNoteEntry
{
    SaplingOutPoint op;
    libzcash::SaplingPaymentAddress address;
    libzcash::SaplingNote note;
    std::array<unsigned char, ZC_MEMO_SIZE> memo;
    int confirmations;
};

/** A transaction with a merkle branch linking it to the block chain. */
class CMerkleTx : public CTransaction
{
private:
    int GetDepthInMainChainINTERNAL(const CBlockIndex* &pindexRet) const;

public:
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;
    int nIndex;

    // memory only
    mutable bool fMerkleVerified;


    CMerkleTx()
    {
        Init();
    }

    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = uint256();
        nIndex = -1;
        fMerkleVerified = false;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CTransaction*)this);
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    }

    void SetMerkleBranch(const CBlock& block);


    /**
     * Return depth of transaction in blockchain:
     * -1  : not in blockchain, and not in memory pool (conflicted transaction)
     *  0  : in memory pool, waiting to be included in a block
     * >=1 : this many blocks deep in the main chain
     */
    int GetDepthInMainChain(const CBlockIndex* &pindexRet) const;
    int GetDepthInMainChain() const { const CBlockIndex *pindexRet; return GetDepthInMainChain(pindexRet); }
    bool IsInMainChain() const { const CBlockIndex *pindexRet; return GetDepthInMainChainINTERNAL(pindexRet) > 0; }
    int GetBlocksToMaturity() const;
    bool AcceptToMemoryPool(bool fLimitFree=true, bool fRejectAbsurdFee=true);
};

/** 
 * A transaction with a bunch of additional info that only the owner cares about.
 * It includes any unrecorded transactions needed to link it back to the block chain.
 */
class CWalletTx : public CMerkleTx
{
private:
    const CWallet* pwallet;

public:
    mapValue_t mapValue;
    mapSproutNoteData_t mapSproutNoteData;
    mapSaplingNoteData_t mapSaplingNoteData;
    std::vector<std::pair<std::string, std::string> > vOrderForm;
    unsigned int fTimeReceivedIsTxTime;
    unsigned int nTimeReceived; //! time received by this node
    unsigned int nTimeSmart;
    char fFromMe;
    std::string strFromAccount;
    int64_t nOrderPos; //! position in ordered transaction list

    // memory only
    mutable bool fDebitCached;
    mutable bool fCreditCached;
    mutable bool fImmatureCreditCached;
    mutable bool fAvailableCreditCached;
    mutable bool fWatchDebitCached;
    mutable bool fWatchCreditCached;
    mutable bool fImmatureWatchCreditCached;
    mutable bool fAvailableWatchCreditCached;
    mutable bool fChangeCached;
    mutable CAmount nDebitCached;
    mutable CAmount nCreditCached;
    mutable CAmount nImmatureCreditCached;
    mutable CAmount nAvailableCreditCached;
    mutable CAmount nWatchDebitCached;
    mutable CAmount nWatchCreditCached;
    mutable CAmount nImmatureWatchCreditCached;
    mutable CAmount nAvailableWatchCreditCached;
    mutable CAmount nChangeCached;

    // memory only: wallet token guard (see wallet/tokenguard.h). Never
    // serialized; recomputed from the transaction itself after a restart, a
    // rescan or a restore from backup. Keyed by txid so a CWalletTx whose
    // transaction is replaced in place cannot serve a stale answer.
    mutable bool fTokenRolesCached;
    mutable uint256 hashTokenRolesCached;
    mutable std::vector<unsigned char> vTokenRolesCached;

    CWalletTx()
    {
        Init(NULL);
    }

    CWalletTx(const CWallet* pwalletIn)
    {
        Init(pwalletIn);
    }

    CWalletTx(const CWallet* pwalletIn, const CMerkleTx& txIn) : CMerkleTx(txIn)
    {
        Init(pwalletIn);
    }

    CWalletTx(const CWallet* pwalletIn, const CTransaction& txIn) : CMerkleTx(txIn)
    {
        Init(pwalletIn);
    }

    void Init(const CWallet* pwalletIn)
    {
        pwallet = pwalletIn;
        mapValue.clear();
        mapSproutNoteData.clear();
        mapSaplingNoteData.clear();
        vOrderForm.clear();
        fTimeReceivedIsTxTime = false;
        nTimeReceived = 0;
        nTimeSmart = 0;
        fFromMe = false;
        strFromAccount.clear();
        fDebitCached = false;
        fCreditCached = false;
        fImmatureCreditCached = false;
        fAvailableCreditCached = false;
        fWatchDebitCached = false;
        fWatchCreditCached = false;
        fImmatureWatchCreditCached = false;
        fAvailableWatchCreditCached = false;
        fChangeCached = false;
        nDebitCached = 0;
        nCreditCached = 0;
        nImmatureCreditCached = 0;
        nAvailableCreditCached = 0;
        nWatchDebitCached = 0;
        nWatchCreditCached = 0;
        nAvailableWatchCreditCached = 0;
        nImmatureWatchCreditCached = 0;
        nChangeCached = 0;
        nOrderPos = -1;
        fTokenRolesCached = false;
        hashTokenRolesCached.SetNull();
        vTokenRolesCached.clear();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        if (ser_action.ForRead())
            Init(NULL);
        char fSpent = false;

        if (!ser_action.ForRead())
        {
            mapValue["fromaccount"] = strFromAccount;

            WriteOrderPos(nOrderPos, mapValue);

            if (nTimeSmart)
                mapValue["timesmart"] = strprintf("%u", nTimeSmart);
        }

        READWRITE(*(CMerkleTx*)this);
        std::vector<CMerkleTx> vUnused; //! Used to be vtxPrev
        READWRITE(vUnused);
        READWRITE(mapValue);
        READWRITE(mapSproutNoteData);
        READWRITE(vOrderForm);
        READWRITE(fTimeReceivedIsTxTime);
        READWRITE(nTimeReceived);
        READWRITE(fFromMe);
        READWRITE(fSpent);

        if (fOverwintered && nVersion >= SAPLING_TX_VERSION) {
            READWRITE(mapSaplingNoteData);
        }

        if (ser_action.ForRead())
        {
            strFromAccount = mapValue["fromaccount"];

            ReadOrderPos(nOrderPos, mapValue);

            nTimeSmart = mapValue.count("timesmart") ? (unsigned int)atoi64(mapValue["timesmart"]) : 0;
        }

        mapValue.erase("fromaccount");
        mapValue.erase("version");
        mapValue.erase("spent");
        mapValue.erase("n");
        mapValue.erase("timesmart");
    }

    //! make sure balances are recalculated
    void MarkDirty()
    {
        fCreditCached = false;
        fAvailableCreditCached = false;
        fWatchDebitCached = false;
        fWatchCreditCached = false;
        fAvailableWatchCreditCached = false;
        fImmatureWatchCreditCached = false;
        fDebitCached = false;
        fChangeCached = false;
    }

    void BindWallet(CWallet *pwalletIn)
    {
        pwallet = pwalletIn;
        MarkDirty();
    }

    void SetSproutNoteData(mapSproutNoteData_t &noteData);
    void SetSaplingNoteData(mapSaplingNoteData_t &noteData);

    //! filter decides which addresses will count towards the debit
    CAmount GetDebit(const isminefilter& filter) const;
    CAmount GetCredit(const isminefilter& filter) const;
    CAmount GetImmatureCredit(bool fUseCache=true) const;
    CAmount GetAvailableCredit(bool fUseCache=true) const;
    CAmount GetImmatureWatchOnlyCredit(const bool& fUseCache=true) const;
    CAmount GetAvailableWatchOnlyCredit(const bool& fUseCache=true) const;
    CAmount GetChange() const;

    void GetAmounts(std::list<COutputEntry>& listReceived,
                    std::list<COutputEntry>& listSent, CAmount& nFee, std::string& strSentAccount, const isminefilter& filter) const;

    void GetAccountAmounts(const std::string& strAccount, CAmount& nReceived,
                           CAmount& nSent, CAmount& nFee, const isminefilter& filter) const;

    bool IsFromMe(const isminefilter& filter) const
    {
        return (GetDebit(filter) > 0);
    }

    bool IsTrusted() const;

    /**
     * Wallet token guard: TOKEN_ROLE_* of output n (wallet/tokenguard.h).
     * Parses at most once per transaction, and only when the transaction has
     * an OP_RETURN output. Call with cs_wallet held, like the other caches.
     */
    unsigned char GetTokenOutputRole(unsigned int n) const;
    //! True if spending output n as ordinary funds would burn ZSLP tokens or a mint baton.
    bool IsTokenBearingOutput(unsigned int n) const { return GetTokenOutputRole(n) != 0; }
    //! True if the wallet token guard keeps output n out of ordinary spends: token-bearing, and -tokenguard not 0.
    bool IsTokenGuarded(unsigned int n) const { return fTokenGuard && IsTokenBearingOutput(n); }

    bool WriteToDisk(CWalletDB *pwalletdb);

    int64_t GetTxTime() const;
    int GetRequestCount() const;

    bool RelayWalletTransaction();

    std::set<uint256> GetConflicts() const;
};




class COutput
{
public:
    const CWalletTx *tx;
    int i;
    int nDepth;
    bool fSpendable;

    COutput(const CWalletTx *txIn, int iIn, int nDepthIn, bool fSpendableIn)
    {
        tx = txIn; i = iIn; nDepth = nDepthIn; fSpendable = fSpendableIn;
    }

    std::string ToString() const;
};




/** Private key that includes an expiration date in case it never gets used. */
class CWalletKey
{
public:
    CPrivKey vchPrivKey;
    int64_t nTimeCreated;
    int64_t nTimeExpires;
    std::string strComment;
    //! todo: add something to note what created it (user, getnewaddress, change)
    //!   maybe should have a map<string, string> property map

    CWalletKey(int64_t nExpires=0);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPrivKey);
        READWRITE(nTimeCreated);
        READWRITE(nTimeExpires);
        READWRITE(LIMITED_STRING(strComment, 65536));
    }
};

/**
 * Internal transfers.
 * Database key is acentry<account><counter>.
 */
class CAccountingEntry
{
public:
    std::string strAccount;
    CAmount nCreditDebit;
    int64_t nTime;
    std::string strOtherAccount;
    std::string strComment;
    mapValue_t mapValue;
    int64_t nOrderPos;  //! position in ordered transaction list
    uint64_t nEntryNo;

    CAccountingEntry()
    {
        SetNull();
    }

    void SetNull()
    {
        nCreditDebit = 0;
        nTime = 0;
        strAccount.clear();
        strOtherAccount.clear();
        strComment.clear();
        nOrderPos = -1;
        nEntryNo = 0;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        //! Note: strAccount is serialized as part of the key, not here.
        READWRITE(nCreditDebit);
        READWRITE(nTime);
        READWRITE(LIMITED_STRING(strOtherAccount, 65536));

        if (!ser_action.ForRead())
        {
            WriteOrderPos(nOrderPos, mapValue);

            if (!(mapValue.empty() && _ssExtra.empty()))
            {
                CDataStream ss(s.GetType(), s.GetVersion());
                ss.insert(ss.begin(), '\0');
                ss << mapValue;
                ss.insert(ss.end(), _ssExtra.begin(), _ssExtra.end());
                strComment.append(ss.str());
            }
        }

        READWRITE(LIMITED_STRING(strComment, 65536));

        size_t nSepPos = strComment.find("\0", 0, 1);
        if (ser_action.ForRead())
        {
            mapValue.clear();
            if (std::string::npos != nSepPos)
            {
                CDataStream ss(std::vector<char>(strComment.begin() + nSepPos + 1, strComment.end()), s.GetType(), s.GetVersion());
                ss >> mapValue;
                _ssExtra = std::vector<char>(ss.begin(), ss.end());
            }
            ReadOrderPos(nOrderPos, mapValue);
        }
        if (std::string::npos != nSepPos)
            strComment.erase(nSepPos);

        mapValue.erase("n");
    }

private:
    std::vector<char> _ssExtra;
};


/** 
 * A CWallet is an extension of a keystore, which also maintains a set of transactions and balances,
 * and provides the ability to create new transactions.
 */
class CWallet : public CCryptoKeyStore, public CValidationInterface
{
private:
    bool SelectCoins(const CAmount& nTargetValue, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, CAmount& nValueRet, bool& fOnlyCoinbaseCoinsRet, bool& fNeedCoinbaseCoinsRet, const CCoinControl *coinControl = NULL, CTokenGuardReport *pTokenGuardReport = NULL) const;

    CWalletDB *pwalletdbEncryption;

    //! the current wallet version: clients below this version are not able to load the wallet
    int nWalletVersion;

    //! the maximum wallet format version: memory-only variable that specifies to what version this wallet may be upgraded
    int nWalletMaxVersion;

    int64_t nNextResend;
    int64_t nLastResend;
    bool fBroadcastTransactions;

    template <class T>
    using TxSpendMap = std::multimap<T, uint256>;
    /**
     * Used to keep track of spent outpoints, and
     * detect and report conflicts (double-spends or
     * mutated transactions where the mutant gets mined).
     */
    typedef TxSpendMap<COutPoint> TxSpends;
    TxSpends mapTxSpends;
    /**
     * Used to keep track of spent Notes, and
     * detect and report conflicts (double-spends).
     */
    typedef TxSpendMap<uint256> TxNullifiers;
    TxNullifiers mapTxSproutNullifiers;
    TxNullifiers mapTxSaplingNullifiers;

    void AddToTransparentSpends(const COutPoint& outpoint, const uint256& wtxid);
    void AddToSproutSpends(const uint256& nullifier, const uint256& wtxid);
    void AddToSaplingSpends(const uint256& nullifier, const uint256& wtxid);
    void AddToSpends(const uint256& wtxid);

public:
    /*
     * Size of the incremental witness cache for the notes in our wallet.
     * This will always be greater than or equal to the size of the largest
     * incremental witness cache in any transaction in mapWallet.
     */
    int64_t nWitnessCacheSize;

    void ClearNoteWitnessCache();

    /**
     * Startup self-check of the note state read from wallet.dat against the active chain.
     *
     * pindexRescan is the block the startup rescan would begin at (the fork of the stored
     * best-block locator). Witness caches that are ahead of the chain tip are cut back to it,
     * caches that do not match what the chain committed to are dropped, a Sapling nullifier
     * that is missing next to its witness is derived again, and pindexRescan is lowered to the
     * first block the rescan has to include so every cache can be brought to the tip.
     * Nothing is deleted from the wallet but cached witness data, which a rescan rebuilds.
     * Returns true if the in-memory state changed and should be written back.
     */
    bool ReconcileNoteState(CBlockIndex*& pindexRescan);

    /**
     * Retire the notes whose nullifier is spent by a wallet transaction that is more than
     * WITNESS_CACHE_SIZE blocks deep in the active chain. One reorganisation step cannot undo such
     * a spend (the node refuses more than MAX_REORG_LENGTH = WITNESS_CACHE_SIZE - 1 disconnects
     * per step), so the note needs no witness and no block update. The limit is per step, not
     * per spend: chained reorgs, an operator invalidateblock and a chain rewound at start-up can
     * go further, and safety rests on UnretireNotesSpentFrom, which every disconnect that reaches
     * a recorded spend height calls (the note comes back unspent, the witness rebuild is armed).
     *
     * Stored form (what an older binary sees): witnessHeight -1 and, for a Sapling note, up to
     * RETIRED_WITNESSES_KEPT (4) frozen
     * witnesses (the newest) so that released binaries keep deriving its nullifier; a Sprout note, and
     * a note of a test build, keep none. All of them (four, fewer, none) are recognised. Returns the number of stored note
     * records this call changed. Idempotent; it also normalises a retired note an older binary
     * rewrote with a witness height. fStoredForm (start-up): a note already in the stored form
     * and spent by a mined wallet transaction is retired at any depth, for a chain that starts
     * below the last checkpoint. Takes cs_main and cs_wallet.
     */
    size_t RetireSpentNotes(bool fStoredForm = false);
    /** RetireSpentNotes for a caller that holds cs_main and cs_wallet. */
    size_t RetireSpentNotesLocked(bool fStoredForm = false);

    /** Number of notes currently retired (memory only; rebuilt by RetireSpentNotes). */
    size_t CountRetiredNotes() const;

    /**
     * Record that this wallet transaction's note data changed since it was last written to wallet.dat,
     * so the next SetBestChain writes it. EVERY code path that changes a note record (witnesses,
     * witnessHeight, nullifier, the retired state) must call this or MarkNoteTxsDirty: a change
     * that is not marked reaches wallet.dat only when something else rewrites the transaction.
     * Conservative on purpose: marking a transaction whose data did not change costs one write.
     * Requires cs_wallet.
     */
    void MarkNoteTxDirty(const uint256& hash);
    /** Same for a batch of collected note transactions. */
    void MarkNoteTxsDirty(const std::vector<CWalletTx*>& txs);
    /** Number of note transactions the next SetBestChain would write. */
    size_t CountDirtyNoteTxs() const;

protected:
    /**
     * pindex is the new tip being connected.
     */
    void IncrementNoteWitnesses(const CBlockIndex* pindex,
                                const CBlock* pblock,
                                SproutMerkleTree& sproutTree,
                                SaplingMerkleTree& saplingTree);
    /**
     * pindex is the old tip being disconnected.
     */
    void DecrementNoteWitnesses(const CBlockIndex* pindex);
    /**
     * Set when a disconnect left a note without a witness the cache could not
     * roll back. The rebuild (clear every witness, rescan the active chain,
     * see ScanForWalletTransactions) is deferred so a deep reorg pays for one
     * rescan, not one per WITNESS_CACHE_SIZE blocks: it runs at the next
     * connected tip, or before the witnesses are written (SetBestChain, which
     * invalidateblock/parkblock/finalizeblock also signal when they finish).
     * Memory only (no wallet.dat change). Written under cs_main and
     * cs_wallet; atomic so it can be tested before taking them.
     */
    std::atomic<bool> fNoteWitnessesLost;
    /**
     * Tips left at which the wallet offers its transactions to the mempool again
     * after a disconnect. The mempool re-admission of a disconnected block runs
     * while the rest of the unwind is still pending, so a wallet send whose anchor
     * is valid at the final tip can be refused then and be neither in the chain nor
     * in the mempool: its notes would count as unspent until the next restart.
     * ChainTip sets it to REACCEPT_TIPS_AFTER_UNWIND on a disconnect, and
     * ReacceptWalletTransactions (startup, import, rescan) when it refused some
     * (to REACCEPT_WHEN_CAUGHT_UP unless a retry is already running);
     * UpdatedBlockTip retries at each new tip until no refused transaction could
     * still be admitted later (an expired one never can) or the count runs out, so
     * a permanently refused one (double spent, or without an expiry height) does
     * not cost a full pass under cs_main at every block until the next restart.
     * Memory only.
     */
    std::atomic<int> nReacceptTipsLeft;
    void RebuildNoteWitnesses();
    /**
     * The witness half of ChainTip. When no wallet transaction carries
     * Sprout or Sapling note data, a connected block only advances
     * nWitnessCacheSize: there is nothing to copy, append, witness or
     * re-height, so the commitment tree appends (which only feed witnesses)
     * are skipped. The trees are borrowed; a copy is made only when they are appended to.
     */
    void WitnessChainTip(const CBlockIndex* pindex,
                         const CBlock* pblock,
                         const SproutMerkleTree& sproutTree,
                         const SaplingMerkleTree& saplingTree,
                         bool added);

    /**
     * Index of wallet transactions that may carry note data.
     *
     * Invariant (requires cs_wallet): every mapWallet entry whose
     * mapSproutNoteData or mapSaplingNoteData is non-empty has its txid in
     * setNoteTxIndex. The set may be a superset; a txid with empty maps is
     * harmless because the witness loops do nothing for empty maps.
     *
     * Maintained by AddToWallet (load and live paths, insert and merge)
     * and EraseFromWallet. nNoteTxIndexWalletSize tracks mapWallet.size()
     * through those same paths; if anything else inserts into or erases from
     * mapWallet the sizes diverge and the index is rebuilt by a full walk
     * before the next witness update (CollectNoteTxs).
     */
    std::set<uint256> setNoteTxIndex;
    /**
     * The wallet transactions that carry note data and all of whose notes are retired
     * (see RetireSpentNotes). Together with setNoteTxIndex (which therefore holds only the
     * transactions with at least one live note) it covers every note transaction; each hash is in
     * one of the two. Block updates look at setNoteTxIndex only, so their cost follows the
     * unspent notes, not every note ever received.
     */
    std::set<uint256> setNoteTxRetired;
    /**
     * Wallet transactions whose note data (witnesses, witnessHeight, nullifier, ...) changed since
     * SetBestChain last wrote them: the checkpoint writes these and nothing else (see
     * MarkNoteTxDirty). Memory only: what is loaded from wallet.dat is clean. A transaction may be
     * listed without having note data or after it left the wallet; the checkpoint skips those.
     */
    std::set<uint256> setNoteTxDirty;
    /**
     * (height of the block, txid) of the wallet transactions whose spend retired a note, so a
     * disconnect that reaches that height (chained reorgs, an operator invalidateblock/parkblock,
     * a chain rewound at start-up: the node's reorg limit is per step) brings those notes back (UnretireNotesSpentFrom).
     */
    std::set<std::pair<int, uint256>> setRetiredSpends;
    /** Tip height of the last RetireSpentNotes sweep made from a block update. */
    int nRetireSweepHeight = -1;
    size_t nNoteTxIndexWalletSize = 0;
    void NoteTxIndexAdd(const uint256& hash, const CWalletTx& wtx);
    /**
     * Fill out with the mapWallet entries that currently carry note data
     * (live notes only, unless fIncludeRetired), in txid order (the same
     * relative order as a full mapWallet walk).
     * Requires cs_wallet. The pointers stay valid until mapWallet is next
     * inserted into or erased from.
     */
    void CollectNoteTxs(std::vector<CWalletTx*>& out, bool fIncludeRetired = false);
    /**
     * A disconnect reached the block at nHeight: every note retired by a spend in that block or
     * above is live again. Its witness is gone, so the rebuild (fNoteWitnessesLost) is armed.
     */
    void UnretireNotesSpentFrom(int nHeight);
    /** The same for the notes retired by one wallet transaction (it left the wallet). */
    void UnretireNotesSpentBy(const uint256& hashSpender);

    /**
     * Wallet transactions as (nOrderPos, txid), which is the order
     * OrderedTxItems() lists them in. It lets AddToWallet find the latest
     * entries without sorting the whole wallet for every new transaction.
     *
     * Requires cs_wallet. Built by a full walk when first needed.
     * AddToWallet then adds each new transaction; loading or erasing a
     * transaction marks the index stale, and a stale index is rebuilt on
     * the next use, as is one whose size differs from mapWallet. Nothing
     * else changes the nOrderPos of a wallet entry except the reorder pass
     * of LoadWallet, which runs straight after loading.
     */
    std::set<std::pair<int64_t, uint256>> setTxOrder;
    bool fTxOrderValid = false;
    /**
     * Walks wallet transactions and accounting entries from the end of the
     * OrderedTxItems() order, skipping pwtxSkip, and gives the smart time
     * of the first one that is not later than nLatestTolerated. Returns
     * false if there is none.
     */
    bool LatestOrderedSmartTime(const CWalletTx* pwtxSkip, int64_t nLatestTolerated, int64_t& nSmartTimeRet);

    template <typename WalletDB>
    bool SetBestChainINTERNAL(WalletDB& walletdb, const CBlockLocator& loc) {
        TestCrashPoint("setbestchain-begin");
        if (!walletdb.TxnBegin()) {
            // This needs to be done atomically, so don't do it at all
            LogPrintf("SetBestChain(): Couldn't start atomic write\n");
            return false;
        }
        // The note transactions that were written in this database transaction: they are clean
        // only once it commits.
        std::vector<uint256> vWritten;
        try {
            // Only transactions whose note data changed since they were last written, in txid
            // order, by reference (the writer serializes a const transaction). Transactions
            // without Sprout or Sapling data (purely transparent ones, shielding and
            // unshielding transactions in which only transparent addresses are ours) are never
            // written here, and a retired note's transaction only when its record changed.
            for (const uint256& hash : setNoteTxDirty) {
                std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(hash);
                if (mi == mapWallet.end()) {
                    continue; // left the wallet
                }
                const CWalletTx& wtx = mi->second;
                if (wtx.mapSproutNoteData.empty() && wtx.mapSaplingNoteData.empty()) {
                    continue;
                }
                if (!walletdb.WriteTx(hash, wtx)) {
                    LogPrintf("SetBestChain(): Failed to write CWalletTx, aborting atomic write\n");
                    walletdb.TxnAbort();
                    return false;
                }
                vWritten.push_back(hash);
            }
            TestCrashPoint("setbestchain-after-txs");
            if (!walletdb.WriteWitnessCacheSize(nWitnessCacheSize)) {
                LogPrintf("SetBestChain(): Failed to write nWitnessCacheSize, aborting atomic write\n");
                walletdb.TxnAbort();
                return false;
            }
            if (!walletdb.WriteBestBlock(loc)) {
                LogPrintf("SetBestChain(): Failed to write best block, aborting atomic write\n");
                walletdb.TxnAbort();
                return false;
            }
            TestCrashPoint("setbestchain-after-locator");
        } catch (const std::exception &exc) {
            // Unexpected failure
            LogPrintf("SetBestChain(): Unexpected error during atomic write:\n");
            LogPrintf("%s\n", exc.what());
            walletdb.TxnAbort();
            return false;
        }
        if (!walletdb.TxnCommit()) {
            // Couldn't commit all to db, but in-memory state is fine
            LogPrintf("SetBestChain(): Couldn't commit atomic write\n");
            return false;
        }
        // Durable together with the locator: only now are those records clean (on any failure
        // above they stay marked and the next checkpoint writes them again). Entries for
        // transactions without note data or that left the wallet are dropped with them.
        for (const uint256& hash : vWritten) {
            setNoteTxDirty.erase(hash);
        }
        for (std::set<uint256>::iterator it = setNoteTxDirty.begin(); it != setNoteTxDirty.end();) {
            std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(*it);
            if (mi == mapWallet.end() || (mi->second.mapSproutNoteData.empty() && mi->second.mapSaplingNoteData.empty())) {
                it = setNoteTxDirty.erase(it);
            } else {
                ++it;
            }
        }
        TestCrashPoint("setbestchain-after-commit");
        return true;
    }

private:
    template <class T>
    void SyncMetaData(std::pair<typename TxSpendMap<T>::iterator, typename TxSpendMap<T>::iterator>);

    /**
     * Shared per-Sapling-note spendability predicate used by BOTH GetFilteredNotes
     * and GetSaplingBalanceCached so the two paths can never diverge.
     *
     * Applies the spent / spending-key / locked checks (everything that does NOT
     * require the decrypted note plaintext). It deliberately does NOT apply the
     * address filter, because recovering a note's payment address requires a
     * decrypt; callers that filter by address must do that themselves after
     * decrypting (as GetFilteredNotes does). Returns true if the note passes.
     *
     * Caller must hold cs_main and cs_wallet.
     */
    bool SaplingNotePassesSpendFilter(
        const SaplingOutPoint& op,
        const SaplingNoteData& nd,
        bool ignoreSpent,
        bool requireSpendingKey,
        bool ignoreLocked) const;

protected:
    /**
     * Trial-decrypt ONE Sapling output against an ordered snapshot of incoming
     * viewing keys, returning the first match (in snapshot order, exactly like
     * the serial FindMySaplingNotes break) or boost::none. Pure and lock-free:
     * it touches no CWallet members and acquires no locks, so it is safe to call
     * concurrently from rescan worker threads. The per-cell match predicate is
     * the unchanged SaplingNotePlaintext::decrypt, so results are bit-identical
     * to the serial path.
     */
    boost::optional<SaplingOutputMatch> TrialDecryptSaplingOutput(
        const OutputDescription& output,
        const std::vector<libzcash::SaplingIncomingViewingKey>& ivks) const;

    /**
     * Trial-decrypt every Sapling output across a window of blocks in parallel
     * (reusing the script-check thread budget), filling `out` keyed by outpoint
     * with the wallet's matches. The ivk set is snapshotted once under
     * cs_SpendingKeyStore and frozen for the whole window, so the "first
     * matching ivk wins" result is identical regardless of which thread computed
     * which cell. Non-matches are simply absent from `out`. Below a small cell
     * threshold (or with <2 workers) it falls back to a single-threaded fill.
     * Caller must hold cs_wallet (the window's blocks must outlive this call).
     */
    void BuildSaplingScanBatch(
        const std::vector<std::pair<CBlockIndex*, CBlock>>& window,
        int nWorkers,
        std::map<SaplingOutPoint, SaplingOutputMatch>& out,
        bool skipKnownTransactions = false) const;

    /**
     * Transient rescan state, set ONLY by ScanForWalletTransactions while
     * cs_wallet is held: a precomputed (parallel) map of which Sapling outputs
     * in the current window decrypt to this wallet. When non-null,
     * FindMySaplingNotes reads matches from here instead of trial-decrypting on
     * the calling thread. Always null outside an active windowed rescan.
     */
    const std::map<SaplingOutPoint, SaplingOutputMatch>* pScanSaplingBatch = nullptr;

protected:
    bool UpdatedNoteData(const CWalletTx& wtxIn, CWalletTx& wtx);
    void MarkAffectedTransactionsDirty(const CTransaction& tx);

    /* the hd chain data model (chain counters) */
    CHDChain hdChain;

public:
    /*
     * Main wallet lock.
     * This lock protects all the fields added by CWallet
     *   except for:
     *      fFileBacked (immutable after instantiation)
     *      strWalletFile (immutable after instantiation)
     */
    mutable CCriticalSection cs_wallet;

    bool fFileBacked;
    std::string strWalletFile;

    std::set<int64_t> setKeyPool;
    std::map<CKeyID, CKeyMetadata> mapKeyMetadata;
    std::map<libzcash::SproutPaymentAddress, CKeyMetadata> mapSproutZKeyMetadata;
    std::map<libzcash::SaplingIncomingViewingKey, CKeyMetadata> mapSaplingZKeyMetadata;

    typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
    MasterKeyMap mapMasterKeys;
    unsigned int nMasterKeyMaxID;

    CWallet()
    {
        SetNull();
    }

    CWallet(const std::string& strWalletFileIn)
    {
        SetNull();

        strWalletFile = strWalletFileIn;
        fFileBacked = true;
    }

    ~CWallet()
    {
        delete pwalletdbEncryption;
        pwalletdbEncryption = NULL;
    }

    void SetNull()
    {
        nWalletVersion = FEATURE_BASE;
        nWalletMaxVersion = FEATURE_BASE;
        fFileBacked = false;
        nMasterKeyMaxID = 0;
        pwalletdbEncryption = NULL;
        nOrderPosNext = 0;
        nNextResend = 0;
        nLastResend = 0;
        nTimeFirstKey = 0;
        fBroadcastTransactions = false;
        nWitnessCacheSize = 0;
        fNoteWitnessesLost = false;
        nReacceptTipsLeft = 0;
        setNoteTxIndex.clear();
        setNoteTxRetired.clear();
        setNoteTxDirty.clear();
        setRetiredSpends.clear();
        nRetireSweepHeight = -1;
        nNoteTxIndexWalletSize = 0;
    }

    /**
     * The reverse mapping of nullifiers to notes.
     *
     * The mapping cannot be updated while an encrypted wallet is locked,
     * because we need the SpendingKey to create the nullifier (#1502). This has
     * several implications for transactions added to the wallet while locked:
     *
     * - Parent transactions can't be marked dirty when a child transaction that
     *   spends their output notes is updated.
     *
     *   - We currently don't cache any note values, so this is not a problem,
     *     yet.
     *
     * - GetFilteredNotes can't filter out spent notes.
     *
     *   - Per the comment in SproutNoteData, we assume that if we don't have a
     *     cached nullifier, the note is not spent.
     *
     * Another more problematic implication is that the wallet can fail to
     * detect transactions on the blockchain that spend our notes. There are two
     * possible cases in which this could happen:
     *
     * - We receive a note when the wallet is locked, and then spend it using a
     *   different wallet client.
     *
     * - We spend from a PaymentAddress we control, then we export the
     *   SpendingKey and import it into a new wallet, and reindex/rescan to find
     *   the old transactions.
     *
     * The wallet will only miss "pure" spends - transactions that are only
     * linked to us by the fact that they contain notes we spent. If it also
     * sends notes to us, or interacts with our transparent addresses, we will
     * detect the transaction and add it to the wallet (again without caching
     * nullifiers for new notes). As by default JoinSplits send change back to
     * the origin PaymentAddress, the wallet should rarely miss transactions.
     *
     * To work around these issues, whenever the wallet is unlocked, we scan all
     * cached notes, and cache any missing nullifiers. Since the wallet must be
     * unlocked in order to spend notes, this means that GetFilteredNotes will
     * always behave correctly within that context (and any other uses will give
     * correct responses afterwards), for the transactions that the wallet was
     * able to detect. Any missing transactions can be rediscovered by:
     *
     * - Unlocking the wallet (to fill all nullifier caches).
     *
     * - Restarting the node with -reindex (which operates on a locked wallet
     *   but with the now-cached nullifiers).
     */
    std::map<uint256, JSOutPoint> mapSproutNullifiersToNotes;

    std::map<uint256, SaplingOutPoint> mapSaplingNullifiersToNotes;

    std::map<uint256, CWalletTx> mapWallet;

    //! Send journal records ("sendonce" in wallet.dat) by SHA-256 of the idempotency key; guarded by cs_wallet
    std::map<uint256, CSendOnceRecord> mapSendOnce;
    bool LoadSendOnce(const uint256& keyHash, const CSendOnceRecord& rec) { mapSendOnce[keyHash] = rec; return true; }

    int64_t nOrderPosNext;
    std::map<uint256, int> mapRequestCount;

    std::map<CTxDestination, CAddressBookData> mapAddressBook;

    CPubKey vchDefaultKey;

    std::set<COutPoint> setLockedCoins;
    std::set<JSOutPoint> setLockedSproutNotes;
    std::set<SaplingOutPoint> setLockedSaplingNotes;

    int64_t nTimeFirstKey;

    const CWalletTx* GetWalletTx(const uint256& hash) const;

    //! check whether we are allowed to upgrade (or already support) to the named feature
    bool CanSupportFeature(enum WalletFeature wf) { AssertLockHeld(cs_wallet); return nWalletMaxVersion >= wf; }

    void AvailableCoins(std::vector<COutput>& vCoins, bool fOnlyConfirmed=true, const CCoinControl *coinControl = NULL, bool fIncludeZeroValue=false, bool fIncludeCoinBase=true) const;
    bool SelectCoinsMinConf(const CAmount& nTargetValue, int nConfMine, int nConfTheirs, std::vector<COutput> vCoins, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, CAmount& nValueRet) const;

    bool IsSpent(const uint256& hash, unsigned int n) const;
    bool IsSproutSpent(const uint256& nullifier) const;
    bool IsSaplingSpent(const uint256& nullifier) const;
    //! Height of the last best-block locator written to wallet.dat (-1: none yet). Memory only.
    std::atomic<int> nCheckpointHeight{-1};

    //! Per-pool note and witness counts (see CWallet::GetHealth).
    struct PoolHealth {
        size_t nUnspent = 0;       //!< notes no active transaction spends
        size_t nSpent = 0;         //!< notes a non-conflicted transaction spends
        size_t nReady = 0;         //!< unspent, confirmed, witness cache present and at the chain tip
        size_t nMissing = 0;       //!< unspent, confirmed, no witness cache
        size_t nStale = 0;         //!< unspent, confirmed, witness cache not at the chain tip
        size_t nUnconfirmed = 0;   //!< unspent, not in a block (no witness is due yet)
        size_t nDead = 0;          //!< notes of a transaction in neither the chain nor the mempool (not counted above)
        size_t nWitnessEntries = 0;//!< witnesses held by unspent notes (sum of cache lengths)
        size_t nSpentWitnessEntries = 0; //!< witnesses still held by spent notes
    };
    struct Health {
        PoolHealth sapling, sprout;
        int64_t nWitnessCacheSize = 0;
        bool fWitnessRebuildPending = false;
        int nCheckpointHeight = -1;
        int nTipHeight = -1;
        size_t nPendingInMempool = 0;   //!< unmined sends in the mempool
        size_t nPendingNotInMempool = 0;//!< unmined sends in neither chain nor mempool, not conflicted
        size_t nExpiringSoon = 0;       //!< unmined sends (in the mempool or not) that expire within TX_EXPIRING_SOON_THRESHOLD blocks
        size_t nExpired = 0;            //!< unmined sends that can no longer be mined
        size_t nConflicted = 0;         //!< unmined sends a mined transaction conflicts with
    };
    //! One pass over mapWallet; cs_main and cs_wallet must be held. Never decrypts, never writes.
    void GetHealth(Health& h) const;
    //! "mined", "pending", "expiringsoon", "expired" or "conflicted" (cs_main held)
    const char* TxStatus(const CWalletTx& wtx) const;

    bool IsLockedCoin(uint256 hash, unsigned int n) const;
    void LockCoin(COutPoint& output);
    void UnlockCoin(COutPoint& output);
    void UnlockAllCoins();
    void ListLockedCoins(std::vector<COutPoint>& vOutpts);

    bool IsLockedNote(const JSOutPoint& outpt) const;
    void LockNote(const JSOutPoint& output);
    void UnlockNote(const JSOutPoint& output);
    void UnlockAllSproutNotes();
    std::vector<JSOutPoint> ListLockedSproutNotes();

    bool IsLockedNote(const SaplingOutPoint& output) const;
    void LockNote(const SaplingOutPoint& output);
    void UnlockNote(const SaplingOutPoint& output);
    void UnlockAllSaplingNotes();
    std::vector<SaplingOutPoint> ListLockedSaplingNotes();

    /**
     * keystore implementation
     * Generate a new key
     */
    CPubKey GenerateNewKey();
    //! Adds a key to the store, and saves it to disk.
    bool AddKeyPubKey(const CKey& key, const CPubKey &pubkey);
    //! Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey& key, const CPubKey &pubkey) { return CCryptoKeyStore::AddKeyPubKey(key, pubkey); }
    //! Load metadata (used by LoadWallet)
    bool LoadKeyMetadata(const CPubKey &pubkey, const CKeyMetadata &metadata);

    bool LoadMinVersion(int nVersion) { AssertLockHeld(cs_wallet); nWalletVersion = nVersion; nWalletMaxVersion = std::max(nWalletMaxVersion, nVersion); return true; }

    //! Adds an encrypted key to the store, and saves it to disk.
    bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    //! Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    bool AddCScript(const CScript& redeemScript);
    bool LoadCScript(const CScript& redeemScript);

    //! Adds a destination data tuple to the store, and saves it to disk
    bool AddDestData(const CTxDestination &dest, const std::string &key, const std::string &value);
    //! Erases a destination data tuple in the store and on disk
    bool EraseDestData(const CTxDestination &dest, const std::string &key);
    //! Adds a destination data tuple to the store, without saving it to disk
    bool LoadDestData(const CTxDestination &dest, const std::string &key, const std::string &value);
    //! Look up a destination data tuple in the store, return true if found false otherwise
    bool GetDestData(const CTxDestination &dest, const std::string &key, std::string *value) const;

    //! Adds a watch-only address to the store, and saves it to disk.
    bool AddWatchOnly(const CScript &dest);
    bool RemoveWatchOnly(const CScript &dest);
    //! Adds a watch-only address to the store, without saving it to disk (used by LoadWallet)
    bool LoadWatchOnly(const CScript &dest);

    bool Unlock(const SecureString& strWalletPassphrase);
    bool ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase);
    bool EncryptWallet(const SecureString& strWalletPassphrase);

    void GetKeyBirthTimes(std::map<CKeyID, int64_t> &mapKeyBirth) const;

    /**
      * Sprout ZKeys
      */
    //! Generates a new Sprout zaddr
    libzcash::SproutPaymentAddress GenerateNewSproutZKey();
    //! Adds spending key to the store, and saves it to disk
    bool AddSproutZKey(const libzcash::SproutSpendingKey &key);
    //! Adds spending key to the store, without saving it to disk (used by LoadWallet)
    bool LoadZKey(const libzcash::SproutSpendingKey &key);
    //! Load spending key metadata (used by LoadWallet)
    bool LoadZKeyMetadata(const libzcash::SproutPaymentAddress &addr, const CKeyMetadata &meta);
    //! Adds an encrypted spending key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedZKey(const libzcash::SproutPaymentAddress &addr, const libzcash::ReceivingKey &rk, const std::vector<unsigned char> &vchCryptedSecret);
    //! Adds an encrypted spending key to the store, and saves it to disk (virtual method, declared in crypter.h)
    bool AddCryptedSproutSpendingKey(
        const libzcash::SproutPaymentAddress &address,
        const libzcash::ReceivingKey &rk,
        const std::vector<unsigned char> &vchCryptedSecret);

    //! Adds a Sprout viewing key to the store, and saves it to disk.
    bool AddSproutViewingKey(const libzcash::SproutViewingKey &vk);
    bool RemoveSproutViewingKey(const libzcash::SproutViewingKey &vk);
    //! Adds a Sprout viewing key to the store, without saving it to disk (used by LoadWallet)
    bool LoadSproutViewingKey(const libzcash::SproutViewingKey &dest);

    /**
      * Sapling ZKeys
      */
    //! Generates new Sapling key
    libzcash::SaplingPaymentAddress GenerateNewSaplingZKey();
    //! Adds Sapling spending key to the store, and saves it to disk
    bool AddSaplingZKey(
        const libzcash::SaplingExtendedSpendingKey &key,
        const libzcash::SaplingPaymentAddress &defaultAddr);
    bool AddSaplingIncomingViewingKey(
        const libzcash::SaplingIncomingViewingKey &ivk,
        const libzcash::SaplingPaymentAddress &addr);
    bool AddCryptedSaplingSpendingKey(
        const libzcash::SaplingExtendedFullViewingKey &extfvk,
        const std::vector<unsigned char> &vchCryptedSecret,
        const libzcash::SaplingPaymentAddress &defaultAddr);
    //! Adds spending key to the store, without saving it to disk (used by LoadWallet)
    bool LoadSaplingZKey(const libzcash::SaplingExtendedSpendingKey &key);
    //! Load spending key metadata (used by LoadWallet)
    bool LoadSaplingZKeyMetadata(const libzcash::SaplingIncomingViewingKey &ivk, const CKeyMetadata &meta);
    //! Adds a Sapling payment address -> incoming viewing key map entry,
    //! without saving it to disk (used by LoadWallet)
    bool LoadSaplingPaymentAddress(
        const libzcash::SaplingPaymentAddress &addr,
        const libzcash::SaplingIncomingViewingKey &ivk);
    //! Adds an encrypted spending key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedSaplingZKey(const libzcash::SaplingExtendedFullViewingKey &extfvk,
                                const std::vector<unsigned char> &vchCryptedSecret);

    /** 
     * Increment the next transaction order id
     * @return next transaction order id
     */
    int64_t IncOrderPosNext(CWalletDB *pwalletdb = NULL);

    typedef std::pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef std::multimap<int64_t, TxPair > TxItems;

    /**
     * Get the wallet's activity log
     * @return multimap of ordered transactions and accounting entries
     * @warning Returned pointers are *only* valid within the scope of passed acentries
     */
    TxItems OrderedTxItems(std::list<CAccountingEntry>& acentries, std::string strAccount = "");

    void MarkDirty();
    bool UpdateNullifierNoteMap();
    void UpdateNullifierNoteMapWithTx(const CWalletTx& wtx);
    void UpdateSaplingNullifierNoteMapWithTx(CWalletTx& wtx);
    void UpdateSaplingNullifierNoteMapForBlock(const CBlock* pblock);
    bool AddToWallet(const CWalletTx& wtxIn, bool fFromLoadWallet, CWalletDB* pwalletdb);
    void SyncTransaction(const CTransaction& tx, const CBlock* pblock);
    bool AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate);
    void EraseFromWallet(const uint256 &hash);
    void WitnessNoteCommitment(
         std::vector<uint256> commitments,
         std::vector<boost::optional<SproutWitness>>& witnesses,
         uint256 &final_anchor);
    int ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate = false);
    /**
     * Offers the wallet transactions neither in the chain nor in the mempool to the
     * mempool; when some were refused that a later tip could still admit, arms the
     * retry at the next tips (nReacceptTipsLeft), as after a disconnect: a send that
     * builds on another one of the wallet's only becomes valid once that one is in a
     * block. Returns how many were refused that a later tip could still admit
     * (expired or expiring ones are not counted: the mempool never takes them).
     */
    size_t ReacceptWalletTransactions();
    /** The offer itself, without arming the retry (UpdatedBlockTip); pnPassedToMempool, when given, receives how many transactions were handed to the mempool (the others lacked their inputs or anchors at this tip). */
    size_t OfferWalletTransactionsToMempool(size_t* pnPassedToMempool = NULL);
    void ResendWalletTransactions(int64_t nBestBlockTime);
    std::vector<uint256> ResendWalletTransactionsBefore(int64_t nTime);
    CAmount GetBalance() const;
    CAmount GetUnconfirmedBalance() const;
    CAmount GetImmatureBalance() const;
    CAmount GetWatchOnlyBalance() const;
    CAmount GetUnconfirmedWatchOnlyBalance() const;
    CAmount GetImmatureWatchOnlyBalance() const;
    /**
     * fAllowTokenInputs is the wallet token guard override for the inputs the
     * caller already put in tx. Inputs this function adds are never
     * token-bearing, whatever the flag says. With the flag set the change
     * output is appended last, so the outputs of a token transaction (named by
     * position) never move.
     */
    bool FundTransaction(CMutableTransaction& tx, CAmount& nFeeRet, int& nChangePosRet, std::string& strFailReason, bool fAllowTokenInputs = false);
    bool CreateTransaction(const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosRet,
                           std::string& strFailReason, const CCoinControl *coinControl = NULL, bool sign = true);
    /** On failure pstrError (if given) receives the reason when one is known, e.g. "mempool full". */
    bool CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey, std::string* pstrError = nullptr);

    static CFeeRate minTxFee;
    static CAmount GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CTxMemPool& pool);

    bool NewKeyPool();
    bool TopUpKeyPool(unsigned int kpSize = 0);
    void ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool);
    void KeepKey(int64_t nIndex);
    void ReturnKey(int64_t nIndex);
    bool GetKeyFromPool(CPubKey &key);
    int64_t GetOldestKeyPoolTime();
    void GetAllReserveKeys(std::set<CKeyID>& setAddress) const;

    std::set< std::set<CTxDestination> > GetAddressGroupings();
    std::map<CTxDestination, CAmount> GetAddressBalances();

    std::set<CTxDestination> GetAccountAddresses(const std::string& strAccount) const;

    boost::optional<uint256> GetSproutNoteNullifier(
        const JSDescription& jsdesc,
        const libzcash::SproutPaymentAddress& address,
        const ZCNoteDecryption& dec,
        const uint256& hSig,
        uint8_t n,
        // Optional out-param: if non-null, receives the decrypted note's
        // plaintext value (a non-invertible CAmount). Surfaced so
        // FindMySproutNotes can populate SproutNoteData::value without a second
        // decrypt. The nullifier behaviour is unchanged whether or not this is
        // supplied. Defaulted so existing 5-arg callers are unaffected.
        boost::optional<CAmount>* valueOut = nullptr) const;
    mapSproutNoteData_t FindMySproutNotes(const CTransaction& tx) const;
    std::pair<mapSaplingNoteData_t, SaplingIncomingViewingKeyMap> FindMySaplingNotes(const CTransaction& tx) const;
    bool IsSproutNullifierFromMe(const uint256& nullifier) const;
    bool IsSaplingNullifierFromMe(const uint256& nullifier) const;

    // Both return false (and clear every witness) when the selected notes
    // carry witnesses with different roots: the wallet note data is out of
    // step and the caller must refuse the spend (no assert, no abort).
    bool GetSproutNoteWitnesses(
         std::vector<JSOutPoint> notes,
         std::vector<boost::optional<SproutWitness>>& witnesses,
         uint256 &final_anchor);
    bool GetSaplingNoteWitnesses(
         std::vector<SaplingOutPoint> notes,
         std::vector<boost::optional<SaplingWitness>>& witnesses,
         uint256 &final_anchor);

    isminetype IsMine(const CTxIn& txin) const;
    CAmount GetDebit(const CTxIn& txin, const isminefilter& filter) const;
    isminetype IsMine(const CTxOut& txout) const;
    CAmount GetCredit(const CTxOut& txout, const isminefilter& filter) const;
    bool IsChange(const CTxOut& txout) const;
    CAmount GetChange(const CTxOut& txout) const;
    bool IsMine(const CTransaction& tx) const;
    /** should probably be renamed to IsRelevantToMe */
    bool IsFromMe(const CTransaction& tx) const;
    CAmount GetDebit(const CTransaction& tx, const isminefilter& filter) const;
    CAmount GetCredit(const CTransaction& tx, const isminefilter& filter) const;
    CAmount GetChange(const CTransaction& tx) const;
    void ChainTip(const CBlockIndex *pindex, const CBlock *pblock, const SproutMerkleTree& sproutTree, const SaplingMerkleTree& saplingTree, bool added);
    /** After an unwind: re-offers the wallet transactions the chain no longer holds to the mempool. */
    void UpdatedBlockTip(const CBlockIndex *pindex);
    /** Saves witness caches and best block locator to disk. */
    void SetBestChain(const CBlockLocator& loc);
    std::set<std::pair<libzcash::PaymentAddress, uint256>> GetNullifiersForAddresses(const std::set<libzcash::PaymentAddress> & addresses);
    bool IsNoteSproutChange(const std::set<std::pair<libzcash::PaymentAddress, uint256>> & nullifierSet, const libzcash::PaymentAddress & address, const JSOutPoint & entry);
    bool IsNoteSaplingChange(const std::set<std::pair<libzcash::PaymentAddress, uint256>> & nullifierSet, const libzcash::PaymentAddress & address, const SaplingOutPoint & entry);

    DBErrors LoadWallet(bool& fFirstRunRet);
    DBErrors ZapWalletTx(std::vector<CWalletTx>& vWtx);

    bool SetAddressBook(const CTxDestination& address, const std::string& strName, const std::string& purpose);

    bool DelAddressBook(const CTxDestination& address);

    void UpdatedTransaction(const uint256 &hashTx);

    void Inventory(const uint256 &hash)
    {
        {
            LOCK(cs_wallet);
            std::map<uint256, int>::iterator mi = mapRequestCount.find(hash);
            if (mi != mapRequestCount.end())
                (*mi).second++;
        }
    }

    void GetScriptForMining(boost::shared_ptr<CReserveScript> &script);
    void ResetRequestCount(const uint256 &hash)
    {
        LOCK(cs_wallet);
        mapRequestCount[hash] = 0;
    };
    
    unsigned int GetKeyPoolSize()
    {
        AssertLockHeld(cs_wallet); // setKeyPool
        return setKeyPool.size();
    }

    bool SetDefaultKey(const CPubKey &vchPubKey);

    //! signify that a particular wallet feature is now used. this may change nWalletVersion and nWalletMaxVersion if those are lower
    bool SetMinVersion(enum WalletFeature, CWalletDB* pwalletdbIn = NULL, bool fExplicit = false);

    //! change which version we're allowed to upgrade to (note that this does not immediately imply upgrading to that format)
    bool SetMaxVersion(int nVersion);

    //! get the current wallet format (the oldest client version guaranteed to understand this wallet)
    int GetVersion() { LOCK(cs_wallet); return nWalletVersion; }

    //! Get wallet transactions that conflict with given transaction (spend same outputs)
    std::set<uint256> GetConflicts(const uint256& txid) const;

    //! Flush wallet (bitdb flush)
    void Flush(bool shutdown=false);

    //! Verify the wallet database and perform salvage if required
    static bool Verify(const std::string& walletFile, std::string& warningString, std::string& errorString);
    
    /** 
     * Address book entry changed.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void (CWallet *wallet, const CTxDestination
            &address, const std::string &label, bool isMine,
            const std::string &purpose,
            ChangeType status)> NotifyAddressBookChanged;

    /** 
     * Wallet transaction added, removed or updated.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void (CWallet *wallet, const uint256 &hashTx,
            ChangeType status)> NotifyTransactionChanged;

    /** Show progress e.g. for rescan */
    boost::signals2::signal<void (const std::string &title, int nProgress)> ShowProgress;

    /** Watch-only address added */
    boost::signals2::signal<void (bool fHaveWatchOnly)> NotifyWatchonlyChanged;

    /** Inquire whether this wallet broadcasts transactions. */
    bool GetBroadcastTransactions() const { return fBroadcastTransactions; }
    /** Set whether this wallet broadcasts transactions. */
    void SetBroadcastTransactions(bool broadcast) { fBroadcastTransactions = broadcast; }
    //! Drop the cached transaction-order index (rebuilt on next use); call after changing any nOrderPos. Requires cs_wallet.
    void InvalidateTxOrderIndex() { fTxOrderValid = false; }

    /* Returns true if HD is enabled for all address types, false if only for Sapling */
    bool IsHDFullyEnabled() const;

    /* Generates a new HD seed (will reset the chain child index counters)
       Sets the seed's version based on the current wallet version (so the
       caller must ensure the current wallet version is correct before calling
       this function). */
    void GenerateNewSeed();

    bool SetHDSeed(const HDSeed& seed);
    bool SetCryptedHDSeed(const uint256& seedFp, const std::vector<unsigned char> &vchCryptedSecret);

    /* Set the HD chain model (chain child index counters) */
    void SetHDChain(const CHDChain& chain, bool memonly);
    const CHDChain& GetHDChain() const { return hdChain; }

    /* Set the current HD seed, without saving it to disk (used by LoadWallet) */
    bool LoadHDSeed(const HDSeed& key);
    /* Set the current encrypted HD seed, without saving it to disk (used by LoadWallet) */
    bool LoadCryptedHDSeed(const uint256& seedFp, const std::vector<unsigned char>& seed);
    
    /* Find notes filtered by payment address, min depth, ability to spend */
    void GetFilteredNotes(std::vector<CSproutNotePlaintextEntry>& sproutEntries,
                          std::vector<SaplingNoteEntry>& saplingEntries,
                          std::string address,
                          int minDepth=1,
                          bool ignoreSpent=true,
                          bool requireSpendingKey=true);

    /* Find notes filtered by payment addresses, min depth, max depth, if they are spent,
       if a spending key is required, and if they are locked */
    void GetFilteredNotes(std::vector<CSproutNotePlaintextEntry>& sproutEntries,
                          std::vector<SaplingNoteEntry>& saplingEntries,
                          std::set<libzcash::PaymentAddress>& filterAddresses,
                          int minDepth=1,
                          int maxDepth=INT_MAX,
                          bool ignoreSpent=true,
                          bool requireSpendingKey=true,
                          bool ignoreLocked=true);

    /**
     * Sum of the Sapling note values GetFilteredNotes would return for the same
     * arguments (maxDepth = INT_MAX, ignoreSpent = true), without constructing
     * the plaintext entries: it reads the memory-only SaplingNoteData::value and
     * ::address caches, decrypting a note only on a cache miss (and then filling
     * both). Only non-invertible amounts and public payment addresses are cached;
     * no note randomness, memo or key material.
     */
    CAmount GetSaplingBalanceFiltered(const std::set<libzcash::PaymentAddress>& filterAddresses,
                                      int minDepth = 1,
                                      bool requireSpendingKey = true,
                                      bool ignoreLocked = true);

    /**
     * Sum of the wallet's spendable Sapling note values, using the MEMORY-ONLY
     * cached SaplingNoteData::value to avoid re-decrypting every note on a
     * balance read. Applies the SAME per-note filter as GetFilteredNotes (via
     * SaplingNotePassesSpendFilter), so it returns an IDENTICAL Sapling total to
     * the slow GetFilteredNotes path for the unfiltered wallet (no address
     * filter — recovering an address requires a decrypt).
     *
     * The cache is memory-only, so on a fresh load a note's value may be
     * boost::none; in that case this DECRYPTS the note to obtain the value and
     * populates the cache (decrypt-fallback). A none value is NEVER treated as 0.
     *
     * Only a non-invertible CAmount is read/summed; no key material is exposed.
     */
    CAmount GetSaplingBalanceCached(int minDepth = 1,
                                    bool requireSpendingKey = true,
                                    bool ignoreLocked = true);

    /**
     * Sum of the wallet's spendable Sprout note values, using the MEMORY-ONLY
     * cached SproutNoteData::value to avoid re-decrypting every note on a
     * balance read. Applies the SAME per-note filter as GetFilteredNotes
     * (ignoreSpent via IsSproutSpent, requireSpendingKey via
     * HaveSproutSpendingKey, ignoreLocked via IsLockedNote), so it returns an
     * IDENTICAL Sprout total to the slow GetFilteredNotes path for the
     * unfiltered wallet. Sprout's payment address lives in the note data
     * (nd.address), so NO decrypt is needed for the filter.
     *
     * The cache is memory-only, so on a fresh load a note's value may be
     * boost::none; in that case this DECRYPTS the note to obtain the value and
     * populates the cache (decrypt-fallback). A none value is NEVER treated as 0.
     *
     * Only a non-invertible CAmount is read/summed; no key material is exposed.
     */
    CAmount GetSproutBalanceCached(int minDepth = 1,
                                   bool requireSpendingKey = true,
                                   bool ignoreLocked = true);
};

/** A key allocated from the key pool. */
class CReserveKey : public CReserveScript
{
protected:
    CWallet* pwallet;
    int64_t nIndex;
    CPubKey vchPubKey;
public:
    CReserveKey(CWallet* pwalletIn)
    {
        nIndex = -1;
        pwallet = pwalletIn;
    }

    ~CReserveKey()
    {
        ReturnKey();
    }

    void ReturnKey();
    virtual bool GetReservedKey(CPubKey &pubkey);
    void KeepKey();
    void KeepScript() { KeepKey(); }
};


/** 
 * Account information.
 * Stored in wallet with key "acc"+string account name.
 */
class CAccount
{
public:
    CPubKey vchPubKey;

    CAccount()
    {
        SetNull();
    }

    void SetNull()
    {
        vchPubKey = CPubKey();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPubKey);
    }
};

//
// Shielded key and address generalizations
//

class PaymentAddressBelongsToWallet : public boost::static_visitor<bool>
{
private:
    CWallet *m_wallet;
public:
    PaymentAddressBelongsToWallet(CWallet *wallet) : m_wallet(wallet) {}

    bool operator()(const libzcash::SproutPaymentAddress &zaddr) const;
    bool operator()(const libzcash::SaplingPaymentAddress &zaddr) const;
    bool operator()(const libzcash::InvalidEncoding& no) const;
};

class HaveSpendingKeyForPaymentAddress : public boost::static_visitor<bool>
{
private:
    CWallet *m_wallet;
public:
    HaveSpendingKeyForPaymentAddress(CWallet *wallet) : m_wallet(wallet) {}

    bool operator()(const libzcash::SproutPaymentAddress &zaddr) const;
    bool operator()(const libzcash::SaplingPaymentAddress &zaddr) const;
    bool operator()(const libzcash::InvalidEncoding& no) const;
};

class GetSpendingKeyForPaymentAddress : public boost::static_visitor<boost::optional<libzcash::SpendingKey>>
{
private:
    CWallet *m_wallet;
public:
    GetSpendingKeyForPaymentAddress(CWallet *wallet) : m_wallet(wallet) {}

    boost::optional<libzcash::SpendingKey> operator()(const libzcash::SproutPaymentAddress &zaddr) const;
    boost::optional<libzcash::SpendingKey> operator()(const libzcash::SaplingPaymentAddress &zaddr) const;
    boost::optional<libzcash::SpendingKey> operator()(const libzcash::InvalidEncoding& no) const;
};

enum SpendingKeyAddResult {
    KeyAlreadyExists,
    KeyAdded,
    KeyNotAdded,
};

class AddSpendingKeyToWallet : public boost::static_visitor<SpendingKeyAddResult>
{
private:
    CWallet *m_wallet;
    const Consensus::Params &params;
    int64_t nTime;
    boost::optional<std::string> hdKeypath; // currently sapling only
    boost::optional<std::string> seedFpStr; // currently sapling only
    bool log;
public: 
    AddSpendingKeyToWallet(CWallet *wallet, const Consensus::Params &params) :
        m_wallet(wallet), params(params), nTime(1), hdKeypath(boost::none), seedFpStr(boost::none), log(false) {}
    AddSpendingKeyToWallet(
        CWallet *wallet,
        const Consensus::Params &params,
        int64_t _nTime,
        boost::optional<std::string> _hdKeypath,
        boost::optional<std::string> _seedFp,
        bool _log
    ) : m_wallet(wallet), params(params), nTime(_nTime), hdKeypath(_hdKeypath), seedFpStr(_seedFp), log(_log) {}


    SpendingKeyAddResult operator()(const libzcash::SproutSpendingKey &sk) const;
    SpendingKeyAddResult operator()(const libzcash::SaplingExtendedSpendingKey &sk) const;
    SpendingKeyAddResult operator()(const libzcash::InvalidEncoding& no) const;    
};



/**
 * Pre-proving gate for a spend of wallet notes. Returns false and sets
 * strError (an RPC-ready message) when the witnesses of the selected notes
 * did not share one root (consistent == false), a selected note has no
 * witness, or the anchor is not one the chain knows (the same
 * GetXxxAnchorAt test mempool admission makes), so no proving time is spent
 * on a transaction that would be rejected. Does not require the anchor to be
 * the tip root. Caller holds cs_main.
 */
bool CheckSaplingSpendWitnesses(bool consistent,
                                const std::vector<boost::optional<SaplingWitness>>& witnesses,
                                const uint256& anchor,
                                const CCoinsViewCache& view,
                                std::string& strError);
bool CheckSproutSpendWitnesses(bool consistent,
                               const std::vector<boost::optional<SproutWitness>>& witnesses,
                               const uint256& anchor,
                               const CCoinsViewCache& view,
                               std::string& strError);

#endif // BITCOIN_WALLET_WALLET_H
