// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "wallet/walletphrase.h"

#include "chainparams.h"
#include "key.h"
#include "key_io.h"
#include "main.h"
#include "script/standard.h"
#include "util.h"
#include "wallet/phrase.h"
#include "wallet/wallet.h"
#include "wallet/wallet_ismine.h"
#include "wallet/walletdb.h"

#include <set>
#include <stdexcept>

namespace {

const int TRANSPARENT_GAP = 20;   // restore: derive more when a key this close to the pool's end was used
const uint32_t SAPLING_BATCH = 5; // restore: Sapling accounts derived per round
const int64_t SAPLING_GAP = 3;    // ... and when one of the newest three was used
const int MAX_ROUNDS = 20;        // restore: rescans at most

// True while RestoreFromPhrase runs (under cs_wallet). Keys derived then may be as old
// as the chain, so they are stamped with the earliest birthday instead of today.
bool fRestoring = false;
struct RestoringScope {
    RestoringScope() { fRestoring = true; }
    ~RestoringScope() { fRestoring = false; }
};

// The account number of a Sapling keypath "m/32'/<coin>'/<account>'", or -1.
int64_t SaplingAccount(const std::string& keypath, uint32_t coinType)
{
    const std::string prefix = "m/32'/" + std::to_string(coinType) + "'/";
    if (keypath.compare(0, prefix.size(), prefix) != 0 || keypath.size() < prefix.size() + 2
            || keypath.back() != '\'')
        return -1;
    int64_t n = 0;
    for (size_t i = prefix.size(); i + 1 < keypath.size(); i++) {
        if (keypath[i] < '0' || keypath[i] > '9' || n > 0x7fffffff) return -1;
        n = n * 10 + (keypath[i] - '0');
    }
    return n;
}

// The transparent keys the wallet has seen money arrive at (outputs it can spend).
std::set<CKeyID> KeysWithHistory(const CWallet& w)
{
    std::set<CKeyID> used;
    for (const auto& entry : w.mapWallet) {
        for (const CTxOut& out : entry.second.vout) {
            CTxDestination dest;
            if (!ExtractDestination(out.scriptPubKey, dest)) continue;
            const CKeyID* id = boost::get<CKeyID>(&dest);
            if (id && (IsMine(w, dest) & ISMINE_SPENDABLE)) used.insert(*id);
        }
    }
    return used;
}

std::set<libzcash::SaplingIncomingViewingKey> SaplingKeysWithNotes(const CWallet& w)
{
    std::set<libzcash::SaplingIncomingViewingKey> used;
    for (const auto& entry : w.mapWallet)
        for (const auto& note : entry.second.mapSaplingNoteData)
            used.insert(note.second.ivk);
    return used;
}

const CKeyMetadata* MetadataOf(const CWallet& w, const CKeyID& id)
{
    auto it = w.mapKeyMetadata.find(id);
    return it == w.mapKeyMetadata.end() ? nullptr : &it->second;
}

// Restore, transparent half: pool keys that turned out used leave the pool and get
// an address book entry (as getnewaddress would have given them). True when a used
// key sits so near the end of the derived range that more keys must be scanned.
bool KeepUsedPoolKeys(CWallet& w, const std::set<CKeyID>& used)
{
    const uint32_t coin = Params().BIP44CoinType();
    int64_t maxUsed = -1, maxDerived = -1;
    CWalletDB db(w.strWalletFile);
    const std::set<int64_t> pool = w.setKeyPool;
    for (int64_t index : pool) {
        CKeyPool entry;
        if (!db.ReadPool(index, entry)) continue;
        const CKeyID id = entry.vchPubKey.GetID();
        const CKeyMetadata* meta = MetadataOf(w, id);
        const int64_t derived = meta ? phrase::TransparentIndex(meta->hdKeypath, coin) : -1;
        maxDerived = std::max(maxDerived, derived);
        if (!used.count(id)) continue;
        w.KeepKey(index);
        w.setKeyPool.erase(index);
        w.SetAddressBook(id, "", "receive");
        maxUsed = std::max(maxUsed, derived);
    }
    return maxUsed >= 0 && maxUsed + TRANSPARENT_GAP > maxDerived;
}

// Restore, Sapling half: derive up to target accounts; when one of the newest
// SAPLING_GAP accounts has notes, raise target and say another rescan is needed.
bool DeriveSaplingAccounts(CWallet& w, uint32_t& target)
{
    const uint32_t coin = Params().BIP44CoinType();
    const auto used = SaplingKeysWithNotes(w);
    int64_t highest = -1;
    for (const auto& entry : w.mapSaplingZKeyMetadata)
        if (used.count(entry.first) && KeyFromPhrase(w, entry.second))
            highest = std::max(highest, SaplingAccount(entry.second.hdKeypath, coin));
    const bool more = highest >= 0 && highest + SAPLING_GAP >= (int64_t)target;
    if (more) target = (uint32_t)highest + 1 + SAPLING_BATCH;
    while (w.GetHDChain().saplingAccountCounter < target)
        w.GenerateNewSaplingZKey();
    return more;
}

// Swap the seed: the new "hdseed" and "hdchain" records and the old seed's move to
// "retiredseed" commit in one database transaction, flushed to the log before the
// in-memory seed changes, so a crash leaves either the old seed or the new one.
void SwapSeed(CWallet& w, const HDSeed& seed)
{
    HDSeed old;
    const bool hadSeed = w.GetHDSeed(old);
    if (hadSeed && old == seed) return;
    CHDChain chain;
    chain.seedFp = seed.Fingerprint();
    chain.nCreateTime = GetTime();
    if (w.fFileBacked) {
        CWalletDB db(w.strWalletFile, "r+", false);
        if (!db.TxnBegin()) throw std::runtime_error("could not start a wallet database transaction");
        const bool ok = db.WriteHDSeed(seed) && (!hadSeed || db.RetireHDSeed(old)) && db.WriteHDChain(chain);
        if (!ok) {
            db.TxnAbort();
            throw std::runtime_error("could not write the new seed");
        }
        if (!db.TxnCommit() || !bitdb.FlushLog())
            throw std::runtime_error("could not save the new seed");
    }
    w.ReplaceHDSeed(seed);
    w.SetHDChain(chain, true);
}

// What a restore reports: the derived addresses that turned out used.
PhraseRestoreResult FoundFromPhrase(const CWallet& w)
{
    PhraseRestoreResult result;
    for (const CKeyID& id : KeysWithHistory(w)) {
        const CKeyMetadata* meta = MetadataOf(w, id);
        if (meta && KeyFromPhrase(w, *meta)) result.transparent.push_back(EncodeDestination(id));
    }
    const auto withNotes = SaplingKeysWithNotes(w);
    std::set<libzcash::SaplingPaymentAddress> sapling;
    w.GetSaplingPaymentAddresses(sapling);
    for (const auto& addr : sapling) {
        libzcash::SaplingIncomingViewingKey ivk;
        if (!w.GetSaplingIncomingViewingKey(addr, ivk) || !withNotes.count(ivk)) continue;
        auto meta = w.mapSaplingZKeyMetadata.find(ivk);
        if (meta != w.mapSaplingZKeyMetadata.end() && KeyFromPhrase(w, meta->second))
            result.sapling.push_back(EncodePaymentAddress(addr));
    }
    return result;
}

} // namespace

bool DeriveTransparentKey(const CWallet& w, CKey& secret, CKeyMetadata& meta)
{
    HDSeed seed;
    if (!w.GetHDSeed(seed)) return false;
    const RawHDSeed raw = seed.RawSeed();
    if (raw.size() != phrase::SEED_BYTES) return false;
    const uint32_t coin = Params().BIP44CoinType();
    const uint256 fp = seed.Fingerprint();
    int64_t next = 0;
    for (const auto& entry : w.mapKeyMetadata)
        if (entry.second.seedFp == fp)
            next = std::max(next, phrase::TransparentIndex(entry.second.hdKeypath, coin) + 1);

    CExtKey master, purpose, cointype, account, chain, child;
    master.SetMaster(raw.data(), raw.size());
    if (!master.Derive(purpose, 44 | ZIP32_HARDENED_KEY_LIMIT)
            || !purpose.Derive(cointype, coin | ZIP32_HARDENED_KEY_LIMIT)
            || !cointype.Derive(account, 0 | ZIP32_HARDENED_KEY_LIMIT)
            || !account.Derive(chain, 0))
        return false;
    for (; next < (int64_t)ZIP32_HARDENED_KEY_LIMIT; next++) {
        if (!chain.Derive(child, (unsigned int)next)) continue;   // invalid child: BIP32 says skip
        if (w.HaveKey(child.key.GetPubKey().GetID())) continue;
        secret = child.key;
        meta.hdKeypath = phrase::TransparentKeypath(coin, (uint32_t)next);
        meta.seedFp = fp;
        if (fRestoring) meta.nCreateTime = 1;   // unknown birthday; 0 would mean 'no value'
        return true;
    }
    return false;
}

bool KeyFromPhrase(const CWallet& w, const CKeyMetadata& meta)
{
    // The seed's own fingerprint, which DeriveTransparentKey stamps; the hdchain copy
    // only when the seed cannot be read (an encrypted, locked wallet).
    HDSeed seed;
    const uint256 fp = w.GetHDSeed(seed) ? seed.Fingerprint() : w.GetHDChain().seedFp;
    return !meta.hdKeypath.empty() && !fp.IsNull() && meta.seedFp == fp;
}

void KeepKeyPoolOnPhrase(CWallet& w)
{
    LOCK(w.cs_wallet);
    HDSeed seed;
    if (!w.fFileBacked || w.IsLocked() || !w.GetHDSeed(seed) || seed.RawSeed().size() != phrase::SEED_BYTES)
        return;
    CWalletDB db(w.strWalletFile);
    int dropped = 0;
    const std::set<int64_t> pool = w.setKeyPool;
    for (int64_t index : pool) {
        CKeyPool entry;
        if (!db.ReadPool(index, entry)) continue;
        const CKeyMetadata* meta = MetadataOf(w, entry.vchPubKey.GetID());
        if (meta && KeyFromPhrase(w, *meta)) continue;
        db.ErasePool(index);   // the key itself stays in the wallet
        w.setKeyPool.erase(index);
        dropped++;
    }
    if (dropped) {
        LogPrintf("recovery phrase: %d key pool keys did not come from the seed; refilling the pool\n", dropped);
        w.TopUpKeyPool();
    }
}

std::vector<std::string> AddressesNotInPhrase(const CWallet& w)
{
    LOCK2(cs_main, w.cs_wallet);
    std::vector<std::string> out;
    std::set<CKeyID> transparent = KeysWithHistory(w);
    for (const auto& entry : w.mapAddressBook) {
        const CKeyID* id = boost::get<CKeyID>(&entry.first);
        if (id && w.HaveKey(*id)) transparent.insert(*id);
    }
    for (const CKeyID& id : transparent) {
        const CKeyMetadata* meta = MetadataOf(w, id);
        if (!meta || !KeyFromPhrase(w, *meta)) out.push_back(EncodeDestination(id));
    }
    std::set<libzcash::SaplingPaymentAddress> sapling;
    w.GetSaplingPaymentAddresses(sapling);
    for (const auto& addr : sapling) {
        libzcash::SaplingIncomingViewingKey ivk;
        libzcash::SaplingFullViewingKey fvk;
        if (!w.GetSaplingIncomingViewingKey(addr, ivk) || !w.GetSaplingFullViewingKey(ivk, fvk)
                || !w.HaveSaplingSpendingKey(fvk))
            continue;   // watch-only: nothing to back up
        auto meta = w.mapSaplingZKeyMetadata.find(ivk);
        if (meta == w.mapSaplingZKeyMetadata.end() || !KeyFromPhrase(w, meta->second))
            out.push_back(EncodePaymentAddress(addr));
    }
    std::set<libzcash::SproutPaymentAddress> sprout;   // Sprout keys are never derived
    w.GetSproutPaymentAddresses(sprout);
    for (const auto& addr : sprout)
        if (w.HaveSproutSpendingKey(addr)) out.push_back(EncodePaymentAddress(addr));
    return out;
}

PhraseRestoreResult RestoreFromPhrase(CWallet& w, const HDSeed& seed, int startHeight)
{
    LOCK2(cs_main, w.cs_wallet);
    if (w.IsCrypted())
        throw std::runtime_error("a recovery phrase can only be restored into an unencrypted wallet");
    if (seed.RawSeed().size() != phrase::SEED_BYTES)
        throw std::runtime_error("the seed must be 32 bytes");
    if (startHeight < 0 || startHeight > chainActive.Height())
        throw std::runtime_error("start height is out of range");

    SwapSeed(w, seed);
    // The phrase's keys may be as old as the chain. ScanForWalletTransactions skips
    // every block older than the wallet's first key, and a fresh wallet's first key
    // was made today: without this a restore into a new wallet scans nothing and
    // shows a zero balance. Keys derived during the restore carry the same birthday
    // in the wallet file, so a later -rescan covers the whole chain as well.
    RestoringScope restoring;
    w.nTimeFirstKey = 1;   // 0 would be considered 'no value'
    KeepKeyPoolOnPhrase(w);
    uint32_t target = SAPLING_BATCH;
    DeriveSaplingAccounts(w, target);
    for (int round = 1; ; round++) {
        LogPrintf("recovery phrase: rescanning from height %d (round %d)\n", startHeight, round);
        w.ScanForWalletTransactions(chainActive[startHeight], true);
        bool more = KeepUsedPoolKeys(w, KeysWithHistory(w));
        more = DeriveSaplingAccounts(w, target) || more;
        if (!more || round >= MAX_ROUNDS) break;
        w.TopUpKeyPool();
    }
    w.TopUpKeyPool();
    return FoundFromPhrase(w);
}
