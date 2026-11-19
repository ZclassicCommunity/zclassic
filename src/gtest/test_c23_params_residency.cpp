// Lazy proving parameters (src/c23/compat/zcl_params_lazy.h): after init the
// process holds no raw proving bytes, the first proof loads and re-verifies
// the Sapling pair (once, however many proofs race for it), a parameter file
// changed on disk after init refuses the proof instead of proving from it, and
// ZCL_PARAMS_VERIFY=boot keeps the abort-at-init behaviour. A wrong Sprout file
// is found before the first Sprout proof, which then aborts (no failure value).
//
// The tests that re-initialise the parameters do it in a forked child
// (EXPECT_EXIT / EXPECT_DEATH), on copies in a fresh temporary directory: the
// real parameter directory is only ever read.
#include "chainparams.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "main.h"
#include "transaction_builder.h"
#include "util.h"
#include "utiltest.h"
#include "zcash/JoinSplit.hpp"
#include "zcash/Note.hpp"
#include "zcash/NoteEncryption.hpp"
#include "zcash/Zcash.h"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include <boost/filesystem.hpp>

#ifndef WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "librustzcash.h"

using namespace libzcash;

extern ZCJoinSplit* params;

namespace {

namespace fs = boost::filesystem;

const char SPEND_B2[] =
    "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";
const char OUTPUT_B2[] =
    "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";
const char SPROUT_B2[] =
    "e9b238411bd6c0ec4791e9d04245ec350c9c5744f5610dfcce4365d5ca49dfefd5054e371842b3f88fa1b9d7e8e075249b3ebabd167fa8b0f3161292d36c180a";
const uint64_t SPROUT_SIZE = UINT64_C(725523612);

bool BootMode()
{
    const char* v = getenv("ZCL_PARAMS_VERIFY");
    return v && std::string(v) == "boot";
}

void InitParams(const fs::path& dir)
{
    auto spend = (dir / "sapling-spend.params").native();
    auto output = (dir / "sapling-output.params").native();
    auto sprout = (dir / "sprout-groth16.params").native();
    librustzcash_init_zksnark_params(
        reinterpret_cast<const codeunit*>(spend.c_str()), spend.length(), SPEND_B2,
        reinterpret_cast<const codeunit*>(output.c_str()), output.length(), OUTPUT_B2,
        reinterpret_cast<const codeunit*>(sprout.c_str()), sprout.length(), SPROUT_B2);
}

bool NotInitialBlockDownload() { return false; }

// Full consensus verification of every proof and signature of tx.
bool ConsensusAccepts(const CTransaction& tx, std::string& reason)
{
    CValidationState state;
    bool ok = ContextualCheckTransaction(tx, state, 2, 100, NotInitialBlockDownload);
    reason = state.GetRejectReason();
    return ok;
}

// One Sapling spend and one Sapling output (spend and output proofs).
TransactionBuilderResult BuildSpendTx(const Consensus::Params& cp)
{
    auto sk = libzcash::SaplingSpendingKey::random();
    auto expsk = sk.expanded_spending_key();
    auto pa = sk.default_address();
    auto testNote = GetTestSaplingNote(pa, 50000);
    auto builder = TransactionBuilder(cp, 1);
    builder.SetFee(10000);
    builder.AddSaplingSpend(expsk, testNote.note, testNote.tree.root(), testNote.tree.witness());
    builder.AddSaplingOutput(sk.full_viewing_key().ovk, pa, 25000, {});
    return builder.Build();
}

// A transparent input shielded to one Sapling output (output proofs only).
TransactionBuilderResult BuildOutputTx(const Consensus::Params& cp)
{
    CBasicKeyStore keyStore;
    CKey tsk = AddTestCKeyToKeyStore(keyStore);
    auto scriptPubKey = GetScriptForDestination(tsk.GetPubKey().GetID());
    auto sk = libzcash::SaplingSpendingKey::random();
    auto builder = TransactionBuilder(cp, 1, &keyStore);
    builder.SetFee(10000);
    builder.AddTransparentInput(COutPoint(), scriptPubKey, 100000);
    builder.SendChangeTo(sk.default_address(), sk.full_viewing_key().ovk);
    builder.AddSaplingOutput(sk.full_viewing_key().ovk, sk.default_address(), 20000, {});
    return builder.Build();
}

// One direct output proof on a fresh context; true and a non-zero proof, or
// false and the output buffer untouched (all zero).
bool DirectOutputProof(std::array<unsigned char, GROTH_PROOF_SIZE>& proof)
{
    auto pa = libzcash::SaplingSpendingKey::random().default_address();
    libzcash::SaplingNote note(pa, 1000);
    std::array<unsigned char, ZC_MEMO_SIZE> memo = {};
    auto enc = libzcash::SaplingNotePlaintext(note, memo).encrypt(note.pk_d).get();
    uint256 cv;
    proof.fill(0);
    void* ctx = librustzcash_sapling_proving_ctx_init();
    bool ok = librustzcash_sapling_output_proof(
        ctx, enc.second.get_esk().begin(), note.d.data(), note.pk_d.begin(),
        note.r.begin(), note.value(), cv.begin(), proof.data());
    librustzcash_sapling_proving_ctx_free(ctx);
    return ok;
}

bool AllZero(const std::array<unsigned char, GROTH_PROOF_SIZE>& b)
{
    for (unsigned char c : b)
        if (c != 0)
            return false;
    return true;
}

} // namespace

TEST(C23ParamsResidency, InitHoldsNoProvingBytesInLazyMode)
{
    ASSERT_TRUE(zcl_c23_params_initialized());
    if (BootMode()) {
        EXPECT_STREQ(zcl_c23_proving_status(), "resident");
        EXPECT_EQ(zcl_c23_params_bytes_resident(), size_t(47958396 + 3592860));
        return;
    }
    EXPECT_STREQ(zcl_c23_proving_status(), "registered");
    EXPECT_EQ(zcl_c23_params_bytes_resident(), 0u);
    EXPECT_FALSE(zcl_c23_proving_keys_parsed());
}

TEST(C23ParamsResidency, LazyProofsVerifyAndRacingFirstProofsLoadOnce)
{
    auto cp = RegtestActivateSapling();
    std::string reason;

    // Spend and output proofs made from lazily loaded keys pass consensus.
    auto spendTx = BuildSpendTx(cp).GetTxOrThrow();
    EXPECT_TRUE(ConsensusAccepts(spendTx, reason)) << reason;
    auto outTx = BuildOutputTx(cp).GetTxOrThrow();
    EXPECT_TRUE(ConsensusAccepts(outTx, reason)) << reason;
    EXPECT_FALSE(zcl_c23_proving_keys_parsed()); // released with the last context
    EXPECT_EQ(zcl_c23_params_bytes_resident(), BootMode() ? size_t(47958396 + 3592860) : 0u);

    // Four sends start at once while one context is held: one load in lazy
    // mode, and every transaction verifies.
    void* held = librustzcash_sapling_proving_ctx_init();
    const unsigned loads0 = zcl_c23_proving_keys_loads();
    std::atomic<int> ready(0), accepted(0);
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; t++) {
        threads.emplace_back([&]() {
            ready++;
            while (ready.load() < 4) {
                std::this_thread::yield();
            }
            auto r = BuildOutputTx(cp);
            std::string why;
            if (r.IsTx() && ConsensusAccepts(r.GetTxOrThrow(), why))
                accepted++;
        });
    }
    for (auto& th : threads)
        th.join();
    EXPECT_EQ(accepted.load(), 4);
    EXPECT_EQ(zcl_c23_proving_keys_loads(), loads0 + (BootMode() ? 0u : 1u));
    EXPECT_STREQ(zcl_c23_proving_status(), "resident");
    librustzcash_sapling_proving_ctx_free(held);
    EXPECT_STREQ(zcl_c23_proving_status(), BootMode() ? "resident" : "registered");

    RegtestDeactivateSapling();
}

TEST(C23ParamsResidency, SproutReadyOnTheGoodFileAndJoinSplitProves)
{
    char err[256] = {0};
    EXPECT_TRUE(zcl_c23_sprout_params_ready(err, sizeof(err))) << err;
    EXPECT_TRUE(zcl_c23_sprout_params_ready(err, sizeof(err))) << err; // cached by stamp

    auto recipient = libzcash::SproutSpendingKey::random().address();
    SproutMerkleTree tree;
    uint256 pubKey = random_uint256();
    std::array<JSInput, 2> inputs = {JSInput(), JSInput()};
    std::array<JSOutput, 2> outputs = {JSOutput(recipient, 10), JSOutput()};
    JSDescription js(true, *params, pubKey, tree.root(), inputs, outputs, 10, 0);
    auto verifier = libzcash::ProofVerifier::Strict();
    EXPECT_TRUE(js.Verify(*params, verifier, pubKey));
}

#ifndef WIN32
namespace {

// A fresh temporary directory, removed with everything in it at scope exit.
struct TempParamsDir {
    fs::path dir;
    TempParamsDir()
    {
        dir = fs::temp_directory_path() / fs::unique_path("zcl-params-%%%%-%%%%-%%%%");
        fs::create_directories(dir);
    }
    ~TempParamsDir()
    {
        boost::system::error_code ec;
        fs::remove_all(dir, ec);
    }
    fs::path operator/(const char* name) const { return dir / name; }
};

// A file of the Sprout parameter size holding zeros (sparse: no disk used):
// the right size, the wrong digest.
void MakeWrongSprout(const fs::path& p, uint64_t size)
{
    int fd = open(p.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(ftruncate(fd, (off_t)size), 0);
    close(fd);
}

// The real file, read only, under the expected name in dir.
void LinkReal(const TempParamsDir& d, const char* name)
{
    fs::create_symlink(ZC_GetParamsDir() / name, d / name);
}

// Flips one byte in the middle of the file and restores its modification and
// access times, so only the content (and the change time) differs.
bool FlipByteKeepTimes(const fs::path& p)
{
    struct stat st;
    if (stat(p.string().c_str(), &st) != 0)
        return false;
    int fd = open(p.string().c_str(), O_RDWR);
    if (fd < 0)
        return false;
    unsigned char b = 0;
    off_t at = st.st_size / 2;
    bool ok = pread(fd, &b, 1, at) == 1;
    b ^= 0x01;
    ok = ok && pwrite(fd, &b, 1, at) == 1;
    close(fd);
    struct timespec times[2];
#ifdef __APPLE__
    times[0] = st.st_atimespec;
    times[1] = st.st_mtimespec;
#else
    times[0] = st.st_atim;
    times[1] = st.st_mtim;
#endif
    return ok && utimensat(AT_FDCWD, p.string().c_str(), times, 0) == 0;
}

void FailChild(const std::string& why)
{
    fprintf(stderr, "child check failed: %s\n", why.c_str());
    fflush(stderr);
    _exit(1);
}

// Child of SaplingFileChangedAfterInitRefusesTheProof.
void SaplingChangeChild(const TempParamsDir& d)
{
    unsetenv("ZCL_PARAMS_VERIFY");
    InitParams(d.dir);
    // A boot-mode parent leaves its key set behind (a second init leaks it);
    // the lazy init itself adds nothing.
    const size_t resident = zcl_c23_params_bytes_resident();
    if (std::string(zcl_c23_proving_status()) != "registered")
        FailChild("status after a lazy init is not registered");
    auto cp = RegtestActivateSapling();
    std::string reason;
    auto good = BuildSpendTx(cp);
    if (!good.IsTx() || !ConsensusAccepts(good.GetTxOrThrow(), reason))
        FailChild("send on the unchanged copy failed: " + reason);
    if (!FlipByteKeepTimes(d / "sapling-output.params"))
        FailChild("could not change the copy");
    const unsigned loads = zcl_c23_proving_keys_loads();
    auto bad = BuildSpendTx(cp);
    if (bad.IsTx())
        FailChild("a send proved from a changed output parameter file");
    std::array<unsigned char, GROTH_PROOF_SIZE> proof;
    if (DirectOutputProof(proof) || !AllZero(proof))
        FailChild("output_proof did not return false with no proof bytes");
    if (zcl_c23_proving_keys_loads() != loads || zcl_c23_proving_keys_parsed())
        FailChild("keys were loaded from the changed file");
    if (zcl_c23_params_bytes_resident() != resident)
        FailChild("raw bytes left resident after a refused load");
    _exit(0);
}

// Child of SproutWrongFileIsCaughtBeforeTheFirstProofInLazyMode.
void SproutLazyChild(const TempParamsDir& d)
{
    unsetenv("ZCL_PARAMS_VERIFY");
    InitParams(d.dir); // only the size of the Sprout file is checked here
    char err[256] = {0};
    if (zcl_c23_sprout_params_ready(err, sizeof(err)))
        FailChild("ready accepted a Sprout file with the wrong digest");
    if (std::string(err).find("Sprout proving parameters") == std::string::npos)
        FailChild(std::string("unexpected message: ") + err);
    _exit(0);
}

// A Sprout JoinSplit proof on whatever parameters are initialised.
void MakeSproutProof()
{
    auto recipient = libzcash::SproutSpendingKey::random().address();
    SproutMerkleTree tree;
    uint256 pubKey = random_uint256();
    std::array<JSInput, 2> inputs = {JSInput(), JSInput()};
    std::array<JSOutput, 2> outputs = {JSOutput(recipient, 10), JSOutput()};
    JSDescription js(true, *params, pubKey, tree.root(), inputs, outputs, 10, 0);
}

} // namespace

TEST(C23ParamsResidency, SaplingFileChangedAfterInitRefusesTheProof)
{
    TempParamsDir d;
    fs::copy_file(ZC_GetParamsDir() / "sapling-spend.params", d / "sapling-spend.params");
    fs::copy_file(ZC_GetParamsDir() / "sapling-output.params", d / "sapling-output.params");
    LinkReal(d, "sprout-groth16.params");
    EXPECT_EXIT(SaplingChangeChild(d), ::testing::ExitedWithCode(0), "");

    // A fresh init on a changed copy still aborts (the Sapling pair is hashed
    // at init in lazy mode too).
    fs::remove(d / "sapling-output.params");
    fs::copy_file(ZC_GetParamsDir() / "sapling-output.params", d / "sapling-output.params");
    ASSERT_TRUE(FlipByteKeepTimes(d / "sapling-output.params"));
    EXPECT_DEATH({
        unsetenv("ZCL_PARAMS_VERIFY");
        InitParams(d.dir);
    }, "Sapling output parameter file is not correct");
}

TEST(C23ParamsResidency, SproutWrongFileIsCaughtBeforeTheFirstProofInLazyMode)
{
    TempParamsDir d;
    LinkReal(d, "sapling-spend.params");
    LinkReal(d, "sapling-output.params");
    MakeWrongSprout(d / "sprout-groth16.params", SPROUT_SIZE);
    EXPECT_EXIT(SproutLazyChild(d), ::testing::ExitedWithCode(0), "");

    // A Sprout proof on it never gets made: librustzcash_sprout_prove has no
    // failure value, so it stops the process with the same advice as init.
    EXPECT_DEATH({
        unsetenv("ZCL_PARAMS_VERIFY");
        InitParams(d.dir);
        MakeSproutProof();
    }, "refusing to create a Sprout proof");

    // ZCL_PARAMS_VERIFY=boot hashes it at init and aborts with the golden
    // message, as before.
    EXPECT_DEATH({
        setenv("ZCL_PARAMS_VERIFY", "boot", 1);
        InitParams(d.dir);
    }, "Sprout groth16 parameter file is not correct");
}

TEST(C23ParamsResidency, SproutFileOfTheWrongSizeAbortsAtInitInLazyMode)
{
    TempParamsDir d;
    LinkReal(d, "sapling-spend.params");
    LinkReal(d, "sapling-output.params");
    MakeWrongSprout(d / "sprout-groth16.params", SPROUT_SIZE - 1);
    EXPECT_DEATH({
        unsetenv("ZCL_PARAMS_VERIFY");
        InitParams(d.dir);
    }, "Sprout groth16 parameter file is not correct");
    fs::remove(d / "sprout-groth16.params");
    EXPECT_DEATH({
        unsetenv("ZCL_PARAMS_VERIFY");
        InitParams(d.dir);
    }, "couldn't load Sprout groth16 parameters file");
}
#endif // WIN32
