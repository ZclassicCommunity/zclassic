// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// gen_golden: record the behaviour of the real Rust librustzcash
// (depends/packages/librustzcash.mk, commit 06da3b9ac8f2) for every
// librustzcash_* function zclassicd calls, as line-oriented hex goldens that
// a C-only test can replay after Rust is removed.
//
// Format: src/test/data/c23_golden/FORMAT.md. Regeneration:
// src/test/rust_oracle/README.md.
//
// Every call whose inputs are not known-valid runs in a forked child, because
// librustzcash is built with panic=abort: a panic kills the process, and the
// golden then records the verdict ABORT.
//
// Inputs that are pseudo-random come from a fixed-seed ChaCha20 stream
// (libsodium randombytes_buf_deterministic), so a rerun records the same inputs.
// Outputs of functions that draw from the OS RNG inside Rust (generate_r,
// spend_sig, binding_sig, proofs) differ between runs; their records carry
// the inputs and Rust's verification verdicts, not byte-exact expectations.

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <gmpxx.h>
#include <sodium.h>

#include "librustzcash.h"

typedef std::vector<uint8_t> B;

// ---------------------------------------------------------------------------
// Basic helpers

static void die(const char* fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void die(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "gen_golden: FATAL: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(2);
}

static void note(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
static void note(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "gen_golden: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static std::string hx(const uint8_t* p, size_t n)
{
    static const char* d = "0123456789abcdef";
    if (n == 0) return "~";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) {
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 15]);
    }
    return s;
}
static std::string hx(const B& b) { return hx(b.data(), b.size()); }

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static B unhex(const std::string& s)
{
    if (s.size() % 2) die("odd-length hex (%zu)", s.size());
    B b(s.size() / 2);
    for (size_t i = 0; i < b.size(); i++) {
        int h = hexval(s[2 * i]), l = hexval(s[2 * i + 1]);
        if (h < 0 || l < 0) die("bad hex digit at %zu", 2 * i);
        b[i] = (uint8_t)(h * 16 + l);
    }
    return b;
}

static B rev(B b)
{
    for (size_t i = 0; i < b.size() / 2; i++) std::swap(b[i], b[b.size() - 1 - i]);
    return b;
}

static B cat(const B& a, const B& b)
{
    B r = a;
    r.insert(r.end(), b.begin(), b.end());
    return r;
}

static B sub(const B& b, size_t off, size_t n)
{
    if (off + n > b.size()) die("sub out of range (%zu+%zu>%zu)", off, n, b.size());
    return B(b.begin() + off, b.begin() + off + n);
}

static B le64(uint64_t v)
{
    B b(8);
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * i));
    return b;
}

static std::string u64s(uint64_t v)
{
    char buf[32];
    snprintf(buf, sizeof buf, "%llu", (unsigned long long)v);
    return buf;
}
static std::string i64s(int64_t v)
{
    char buf[32];
    snprintf(buf, sizeof buf, "%lld", (long long)v);
    return buf;
}

static std::string read_file(const std::string& path)
{
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) die("cannot open %s: %s", path.c_str(), strerror(errno));
    std::string s;
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) s.append(buf, n);
    if (ferror(f)) die("read error on %s", path.c_str());
    fclose(f);
    return s;
}

// ---------------------------------------------------------------------------
// Deterministic pseudo-random stream: seed_i = BLAKE2b-256(key="u5-rust-golden-v1",
// master || LE64(i)), block_i = randombytes_buf_deterministic(n, seed_i) (ChaCha20).

struct DRng {
    uint8_t master[32];
    uint64_t ctr;
    explicit DRng(const std::string& tag) : ctr(0)
    {
        static const char key[] = "u5-rust-golden-v1";
        if (crypto_generichash(master, 32, (const uint8_t*)tag.data(), tag.size(),
                               (const uint8_t*)key, sizeof key - 1) != 0)
            die("blake2b failed");
    }
    void fill(uint8_t* p, size_t n)
    {
        uint8_t in[40], seed[32];
        memcpy(in, master, 32);
        for (int i = 0; i < 8; i++) in[32 + i] = (uint8_t)(ctr >> (8 * i));
        ctr++;
        if (crypto_generichash(seed, 32, in, sizeof in, NULL, 0) != 0) die("blake2b failed");
        randombytes_buf_deterministic(p, n, seed);
    }
    B bytes(size_t n)
    {
        B b(n);
        if (n) fill(b.data(), n);
        return b;
    }
    uint64_t u64()
    {
        uint8_t b[8];
        fill(b, 8);
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v |= (uint64_t)b[i] << (8 * i);
        return v;
    }
    uint64_t below(uint64_t n) { return n ? u64() % n : 0; }
};

// ---------------------------------------------------------------------------
// Field and curve arithmetic with GMP, used only to construct inputs
// (canonical scalars, torsion points, off-curve encodings) independently of
// Rust. Rust's verdicts are what the goldens record.

static mpz_class Q;   // BLS12-381 scalar field = Jubjub base field
static mpz_class RJ;  // Jubjub prime subgroup order
static mpz_class JD;  // Jubjub d
static mpz_class P;   // BLS12-381 base field
static mpz_class TWO256, TWO255;

static mpz_class md(const mpz_class& a, const mpz_class& m)
{
    mpz_class r;
    mpz_mod(r.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t());
    return r;
}
static mpz_class invm(const mpz_class& a, const mpz_class& m)
{
    mpz_class r, t = md(a, m);
    if (!mpz_invert(r.get_mpz_t(), t.get_mpz_t(), m.get_mpz_t())) die("no inverse");
    return r;
}
static mpz_class powm(const mpz_class& b, const mpz_class& e, const mpz_class& m)
{
    mpz_class r, t = md(b, m);
    mpz_powm(r.get_mpz_t(), t.get_mpz_t(), e.get_mpz_t(), m.get_mpz_t());
    return r;
}
static int legendre(const mpz_class& a, const mpz_class& p)
{
    mpz_class t = md(a, p);
    return mpz_legendre(t.get_mpz_t(), p.get_mpz_t());
}
static mpz_class le2z(const uint8_t* b, size_t n)
{
    mpz_class z;
    mpz_import(z.get_mpz_t(), n, -1, 1, 0, 0, b);
    return z;
}
static mpz_class le2z(const B& b) { return le2z(b.data(), b.size()); }
static B z2le(const mpz_class& z, size_t n)
{
    if (sgn(z) < 0 || mpz_sizeinbase(z.get_mpz_t(), 2) > 8 * n) die("z2le overflow");
    B b(n, 0);
    size_t cnt = 0;
    if (z != 0) mpz_export(b.data(), &cnt, -1, 1, 0, 0, z.get_mpz_t());
    return b;
}
static B z2be(const mpz_class& z, size_t n) { return rev(z2le(z, n)); }

static bool sqrtm(const mpz_class& ain, const mpz_class& p, mpz_class& out)
{
    mpz_class a = md(ain, p);
    if (a == 0) {
        out = 0;
        return true;
    }
    if (legendre(a, p) != 1) return false;
    mpz_class qq = p - 1;
    unsigned long s = 0;
    while (mpz_even_p(qq.get_mpz_t())) {
        qq >>= 1;
        s++;
    }
    mpz_class z = 2;
    while (legendre(z, p) != -1) z += 1;
    unsigned long M = s;
    mpz_class c = powm(z, qq, p), t = powm(a, qq, p), R = powm(a, (qq + 1) / 2, p);
    while (t != 1) {
        unsigned long i = 0;
        mpz_class tt = t;
        while (tt != 1) {
            tt = md(tt * tt, p);
            if (++i == M) return false;
        }
        mpz_class b = c;
        for (unsigned long j = 0; j + 1 < M - i; j++) b = md(b * b, p);
        M = i;
        c = md(b * b, p);
        t = md(t * c, p);
        R = md(R * b, p);
    }
    out = R;
    return true;
}

struct JP {
    mpz_class x, y;
};
static JP jid()
{
    JP p;
    p.x = 0;
    p.y = 1;
    return p;
}
static bool jeq(const JP& a, const JP& b) { return a.x == b.x && a.y == b.y; }
static JP jadd(const JP& a, const JP& b)
{
    // -x^2 + y^2 = 1 + d x^2 y^2 (complete twisted Edwards addition, a = -1)
    mpz_class x1x2 = md(a.x * b.x, Q), y1y2 = md(a.y * b.y, Q);
    mpz_class t = md(md(JD * x1x2, Q) * y1y2, Q);
    JP r;
    r.x = md(md(a.x * b.y + a.y * b.x, Q) * invm(1 + t, Q), Q);
    r.y = md(md(y1y2 + x1x2, Q) * invm(md(1 - t, Q), Q), Q);
    return r;
}
static JP jmul(const mpz_class& k, const JP& p)
{
    JP r = jid(), b = p;
    size_t bits = mpz_sizeinbase(k.get_mpz_t(), 2);
    for (size_t i = 0; i < bits; i++) {
        if (mpz_tstbit(k.get_mpz_t(), i)) r = jadd(r, b);
        b = jadd(b, b);
    }
    return r;
}
static B jenc(const JP& p)
{
    B b = z2le(p.y, 32);
    if (mpz_odd_p(p.x.get_mpz_t())) b[31] |= 0x80;
    return b;
}
// Same acceptance rule as sapling-crypto edwards::Point::read (y < q, square
// root exists, sign fixes x; x = 0 with sign 1 accepted).
static bool jdec(const uint8_t* in, JP& out)
{
    uint8_t t[32];
    memcpy(t, in, 32);
    bool sign = (t[31] >> 7) != 0;
    t[31] &= 0x7f;
    mpz_class y = le2z(t, 32);
    if (y >= Q) return false;
    mpz_class y2 = md(y * y, Q);
    mpz_class x2 = md((y2 - 1) * invm(md(JD * y2 + 1, Q), Q), Q);
    mpz_class x;
    if (!sqrtm(x2, Q, x)) return false;
    if ((mpz_odd_p(x.get_mpz_t()) != 0) != sign) x = md(-x, Q);
    out.x = x;
    out.y = y;
    return true;
}
static bool jdec(const B& b, JP& out) { return b.size() == 32 && jdec(b.data(), out); }
static bool jprime(const JP& p) { return jeq(jmul(RJ, p), jid()); }

static JP TOR[8];        // the 8-torsion subgroup, TOR[k] = [k]T8
static B OFFCURVE_ENC;   // a y < q with no x on the curve
static B G1_OFFCURVE, G1_NONSUB, G2_OFFCURVE, G2_NONSUB;

// Weierstrass affine arithmetic on BLS12-381 G1 (y^2 = x^3 + 4) for the subgroup test.
struct WP {
    mpz_class x, y;
    bool inf;
};
static WP wadd(const WP& a, const WP& b)
{
    if (a.inf) return b;
    if (b.inf) return a;
    mpz_class lam;
    if (a.x == b.x) {
        if (md(a.y + b.y, P) == 0) return WP{0, 0, true};
        lam = md(3 * a.x * a.x * invm(2 * a.y, P), P);
    } else {
        lam = md((b.y - a.y) * invm(b.x - a.x, P), P);
    }
    WP r;
    r.inf = false;
    r.x = md(lam * lam - a.x - b.x, P);
    r.y = md(lam * (a.x - r.x) - a.y, P);
    return r;
}
static WP wmul(const mpz_class& k, const WP& p)
{
    WP r{0, 0, true}, b = p;
    size_t bits = mpz_sizeinbase(k.get_mpz_t(), 2);
    for (size_t i = 0; i < bits; i++) {
        if (mpz_tstbit(k.get_mpz_t(), i)) r = wadd(r, b);
        b = wadd(b, b);
    }
    return r;
}

static void init_math()
{
    Q = mpz_class("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    RJ = mpz_class("0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7", 16);
    P = mpz_class("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);
    JD = md(-mpz_class(10240) * invm(10241, Q), Q);
    TWO256 = mpz_class(1) << 256;
    TWO255 = mpz_class(1) << 255;

    // 8-torsion generator: [r]P for points P until one has order exactly 8.
    bool found = false;
    for (unsigned long y = 2; y < 10000 && !found; y++) {
        JP p;
        B e = z2le(mpz_class(y), 32);
        if (!jdec(e, p)) continue;
        JP t = jmul(RJ, p);
        if (!jeq(jmul(4, t), jid())) {
            if (!jeq(jmul(8, t), jid())) die("torsion point has order > 8: d or r wrong");
            for (int k = 0; k < 8; k++) TOR[k] = jmul(k, t);
            found = true;
        }
    }
    if (!found) die("no order-8 point found");
    for (unsigned long y = 2;; y++) {
        mpz_class yy = y, y2 = md(yy * yy, Q);
        mpz_class x2 = md((y2 - 1) * invm(md(JD * y2 + 1, Q), Q), Q);
        if (legendre(x2, Q) == -1) {
            OFFCURVE_ENC = z2le(yy, 32);
            break;
        }
    }

    DRng rng("bls12-381-encodings");
    // G1: off-curve x and an on-curve point outside the prime-order subgroup.
    bool off = false, non = false;
    while (!off || !non) {
        mpz_class x = md(le2z(rng.bytes(64)), P);
        mpz_class rhs = md(x * x * x + 4, P);
        int l = legendre(rhs, P);
        B e = z2be(x, 48);
        if (e[0] & 0xe0) continue;
        if (l == -1 && !off) {
            G1_OFFCURVE = e;
            G1_OFFCURVE[0] |= 0x80;
            off = true;
        } else if (l == 1 && !non) {
            WP pt{x, powm(rhs, (P + 1) / 4, P), false};
            if (md(pt.y * pt.y, P) != rhs) die("G1 sqrt failed");
            if (wmul(Q, pt).inf) continue;  // in the subgroup (probability ~2^-126)
            G1_NONSUB = e;
            G1_NONSUB[0] |= 0x80;
            non = true;
        }
    }
    // G2 (y^2 = x^3 + 4(1+i)): square test in Fp2 by the norm. A random on-curve
    // point lies in the order-r subgroup with probability below 2^-380; not re-checked.
    off = non = false;
    while (!off || !non) {
        mpz_class c0 = md(le2z(rng.bytes(64)), P), c1 = md(le2z(rng.bytes(64)), P);
        mpz_class s0 = md(c0 * c0 - c1 * c1, P), s1 = md(2 * c0 * c1, P);
        mpz_class t0 = md(s0 * c0 - s1 * c1, P), t1 = md(s0 * c1 + s1 * c0, P);
        t0 = md(t0 + 4, P);
        t1 = md(t1 + 4, P);
        mpz_class norm = md(t0 * t0 + t1 * t1, P);
        int l = legendre(norm, P);
        B e = cat(z2be(c1, 48), z2be(c0, 48));
        if (e[0] & 0xe0) continue;
        e[0] |= 0x80;
        if (l == -1 && !off) {
            G2_OFFCURVE = e;
            off = true;
        } else if (l == 1 && !non) {
            G2_NONSUB = e;
            non = true;
        }
    }
}

static B rand_fs(DRng& r) { return z2le(md(le2z(r.bytes(64)), RJ), 32); }  // canonical < r
static B rand_fr(DRng& r) { return z2le(md(le2z(r.bytes(64)), Q), 32); }   // canonical < q

// ---------------------------------------------------------------------------
// Isolation: run fn(fd) in a forked child. A Rust panic aborts the child.

struct Iso {
    bool died;
    int sig;
    std::string out, err;
};

static void write_all(int fd, const char* p, size_t n)
{
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            _exit(3);
        }
        p += w;
        n -= (size_t)w;
    }
}
static void emit(int fd, const std::string& s) { write_all(fd, s.data(), s.size()); }

static unsigned long g_forks = 0;

static Iso isolate(const std::function<void(int)>& fn)
{
    fflush(stdout);
    fflush(stderr);
    int po[2], pe[2];
    if (pipe(po) != 0 || pipe(pe) != 0) die("pipe: %s", strerror(errno));
    pid_t pid = fork();
    if (pid < 0) die("fork: %s", strerror(errno));
    if (pid == 0) {
        close(po[0]);
        close(pe[0]);
        if (dup2(pe[1], 2) < 0) _exit(4);
        fn(po[1]);
        _exit(0);
    }
    g_forks++;
    close(po[1]);
    close(pe[1]);
    Iso r;
    r.died = false;
    r.sig = 0;
    struct pollfd fds[2] = {{po[0], POLLIN, 0}, {pe[0], POLLIN, 0}};
    int open_fds = 2;
    char buf[65536];
    while (open_fds > 0) {
        if (poll(fds, 2, -1) < 0) {
            if (errno == EINTR) continue;
            die("poll: %s", strerror(errno));
        }
        for (int i = 0; i < 2; i++) {
            if (fds[i].fd < 0 || !(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            ssize_t n = read(fds[i].fd, buf, sizeof buf);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) {
                close(fds[i].fd);
                fds[i].fd = -1;
                open_fds--;
                continue;
            }
            (i == 0 ? r.out : r.err).append(buf, (size_t)n);
        }
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR) die("waitpid: %s", strerror(errno));
    }
    if (WIFSIGNALED(st)) {
        r.died = true;
        r.sig = WTERMSIG(st);
    } else if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        die("child harness failure (status %d), stderr: %s", st, r.err.c_str());
    }
    return r;
}

static std::string first_line(const std::string& s)
{
    std::string l = s.substr(0, s.find('\n'));
    for (auto& c : l)
        if (c == '\r' || c == '\t') c = ' ';
    if (l.size() > 300) l = l.substr(0, 300);
    return l;
}

static std::vector<std::string> split_lines(const std::string& s)
{
    std::vector<std::string> v;
    size_t a = 0;
    while (a < s.size()) {
        size_t b = s.find('\n', a);
        if (b == std::string::npos) b = s.size();
        v.push_back(s.substr(a, b - a));
        a = b + 1;
    }
    return v;
}
static std::vector<std::string> split_ws(const std::string& s)
{
    std::vector<std::string> v;
    size_t a = 0;
    while (a < s.size()) {
        while (a < s.size() && s[a] == ' ') a++;
        size_t b = s.find(' ', a);
        if (b == std::string::npos) b = s.size();
        if (b > a) v.push_back(s.substr(a, b - a));
        a = b;
    }
    return v;
}

// ---------------------------------------------------------------------------
// Golden writer

static std::string g_out_dir;
static bool g_quick = false;

struct Golden {
    std::string file;
    FILE* f;
    unsigned n, nT, nF, nOK, nAB;
    Golden(const std::string& name, const std::string& fn, const std::string& in_cols,
           const std::string& out_cols, const std::string& comment)
        : file(name), n(0), nT(0), nF(0), nOK(0), nAB(0)
    {
        std::string path = g_out_dir + "/" + name;
        f = fopen(path.c_str(), "wb");
        if (!f) die("cannot create %s: %s", path.c_str(), strerror(errno));
        fprintf(f, "# c23_golden v1. Format: FORMAT.md. Generated by src/test/rust_oracle/gen_golden.cpp\n");
        fprintf(f, "# from librustzcash 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5 (panic=abort).\n");
        if (!comment.empty()) {
            for (auto& l : split_lines(comment)) fprintf(f, "# %s\n", l.c_str());
        }
        fprintf(f, "@fn %s\n", fn.c_str());
        if (!in_cols.empty()) fprintf(f, "@in %s\n", in_cols.c_str());
        if (!out_cols.empty()) fprintf(f, "@out %s\n", out_cols.c_str());
    }
    ~Golden() { close(); }
    void close()
    {
        if (f) {
            if (fclose(f) != 0) die("close %s failed", file.c_str());
            f = nullptr;
        }
    }
    void tally(const std::string& v)
    {
        if (v == "T") nT++;
        else if (v == "F") nF++;
        else if (v == "OK") nOK++;
        else if (v == "ABORT") nAB++;
        else if (v != "-") die("bad verdict token '%s' in %s", v.c_str(), file.c_str());
    }
    void line(const std::string& s)
    {
        if (fputs(s.c_str(), f) < 0 || fputc('\n', f) < 0) die("write %s failed", file.c_str());
    }
    void comment(const std::string& s) { line("# " + s); }
    // A single-call record. res = "<verdict> <outputs...>".
    void rec(const std::string& label, const std::string& ins, const std::string& res)
    {
        n++;
        auto toks = split_ws(res);
        if (toks.empty()) die("empty result in %s", file.c_str());
        tally(toks[0]);
        line("C " + std::to_string(n) + " " + label + (ins.empty() ? "" : " " + ins) + " " + res);
    }
};

struct Summary {
    std::string file;
    unsigned n, nT, nF, nOK, nAB;
};
static std::vector<Summary> g_summary;
static void finish(Golden& g)
{
    g.close();
    g_summary.push_back(Summary{g.file, g.n, g.nT, g.nF, g.nOK, g.nAB});
    note("%-44s %6u records (T %u, F %u, OK %u, ABORT %u)", g.file.c_str(), g.n, g.nT, g.nF, g.nOK, g.nAB);
}

static std::string dashes(size_t n)
{
    std::string s;
    for (size_t i = 0; i < n; i++) s += " -";
    return s;
}

// Run one call in a child. body returns "<verdict> <outputs...>". If the child
// dies, the record gets ABORT with nout "-" placeholders, preceded by a comment.
static void single(Golden& g, const std::string& label, const std::string& ins, size_t nout,
                   const std::function<std::string()>& body)
{
    Iso r = isolate([&](int fd) { emit(fd, body()); });
    if (r.died) {
        g.comment("abort signal " + std::to_string(r.sig) + ": " + first_line(r.err));
        g.rec(label, ins, "ABORT" + dashes(nout));
    } else {
        if (r.out.empty()) die("empty child output for %s %s", g.file.c_str(), label.c_str());
        g.rec(label, ins, r.out);
    }
}

static const char* TF(bool b) { return b ? "T" : "F"; }

// ---------------------------------------------------------------------------
// Mutation sets

typedef std::vector<std::pair<std::string, B>> Muts;

static Muts point_mutations(const B& enc)
{
    Muts m;
    JP p;
    bool ok = jdec(enc, p);
    B t = enc;
    t[31] ^= 0x80;
    m.push_back({"signflip", t});
    if (ok) {
        mpz_class y = p.y + Q;
        if (y < TWO255) {
            B e = z2le(y, 32);
            e[31] |= (enc[31] & 0x80);
            m.push_back({"y+q", e});
        }
    }
    m.push_back({"y=q", z2le(Q, 32)});
    B e = z2le(Q, 32);
    e[31] |= 0x80;
    m.push_back({"y=q:s1", e});
    e = B(32, 0xff);
    e[31] = 0x7f;
    m.push_back({"y=2^255-1", e});
    m.push_back({"offcurve", OFFCURVE_ENC});
    e = z2le(1, 32);
    e[31] |= 0x80;
    m.push_back({"x0s1:id", e});
    e = z2le(Q - 1, 32);
    e[31] |= 0x80;
    m.push_back({"x0s1:m1", e});
    for (int k = 0; k < 8; k++) m.push_back({"tor" + std::to_string(k), jenc(TOR[k])});
    if (ok) {
        for (int k = 1; k < 8; k++) m.push_back({"mix" + std::to_string(k), jenc(jadd(p, TOR[k]))});
    }
    return m;
}

static Muts fs_mutations(const B& s)
{
    Muts m;
    m.push_back({"=r", z2le(RJ, 32)});
    m.push_back({"=r+1", z2le(RJ + 1, 32)});
    m.push_back({"=r-1", z2le(RJ - 1, 32)});
    mpz_class v = le2z(s) + RJ;
    if (v < TWO256) m.push_back({"+r", z2le(v, 32)});
    m.push_back({"=max", B(32, 0xff)});
    m.push_back({"=0", B(32, 0)});
    return m;
}

static Muts fr_mutations(const B& s)
{
    Muts m;
    m.push_back({"=q", z2le(Q, 32)});
    m.push_back({"=q+1", z2le(Q + 1, 32)});
    m.push_back({"=q-1", z2le(Q - 1, 32)});
    mpz_class v = le2z(s) + Q;
    if (v < TWO256) m.push_back({"+q", z2le(v, 32)});
    m.push_back({"=max", B(32, 0xff)});
    B t = s;
    t[31] |= 0x80;
    m.push_back({"bit255", t});
    return m;
}

static Muts proof_mutations(const B& pr)
{
    Muts m;
    struct Slot {
        const char* n;
        size_t off, len;
        bool g2;
    } slots[3] = {{"A", 0, 48, false}, {"B", 48, 96, true}, {"C", 144, 48, false}};
    for (auto& sl : slots) {
        B orig = sub(pr, sl.off, sl.len);
        auto put = [&](const std::string& name, const B& v) {
            B x = pr;
            std::copy(v.begin(), v.end(), x.begin() + sl.off);
            m.push_back({std::string(sl.n) + ":" + name, x});
        };
        B s(sl.len, 0);
        s[0] = 0xc0;
        put("inf_clean", s);
        B s2 = s;
        s2[sl.len - 1] = 1;
        put("inf_dirty_tail", s2);
        s2 = orig;
        s2[0] |= 0x40;
        put("inf_dirty_keepx", s2);
        s2 = B(sl.len, 0);
        s2[0] = 0xe0;
        put("inf_sortbit", s2);
        s2 = B(sl.len, 0);
        s2[0] = 0x40;
        put("inf_nocomp", s2);
        s2 = orig;
        s2[0] &= 0x7f;
        put("nocomp", s2);
        s2 = orig;
        s2[0] ^= 0x20;
        put("sortflip", s2);
        s2 = orig;
        {
            B pe = z2be(P, 48);
            pe[0] |= (uint8_t)(orig[0] & 0xa0);
            std::copy(pe.begin(), pe.end(), s2.begin());
        }
        put("x=p", s2);
        s2 = B(sl.len, 0xff);
        s2[0] = 0x9f;
        put("x_allones", s2);
        put("offcurve", sl.g2 ? G2_OFFCURVE : G1_OFFCURVE);
        put("nonsubgroup", sl.g2 ? G2_NONSUB : G1_NONSUB);
        put("zero", B(sl.len, 0));
    }
    B sw = pr;
    std::copy(pr.begin() + 144, pr.end(), sw.begin());
    std::copy(pr.begin(), pr.begin() + 48, sw.begin() + 144);
    m.push_back({"swapAC", sw});
    return m;
}

static Muts sig_mutations(const B& sig)
{
    Muts m;
    B R = sub(sig, 0, 32), S = sub(sig, 32, 32);
    for (auto& pm : point_mutations(R)) m.push_back({"R:" + pm.first, cat(pm.second, S)});
    mpz_class s = le2z(S);
    if (s + RJ < TWO256) m.push_back({"S:+r", cat(R, z2le(s + RJ, 32))});
    m.push_back({"S:=r", cat(R, z2le(RJ, 32))});
    m.push_back({"S:=r-1", cat(R, z2le(RJ - 1, 32))});
    m.push_back({"S:=max", cat(R, B(32, 0xff))});
    m.push_back({"S:=0", cat(R, B(32, 0))});
    return m;
}

// ---------------------------------------------------------------------------
// Rust-backed derivations used to build valid inputs (called in the parent only
// with inputs known valid; they never panic on such inputs).

static const unsigned char PERS_EXPAND[16] = {'Z','c','a','s','h','_','E','x','p','a','n','d','S','e','e','d'};

static B prf_expand(const B& sk, uint8_t t)
{
    B in = sk;
    in.push_back(t);
    B out(64);
    if (crypto_generichash_blake2b_salt_personal(out.data(), 64, in.data(), in.size(), NULL, 0, NULL,
                                                 PERS_EXPAND) != 0)
        die("blake2b failed");
    return out;
}

static B r_to_scalar(const B& in64)
{
    B o(32);
    librustzcash_to_scalar(in64.data(), o.data());
    return o;
}
static B r_ask_to_ak(const B& a)
{
    B o(32);
    librustzcash_ask_to_ak(a.data(), o.data());
    return o;
}
static B r_nsk_to_nk(const B& a)
{
    B o(32);
    librustzcash_nsk_to_nk(a.data(), o.data());
    return o;
}
static B r_crh_ivk(const B& ak, const B& nk)
{
    B o(32);
    librustzcash_crh_ivk(ak.data(), nk.data(), o.data());
    return o;
}

static B valid_d(DRng& r)
{
    for (;;) {
        B d = r.bytes(11);
        if (librustzcash_check_diversifier(d.data())) return d;
    }
}
static B invalid_d(DRng& r)
{
    for (;;) {
        B d = r.bytes(11);
        if (!librustzcash_check_diversifier(d.data())) return d;
    }
}

struct Keys {
    B sk, ask, nsk, ovk, ak, nk, ivk, d, pkd;
};
static Keys keys_from_sk(const B& sk, DRng& r)
{
    Keys k;
    k.sk = sk;
    k.ask = r_to_scalar(prf_expand(sk, 0));
    k.nsk = r_to_scalar(prf_expand(sk, 1));
    k.ovk = sub(prf_expand(sk, 2), 0, 32);
    k.ak = r_ask_to_ak(k.ask);
    k.nk = r_nsk_to_nk(k.nsk);
    k.ivk = r_crh_ivk(k.ak, k.nk);
    k.d = valid_d(r);
    k.pkd = B(32);
    if (!librustzcash_ivk_to_pkd(k.ivk.data(), k.d.data(), k.pkd.data())) die("ivk_to_pkd failed on valid d");
    return k;
}

static B r_merkle(size_t depth, const B& a, const B& b)
{
    B o(32);
    librustzcash_merkle_hash(depth, a.data(), b.data(), o.data());
    return o;
}

static B r_cm(const B& d, const B& pkd, uint64_t v, const B& rcm)
{
    B o(32);
    if (!librustzcash_sapling_compute_cm(d.data(), pkd.data(), v, rcm.data(), o.data())) die("compute_cm failed on valid note");
    return o;
}
static B r_nf(const B& d, const B& pkd, uint64_t v, const B& rcm, const B& ak, const B& nk, uint64_t pos)
{
    B o(32);
    if (!librustzcash_sapling_compute_nf(d.data(), pkd.data(), v, rcm.data(), ak.data(), nk.data(), pos, o.data()))
        die("compute_nf failed on valid note");
    return o;
}

// ---------------------------------------------------------------------------
// Minimal JSON scanning for the zclassicd test vector files.

static std::vector<std::vector<std::string>> json_rows(const std::string& s)
{
    std::vector<std::vector<std::string>> rows;
    int depth = 0;
    std::vector<std::string> cur;
    for (size_t i = 0; i < s.size(); i++) {
        char c = s[i];
        if (c == '[') {
            depth++;
            if (depth == 2) cur.clear();
        } else if (c == ']') {
            if (depth == 2) rows.push_back(cur);
            depth--;
        } else if (c == '"' && depth == 2) {
            size_t j = s.find('"', i + 1);
            if (j == std::string::npos) die("unterminated string");
            cur.push_back(s.substr(i + 1, j - i - 1));
            i = j;
        } else if (depth == 2 && (isdigit((unsigned char)c) || c == '-')) {
            size_t j = i;
            while (j < s.size() && (isdigit((unsigned char)s[j]) || s[j] == '-')) j++;
            cur.push_back(s.substr(i, j - i));
            i = j - 1;
        }
    }
    return rows;
}
static std::vector<std::string> json_strings(const std::string& s)
{
    std::vector<std::string> v;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '"') {
            size_t j = s.find('"', i + 1);
            if (j == std::string::npos) die("unterminated string");
            v.push_back(s.substr(i + 1, j - i - 1));
            i = j;
        }
    }
    return v;
}

// ---------------------------------------------------------------------------
// Sapling (v4) transaction parsing and ZIP-243 sighash for NOT_AN_INPUT/SIGHASH_ALL,
// mirroring src/script/interpreter.cpp SignatureHash.

struct SpendD {
    B cv, anchor, nf, rk, proof, sig;
};
struct OutD {
    B cv, cm, epk, enc, outc, proof;
};
struct JSD {
    uint64_t vpub_old, vpub_new;
    B anchor, nf1, nf2, cm1, cm2, epk, seed, mac1, mac2, proof;
};
struct Tx {
    int height;
    std::string txid;
    B raw;
    uint32_t header, vgid, lock, expiry;
    int64_t vb;
    B prevouts, sequences, outputs_ser, js_ser, spends_nosig, outputs_shielded;
    std::vector<SpendD> spends;
    std::vector<OutD> outs;
    std::vector<JSD> js;
    B jspk, jssig, bsig, sighash;
};

struct Cur {
    const B& b;
    size_t p;
    explicit Cur(const B& bb) : b(bb), p(0) {}
    B take(size_t n)
    {
        if (p + n > b.size()) die("tx truncated at %zu (+%zu)", p, n);
        B r(b.begin() + p, b.begin() + p + n);
        p += n;
        return r;
    }
    uint64_t le(size_t n)
    {
        B r = take(n);
        uint64_t v = 0;
        for (size_t i = 0; i < n; i++) v |= (uint64_t)r[i] << (8 * i);
        return v;
    }
    uint64_t cs()
    {
        uint8_t c = (uint8_t)le(1);
        if (c < 253) return c;
        if (c == 253) return le(2);
        if (c == 254) return le(4);
        return le(8);
    }
};

static B blake2b256_pers(const B& data, const char* pers16)
{
    B out(32);
    if (crypto_generichash_blake2b_salt_personal(out.data(), 32, data.data(), data.size(), NULL, 0, NULL,
                                                 (const unsigned char*)pers16) != 0)
        die("blake2b failed");
    return out;
}

static uint32_t branch_id_for_height(int h)
{
    // src/chainparams.cpp mainnet activations, src/consensus/upgrades.cpp branch ids.
    if (h >= 585322) return 0x930b540d;  // DiffAdj (Bubbly) and Buttercup share this id
    if (h >= 585318) return 0x821a451c;  // Bubbles
    if (h >= 476969) return 0x76b809bb;  // Sapling
    die("height %d predates Sapling", h);
}

static Tx parse_tx(int height, const std::string& txid, const B& raw)
{
    Tx t;
    t.height = height;
    t.txid = txid;
    t.raw = raw;
    // txid check: double SHA-256, displayed byte-reversed.
    uint8_t h1[32], h2[32];
    crypto_hash_sha256(h1, raw.data(), raw.size());
    crypto_hash_sha256(h2, h1, 32);
    if (hx(rev(B(h2, h2 + 32))) != txid) die("txid mismatch for %s", txid.c_str());
    Cur c(raw);
    t.header = (uint32_t)c.le(4);
    if (t.header != 0x80000004) die("tx %s is not v4 overwintered", txid.c_str());
    t.vgid = (uint32_t)c.le(4);
    if (t.vgid != 0x892f2085) die("tx %s not Sapling version group", txid.c_str());
    uint64_t nin = c.cs();
    for (uint64_t i = 0; i < nin; i++) {
        B po = c.take(36);
        t.prevouts.insert(t.prevouts.end(), po.begin(), po.end());
        c.take(c.cs());
        B sq = c.take(4);
        t.sequences.insert(t.sequences.end(), sq.begin(), sq.end());
    }
    uint64_t nout = c.cs();
    for (uint64_t i = 0; i < nout; i++) {
        size_t a = c.p;
        c.take(8);
        c.take(c.cs());
        t.outputs_ser.insert(t.outputs_ser.end(), raw.begin() + a, raw.begin() + c.p);
    }
    t.lock = (uint32_t)c.le(4);
    t.expiry = (uint32_t)c.le(4);
    t.vb = (int64_t)c.le(8);
    uint64_t ns = c.cs();
    for (uint64_t i = 0; i < ns; i++) {
        SpendD s;
        s.cv = c.take(32);
        s.anchor = c.take(32);
        s.nf = c.take(32);
        s.rk = c.take(32);
        s.proof = c.take(192);
        s.sig = c.take(64);
        B x = cat(cat(cat(cat(s.cv, s.anchor), s.nf), s.rk), s.proof);
        t.spends_nosig.insert(t.spends_nosig.end(), x.begin(), x.end());
        t.spends.push_back(s);
    }
    uint64_t no = c.cs();
    for (uint64_t i = 0; i < no; i++) {
        size_t a = c.p;
        OutD o;
        o.cv = c.take(32);
        o.cm = c.take(32);
        o.epk = c.take(32);
        o.enc = c.take(580);
        o.outc = c.take(80);
        o.proof = c.take(192);
        t.outputs_shielded.insert(t.outputs_shielded.end(), raw.begin() + a, raw.begin() + c.p);
        t.outs.push_back(o);
    }
    uint64_t nj = c.cs();
    for (uint64_t i = 0; i < nj; i++) {
        size_t a = c.p;
        JSD j;
        j.vpub_old = c.le(8);
        j.vpub_new = c.le(8);
        j.anchor = c.take(32);
        j.nf1 = c.take(32);
        j.nf2 = c.take(32);
        j.cm1 = c.take(32);
        j.cm2 = c.take(32);
        j.epk = c.take(32);
        j.seed = c.take(32);
        j.mac1 = c.take(32);
        j.mac2 = c.take(32);
        j.proof = c.take(192);
        c.take(601 * 2);
        t.js_ser.insert(t.js_ser.end(), raw.begin() + a, raw.begin() + c.p);
        t.js.push_back(j);
    }
    if (nj) {
        t.jspk = c.take(32);
        t.jssig = c.take(64);
    }
    if (ns + no) t.bsig = c.take(64);
    if (c.p != raw.size()) die("tx %s has %zu trailing bytes", txid.c_str(), raw.size() - c.p);

    B zero(32, 0);
    B msg;
    msg = sub(le64(t.header), 0, 4);
    msg = cat(msg, sub(le64(t.vgid), 0, 4));
    msg = cat(msg, blake2b256_pers(t.prevouts, "ZcashPrevoutHash"));
    msg = cat(msg, blake2b256_pers(t.sequences, "ZcashSequencHash"));
    msg = cat(msg, blake2b256_pers(t.outputs_ser, "ZcashOutputsHash"));
    msg = cat(msg, nj ? blake2b256_pers(cat(t.js_ser, t.jspk), "ZcashJSplitsHash") : zero);
    msg = cat(msg, ns ? blake2b256_pers(t.spends_nosig, "ZcashSSpendsHash") : zero);
    msg = cat(msg, no ? blake2b256_pers(t.outputs_shielded, "ZcashSOutputHash") : zero);
    msg = cat(msg, sub(le64(t.lock), 0, 4));
    msg = cat(msg, sub(le64(t.expiry), 0, 4));
    msg = cat(msg, le64((uint64_t)t.vb));
    msg = cat(msg, sub(le64(1), 0, 4));  // SIGHASH_ALL
    char pers[16];
    memcpy(pers, "ZcashSigHash", 12);
    uint32_t br = branch_id_for_height(height);
    for (int i = 0; i < 4; i++) pers[12 + i] = (char)(br >> (8 * i));
    t.sighash = blake2b256_pers(msg, pers);
    return t;
}

static std::vector<Tx> load_txs(const std::string& path)
{
    std::vector<Tx> v;
    for (auto& l : split_lines(read_file(path))) {
        if (l.empty() || l[0] == '#') continue;
        auto t = split_ws(l);
        if (t.size() != 3) die("bad tx line in %s", path.c_str());
        v.push_back(parse_tx(atoi(t[0].c_str()), t[1], unhex(t[2])));
    }
    return v;
}

// ---------------------------------------------------------------------------
// Sprout helpers (src/zcash/prf.cpp, src/zcash/Note.cpp) for the Groth16 JoinSplit.

static void sha256_compress(const uint8_t in[64], uint8_t out[32])
{
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t s[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)in[4 * i] << 24 | (uint32_t)in[4 * i + 1] << 16 | (uint32_t)in[4 * i + 2] << 8 | in[4 * i + 3];
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
#undef ROR
    s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e; s[5] += f; s[6] += g; s[7] += h;
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(s[i] >> 24);
        out[4 * i + 1] = (uint8_t)(s[i] >> 16);
        out[4 * i + 2] = (uint8_t)(s[i] >> 8);
        out[4 * i + 3] = (uint8_t)s[i];
    }
}
static B compress(const B& l, const B& r)
{
    B in = cat(l, r);
    B o(32);
    sha256_compress(in.data(), o.data());
    return o;
}
static B sprout_prf(bool a, bool b, bool c, bool d, const B& x, const B& y)
{
    B blob = cat(x, y);
    blob[0] &= 0x0f;
    blob[0] |= (uint8_t)((a ? 0x80 : 0) | (b ? 0x40 : 0) | (c ? 0x20 : 0) | (d ? 0x10 : 0));
    B o(32);
    sha256_compress(blob.data(), o.data());
    return o;
}
static B sprout_apk(const B& ask) { return sprout_prf(1, 1, 0, 0, ask, B(32, 0)); }
static B sprout_nf(const B& ask, const B& rho) { return sprout_prf(1, 1, 1, 0, ask, rho); }
static B sprout_mac(const B& ask, int i, const B& hsig) { return sprout_prf(0, i != 0, 0, 0, ask, hsig); }
static B sprout_rho(const B& phi, int i, const B& hsig) { return sprout_prf(0, i != 0, 1, 0, phi, hsig); }
static B sprout_cm(const B& apk, uint64_t v, const B& rho, const B& r)
{
    B in;
    in.push_back(0xb0);
    in = cat(cat(cat(cat(in, apk), le64(v)), rho), r);
    B o(32);
    crypto_hash_sha256(o.data(), in.data(), in.size());
    return o;
}
static B sprout_hsig(const B& seed, const B& nf1, const B& nf2, const B& jspk)
{
    return blake2b256_pers(cat(cat(cat(seed, nf1), nf2), jspk), "ZcashComputehSig");
}

// ---------------------------------------------------------------------------
// Bit-flip helpers

struct Field {
    std::string name;
    B* v;
};
// mode 1: flip every bit of every field; mode 2: one bit per byte (bit index byte % 8);
// mode 0: one deterministic random bit per field.
static void bitflips(const std::vector<Field>& fields, int mode, DRng& r,
                     const std::function<void(const std::string&)>& fn)
{
    for (auto& f : fields) {
        size_t nbits = f.v->size() * 8;
        if (mode == 2) {
            for (size_t by = 0; by < f.v->size(); by++) {
                size_t b = by * 8 + by % 8;
                (*f.v)[by] ^= (uint8_t)(1 << (by % 8));
                fn("flip:" + f.name + ":" + std::to_string(b));
                (*f.v)[by] ^= (uint8_t)(1 << (by % 8));
            }
        } else if (mode == 1) {
            for (size_t b = 0; b < nbits; b++) {
                (*f.v)[b / 8] ^= (uint8_t)(1 << (b % 8));
                fn("flip:" + f.name + ":" + std::to_string(b));
                (*f.v)[b / 8] ^= (uint8_t)(1 << (b % 8));
            }
        } else {
            size_t b = r.below(nbits);
            (*f.v)[b / 8] ^= (uint8_t)(1 << (b % 8));
            fn("flip:" + f.name + ":" + std::to_string(b));
            (*f.v)[b / 8] ^= (uint8_t)(1 << (b % 8));
        }
    }
}

// ---------------------------------------------------------------------------
// Global corpus state

static std::string g_src;     // zclassicd src/ directory
static std::string g_params;  // directory with the Zcash parameter files
static size_t NRAND = 2000;

static std::vector<std::vector<std::string>> g_keyrows;  // sapling_key_components.json rows
static std::vector<B> g_empty;                           // empty Sapling roots, depth 0..63

static const char* SPEND_HASH = "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";
static const char* OUTPUT_HASH = "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";
static const char* SPROUT_HASH = "e9b238411bd6c0ec4791e9d04245ec350c9c5744f5610dfcce4365d5ca49dfefd5054e371842b3f88fa1b9d7e8e075249b3ebabd167fa8b0f3161292d36c180a";

// Mixed scalar distribution: canonical, raw 256-bit, or edge.
static B mixed_fs(DRng& r, size_t i)
{
    switch (i % 8) {
    case 0: case 1: case 2: case 3: case 4: return rand_fs(r);
    case 5: case 6: return r.bytes(32);
    default: {
        static const char* edges[] = {"0", "1", "r-1", "r", "r+1", "max", "2^255", "2^252"};
        std::string e = edges[r.below(8)];
        if (e == "0") return B(32, 0);
        if (e == "1") return z2le(1, 32);
        if (e == "r-1") return z2le(RJ - 1, 32);
        if (e == "r") return z2le(RJ, 32);
        if (e == "r+1") return z2le(RJ + 1, 32);
        if (e == "max") return B(32, 0xff);
        if (e == "2^255") return z2le(TWO255, 32);
        return z2le(mpz_class(1) << 252, 32);
    }
    }
}

// Mixed Jubjub point encodings: valid prime-order, or a mutation of one, or raw bytes.
static B mixed_point(DRng& r, size_t i)
{
    B good = r_ask_to_ak(rand_fs(r));
    switch (i % 6) {
    case 0: case 1: case 2: return good;
    case 3: return r.bytes(32);
    default: {
        Muts m = point_mutations(good);
        return m[r.below(m.size())].second;
    }
    }
}

// ---------------------------------------------------------------------------
// Section 1: key, tree, note, KA and ZIP-32 functions (no parameters needed)

static void gen_to_scalar()
{
    Golden g("to_scalar.golden", "librustzcash_to_scalar", "input:hex64", "result:hex32",
             "void; verdict OK or ABORT. Fs::to_uniform (512-bit LE integer mod r).");
    for (size_t i = 0; i < g_keyrows.size(); i++) {
        B sk = rev(unhex(g_keyrows[i][0]));
        for (int t = 0; t < 2; t++) {
            B in = prf_expand(sk, (uint8_t)t);
            B want = rev(unhex(g_keyrows[i][1 + t]));
            if (r_to_scalar(in) != want) die("to_scalar key vector %zu/%d mismatch", i, t);
            single(g, "vec:keycomp:" + std::to_string(i) + (t ? ":nsk" : ":ask"), hx(in), 1,
                   [&] { return "OK " + hx(r_to_scalar(in)); });
        }
    }
    std::vector<std::pair<std::string, B>> edges = {
        {"edge:zero", B(64, 0)}, {"edge:ones", B(64, 0xff)},
        {"edge:r_low", cat(z2le(RJ, 32), B(32, 0))}, {"edge:r_high", cat(B(32, 0), z2le(RJ, 32))},
        {"edge:r-1", cat(z2le(RJ - 1, 32), B(32, 0))}, {"edge:2^256", cat(B(32, 0), z2le(1, 32))},
        {"edge:r*2^256", z2le(RJ << 256, 64)}};
    for (auto& e : edges) single(g, e.first, hx(e.second), 1, [&] { return "OK " + hx(r_to_scalar(e.second)); });
    DRng r("to_scalar");
    for (size_t i = 0; i < NRAND; i++) {
        B in = r.bytes(64);
        single(g, "rand", hx(in), 1, [&] { return "OK " + hx(r_to_scalar(in)); });
    }
    finish(g);
}

static void gen_fixed_mult(const char* file, const char* fn, int col_in, int col_out, bool nsk)
{
    Golden g(file, fn, "scalar:hex32", "result:hex32",
             "void; scalar read as a raw 256-bit integer with no range check (read_fs).");
    auto call = [&](const B& s) { return "OK " + hx(nsk ? r_nsk_to_nk(s) : r_ask_to_ak(s)); };
    for (size_t i = 0; i < g_keyrows.size(); i++) {
        B s = rev(unhex(g_keyrows[i][col_in]));
        B want = rev(unhex(g_keyrows[i][col_out]));
        if ((nsk ? r_nsk_to_nk(s) : r_ask_to_ak(s)) != want) die("%s key vector %zu mismatch", fn, i);
        single(g, "vec:keycomp:" + std::to_string(i), hx(s), 1, [&] { return call(s); });
    }
    B base = rev(unhex(g_keyrows[0][col_in]));
    for (auto& m : fs_mutations(base)) single(g, "edge:" + m.first, hx(m.second), 1, [&] { return call(m.second); });
    B t = z2le(TWO255, 32);
    single(g, "edge:2^255", hx(t), 1, [&] { return call(t); });
    DRng r{std::string(fn)};
    for (size_t i = 0; i < NRAND; i++) {
        B s = mixed_fs(r, i);
        single(g, "rand", hx(s), 1, [&] { return call(s); });
    }
    finish(g);
}

static void gen_crh_ivk()
{
    Golden g("crh_ivk.golden", "librustzcash_crh_ivk", "ak:hex32 nk:hex32", "ivk:hex32",
             "void; BLAKE2s-256('Zcashivk', ak||nk) on raw bytes, top 5 bits cleared.");
    auto call = [](const B& a, const B& n) { return "OK " + hx(r_crh_ivk(a, n)); };
    for (size_t i = 0; i < g_keyrows.size(); i++) {
        B ak = rev(unhex(g_keyrows[i][4])), nk = rev(unhex(g_keyrows[i][5]));
        if (r_crh_ivk(ak, nk) != rev(unhex(g_keyrows[i][6]))) die("crh_ivk vector %zu mismatch", i);
        single(g, "vec:keycomp:" + std::to_string(i), hx(ak) + " " + hx(nk), 1, [&] { return call(ak, nk); });
    }
    DRng r("crh_ivk");
    for (size_t i = 0; i < NRAND; i++) {
        B ak = mixed_point(r, i), nk = mixed_point(r, i + 3);
        single(g, "rand", hx(ak) + " " + hx(nk), 1, [&] { return call(ak, nk); });
    }
    finish(g);
}

static void gen_check_diversifier()
{
    Golden g("check_diversifier.golden", "librustzcash_check_diversifier", "d:hex11", "",
             "bool; T iff group_hash('Zcash_gd', d) exists and is not small order.");
    auto call = [](const B& d) { return std::string(TF(librustzcash_check_diversifier(d.data()))); };
    for (size_t i = 0; i < g_keyrows.size(); i++) {
        B d = unhex(g_keyrows[i][7]);
        single(g, "vec:keycomp:" + std::to_string(i), hx(d), 0, [&] { return call(d); });
    }
    std::vector<B> edges = {B(11, 0), B(11, 0xff)};
    for (auto& d : edges) single(g, "edge", hx(d), 0, [&] { return call(d); });
    DRng r("check_diversifier");
    for (size_t i = 0; i < NRAND; i++) {
        B d = r.bytes(11);
        single(g, "rand", hx(d), 0, [&] { return call(d); });
    }
    finish(g);
}

static void gen_ivk_to_pkd()
{
    Golden g("ivk_to_pkd.golden", "librustzcash_ivk_to_pkd", "ivk:hex32 d:hex11", "pk_d:hex32",
             "bool; F iff g_d invalid; ivk read with no range check.");
    auto call = [](const B& ivk, const B& d) {
        B o(32);
        bool ok = librustzcash_ivk_to_pkd(ivk.data(), d.data(), o.data());
        return ok ? "T " + hx(o) : std::string("F -");
    };
    for (size_t i = 0; i < g_keyrows.size(); i++) {
        B ivk = rev(unhex(g_keyrows[i][6])), d = unhex(g_keyrows[i][7]);
        B o(32);
        if (!librustzcash_ivk_to_pkd(ivk.data(), d.data(), o.data()) || o != rev(unhex(g_keyrows[i][8])))
            die("ivk_to_pkd vector %zu mismatch", i);
        single(g, "vec:keycomp:" + std::to_string(i), hx(ivk) + " " + hx(d), 1, [&] { return call(ivk, d); });
    }
    DRng r("ivk_to_pkd");
    for (size_t i = 0; i < NRAND; i++) {
        B ivk = (i % 3 == 0) ? r_crh_ivk(r_ask_to_ak(rand_fs(r)), r_nsk_to_nk(rand_fs(r))) : mixed_fs(r, i);
        B d = (i % 2) ? valid_d(r) : r.bytes(11);
        single(g, "rand", hx(ivk) + " " + hx(d), 1, [&] { return call(ivk, d); });
    }
    finish(g);
}

static void gen_tree()
{
    {
        Golden g("tree_uncommitted.golden", "librustzcash_tree_uncommitted", "", "result:hex32",
                 "void; the empty Sapling leaf (Fr one).");
        single(g, "only", "", 1, [] {
            B o(32);
            librustzcash_tree_uncommitted(o.data());
            return "OK " + hx(o);
        });
        finish(g);
    }
    Golden g("merkle_hash.golden", "librustzcash_merkle_hash", "depth:size a:hex32 b:hex32", "result:hex32",
             "void; Pedersen hash of 6 depth bits + low 255 bits of a and of b; depth >= 63 panics.");
    auto call = [](size_t depth, const B& a, const B& b) { return "OK " + hx(r_merkle(depth, a, b)); };
    std::set<std::string> seen;
    auto rec = [&](const std::string& label, size_t depth, const B& a, const B& b) {
        std::string ins = u64s(depth) + " " + hx(a) + " " + hx(b);
        if (!seen.insert(ins).second) return;
        single(g, label, ins, 1, [&] { return call(depth, a, b); });
    };
    // Pedersen hash vector (src/gtest/test_pedersen_hash.cpp; uint256S is byte-reversed).
    B a = rev(unhex("87a086ae7d2252d58729b30263fb7b66308bf94ef59a76c9c86e7ea016536505"));
    B b = rev(unhex("a75b84a125b2353da7e8d96ee2a15efe4de23df9601b9d9564ba59de57130406"));
    if (r_merkle(25, a, b) != rev(unhex("5bf43b5736c19b714d1f462c9d22ba3492c36e3d9bbd7ca24d94b440550aa561")))
        die("Pedersen vector mismatch");
    rec("vec:pedersen", 25, a, b);
    // Empty roots, checked against merkle_roots_empty_sapling.json.
    auto empty_json = json_strings(read_file(g_src + "/test/data/merkle_roots_empty_sapling.json"));
    g_empty.clear();
    B u(32);
    librustzcash_tree_uncommitted(u.data());
    g_empty.push_back(u);
    for (size_t d = 0; d < 63; d++) {
        rec("vec:empty:" + std::to_string(d), d, g_empty[d], g_empty[d]);
        g_empty.push_back(r_merkle(d, g_empty[d], g_empty[d]));
    }
    for (size_t d = 0; d < empty_json.size(); d++)
        if (hx(g_empty[d]) != empty_json[d]) die("empty root %zu mismatch", d);
    // Incremental tree vectors: merkle_commitments_sapling.json (uint256S order),
    // roots in merkle_roots_sapling.json (serialized order) are for the depth-4
    // testing tree (INCREMENTAL_MERKLE_TREE_DEPTH_TESTING). The same leaves are
    // then carried on to a depth-32 root (label vec:tree32, no published root).
    auto cms = json_strings(read_file(g_src + "/test/data/merkle_commitments_sapling.json"));
    auto roots = json_strings(read_file(g_src + "/test/data/merkle_roots_sapling.json"));
    if (cms.size() != roots.size()) die("merkle vector size mismatch");
    std::vector<B> leaves;
    for (size_t k = 0; k < cms.size(); k++) {
        leaves.push_back(rev(unhex(cms[k])));
        std::vector<B> level = leaves;
        for (size_t d = 0; d < 32; d++) {
            std::vector<B> next;
            for (size_t i = 0; i < level.size(); i += 2) {
                const B& l = level[i];
                const B& rr = (i + 1 < level.size()) ? level[i + 1] : g_empty[d];
                rec(std::string(d < 4 ? "vec:tree:" : "vec:tree32:") + std::to_string(k) + ":" + std::to_string(d), d, l, rr);
                next.push_back(r_merkle(d, l, rr));
            }
            level = next;
            if (d == 3 && hx(level[0]) != roots[k]) die("depth-4 tree root %zu mismatch", k);
        }
    }
    // Edges: non-canonical inputs and the panic boundary.
    DRng er("merkle-edge");
    B c = rand_fr(er);
    for (auto& m : fr_mutations(c)) {
        rec("edge:a" + m.first, 5, m.second, c);
        rec("edge:b" + m.first, 5, c, m.second);
    }
    for (size_t d : {(size_t)62, (size_t)63, (size_t)64, (size_t)127, (size_t)255, (size_t)1000, SIZE_MAX})
        rec("edge:depth", d, c, c);
    DRng r("merkle_hash");
    for (size_t i = 0; i < NRAND; i++) {
        size_t depth = r.below(63);
        B x = (i % 4 == 3) ? r.bytes(32) : rand_fr(r);
        B y = (i % 5 == 4) ? r.bytes(32) : rand_fr(r);
        rec("rand", depth, x, y);
    }
    finish(g);
}

static void gen_note_fns()
{
    // compute_cm
    {
        Golden g("sapling_compute_cm.golden", "librustzcash_sapling_compute_cm",
                 "d:hex11 pk_d:hex32 value:u64 rcm:hex32", "cm:hex32",
                 "bool; F if g_d invalid, pk_d not a prime-order point, or rcm >= r.");
        auto call = [](const B& d, const B& pkd, uint64_t v, const B& rcm) {
            B o(32);
            bool ok = librustzcash_sapling_compute_cm(d.data(), pkd.data(), v, rcm.data(), o.data());
            return ok ? "T " + hx(o) : std::string("F -");
        };
        auto rec = [&](const std::string& l, const B& d, const B& pkd, uint64_t v, const B& rcm) {
            single(g, l, hx(d) + " " + hx(pkd) + " " + u64s(v) + " " + hx(rcm), 1, [&] { return call(d, pkd, v, rcm); });
        };
        for (size_t i = 0; i < g_keyrows.size(); i++) {
            auto& row = g_keyrows[i];
            B d = unhex(row[7]), pkd = rev(unhex(row[8])), rcm = rev(unhex(row[10]));
            uint64_t v = strtoull(row[9].c_str(), nullptr, 10);
            if (r_cm(d, pkd, v, rcm) != rev(unhex(row[11]))) die("cm vector %zu mismatch", i);
            rec("vec:keycomp:" + std::to_string(i), d, pkd, v, rcm);
        }
        DRng r("compute_cm");
        Keys k = keys_from_sk(r.bytes(32), r);
        B rcm = rand_fs(r);
        for (auto& m : point_mutations(k.pkd)) rec("mut:pk_d:" + m.first, k.d, m.second, 7, rcm);
        for (auto& m : fs_mutations(rcm)) rec("mut:rcm" + m.first, k.d, k.pkd, 7, m.second);
        rec("mut:d:invalid", invalid_d(r), k.pkd, 7, rcm);
        for (uint64_t v : {(uint64_t)0, (uint64_t)1, (uint64_t)2100000000000000ULL, UINT64_MAX})
            rec("edge:value", k.d, k.pkd, v, rcm);
        for (size_t i = 0; i < NRAND; i++) {
            Keys kk = keys_from_sk(r.bytes(32), r);
            B pkd = kk.pkd, d = kk.d, rc = rand_fs(r);
            uint64_t v = r.u64() >> (r.below(64));
            std::string l = "rand";
            switch (i % 6) {
            case 3: { Muts m = point_mutations(pkd); auto& x = m[r.below(m.size())]; pkd = x.second; l = "rand:pk_d:" + x.first; break; }
            case 4: rc = mixed_fs(r, 7); l = "rand:rcm"; break;
            case 5: if (r.below(2)) { d = r.bytes(11); l = "rand:d"; } else { pkd = r.bytes(32); l = "rand:pk_d_raw"; } break;
            default: break;
            }
            rec(l, d, pkd, v, rc);
        }
        finish(g);
    }
    // compute_nf
    {
        Golden g("sapling_compute_nf.golden", "librustzcash_sapling_compute_nf",
                 "d:hex11 pk_d:hex32 value:u64 rcm:hex32 ak:hex32 nk:hex32 position:u64", "nf:hex32",
                 "bool; F if g_d invalid, pk_d/ak/nk not prime-order points, or rcm >= r.");
        auto call = [](const B& d, const B& pkd, uint64_t v, const B& rcm, const B& ak, const B& nk, uint64_t pos) {
            B o(32);
            bool ok = librustzcash_sapling_compute_nf(d.data(), pkd.data(), v, rcm.data(), ak.data(), nk.data(), pos, o.data());
            return ok ? "T " + hx(o) : std::string("F -");
        };
        auto rec = [&](const std::string& l, const B& d, const B& pkd, uint64_t v, const B& rcm, const B& ak,
                       const B& nk, uint64_t pos) {
            single(g, l, hx(d) + " " + hx(pkd) + " " + u64s(v) + " " + hx(rcm) + " " + hx(ak) + " " + hx(nk) + " " + u64s(pos),
                   1, [&] { return call(d, pkd, v, rcm, ak, nk, pos); });
        };
        for (size_t i = 0; i < g_keyrows.size(); i++) {
            auto& row = g_keyrows[i];
            B d = unhex(row[7]), pkd = rev(unhex(row[8])), rcm = rev(unhex(row[10]));
            B ak = rev(unhex(row[4])), nk = rev(unhex(row[5]));
            uint64_t v = strtoull(row[9].c_str(), nullptr, 10), pos = strtoull(row[12].c_str(), nullptr, 10);
            if (r_nf(d, pkd, v, rcm, ak, nk, pos) != rev(unhex(row[13]))) die("nf vector %zu mismatch", i);
            rec("vec:keycomp:" + std::to_string(i), d, pkd, v, rcm, ak, nk, pos);
        }
        DRng r("compute_nf");
        Keys k = keys_from_sk(r.bytes(32), r);
        B rcm = rand_fs(r);
        for (auto& m : point_mutations(k.pkd)) rec("mut:pk_d:" + m.first, k.d, m.second, 7, rcm, k.ak, k.nk, 3);
        for (auto& m : point_mutations(k.ak)) rec("mut:ak:" + m.first, k.d, k.pkd, 7, rcm, m.second, k.nk, 3);
        for (auto& m : point_mutations(k.nk)) rec("mut:nk:" + m.first, k.d, k.pkd, 7, rcm, k.ak, m.second, 3);
        for (auto& m : fs_mutations(rcm)) rec("mut:rcm" + m.first, k.d, k.pkd, 7, m.second, k.ak, k.nk, 3);
        rec("mut:d:invalid", invalid_d(r), k.pkd, 7, rcm, k.ak, k.nk, 3);
        for (uint64_t p : {(uint64_t)0, (uint64_t)0xffffffffULL, (uint64_t)0x100000000ULL, UINT64_MAX})
            rec("edge:position", k.d, k.pkd, 7, rcm, k.ak, k.nk, p);
        for (size_t i = 0; i < NRAND; i++) {
            Keys kk = keys_from_sk(r.bytes(32), r);
            B pkd = kk.pkd, d = kk.d, rc = rand_fs(r), ak = kk.ak, nk = kk.nk;
            uint64_t v = r.u64() >> r.below(64), pos = r.u64() >> r.below(64);
            std::string l = "rand";
            switch (i % 8) {
            case 3: { Muts m = point_mutations(pkd); auto& x = m[r.below(m.size())]; pkd = x.second; l = "rand:pk_d:" + x.first; break; }
            case 4: { Muts m = point_mutations(ak); auto& x = m[r.below(m.size())]; ak = x.second; l = "rand:ak:" + x.first; break; }
            case 5: { Muts m = point_mutations(nk); auto& x = m[r.below(m.size())]; nk = x.second; l = "rand:nk:" + x.first; break; }
            case 6: rc = mixed_fs(r, 7); l = "rand:rcm"; break;
            case 7: d = r.bytes(11); l = "rand:d"; break;
            default: break;
            }
            rec(l, d, pkd, v, rc, ak, nk, pos);
        }
        finish(g);
    }
}

static void gen_ka()
{
    {
        Golden g("sapling_ka_agree.golden", "librustzcash_sapling_ka_agree", "p:hex32 sk:hex32", "result:hex32",
                 "bool; F if p does not decode or sk >= r; result = [sk]([8]p), any curve point accepted.");
        auto call = [](const B& p, const B& sk) {
            B o(32);
            bool ok = librustzcash_sapling_ka_agree(p.data(), sk.data(), o.data());
            return ok ? "T " + hx(o) : std::string("F -");
        };
        auto rec = [&](const std::string& l, const B& p, const B& sk) {
            single(g, l, hx(p) + " " + hx(sk), 1, [&] { return call(p, sk); });
        };
        DRng r("ka_agree");
        B p = r_ask_to_ak(rand_fs(r)), sk = rand_fs(r);
        for (auto& m : point_mutations(p)) rec("mut:p:" + m.first, m.second, sk);
        for (auto& m : fs_mutations(sk)) rec("mut:sk" + m.first, p, m.second);
        for (size_t i = 0; i < NRAND; i++) rec("rand", mixed_point(r, i), mixed_fs(r, i + 1));
        finish(g);
    }
    {
        Golden g("sapling_ka_derivepublic.golden", "librustzcash_sapling_ka_derivepublic", "d:hex11 esk:hex32",
                 "result:hex32", "bool; F if g_d invalid or esk >= r; result = [esk]g_d.");
        auto call = [](const B& d, const B& esk) {
            B o(32);
            bool ok = librustzcash_sapling_ka_derivepublic(d.data(), esk.data(), o.data());
            return ok ? "T " + hx(o) : std::string("F -");
        };
        auto rec = [&](const std::string& l, const B& d, const B& esk) {
            single(g, l, hx(d) + " " + hx(esk), 1, [&] { return call(d, esk); });
        };
        DRng r("ka_derivepublic");
        B d = valid_d(r), esk = rand_fs(r);
        for (auto& m : fs_mutations(esk)) rec("mut:esk" + m.first, d, m.second);
        rec("mut:d:invalid", invalid_d(r), esk);
        for (size_t i = 0; i < NRAND; i++) rec("rand", (i % 3 == 2) ? r.bytes(11) : valid_d(r), mixed_fs(r, i));
        finish(g);
    }
}

static void gen_generate_r()
{
    Golden g("sapling_generate_r.golden", "librustzcash_sapling_generate_r", "", "result:hex32 lt_r:bool",
             "void; OsRng 64 bytes -> to_uniform. NONDETERMINISTIC: replay checks lt_r (result < r) only;\n"
             "the recorded results are samples, never expected values.");
    for (size_t i = 0; i < NRAND; i++) {
        single(g, "sample", "", 2, [] {
            B o(32);
            librustzcash_sapling_generate_r(o.data());
            return "OK " + hx(o) + " " + TF(le2z(o) < RJ);
        });
    }
    finish(g);
}

static void gen_spend_sig()
{
    Golden g("sapling_spend_sig.golden", "librustzcash_sapling_spend_sig", "ask:hex32 ar:hex32 sighash:hex32",
             "sig:hex64 | derived rk:hex32",
             "bool; F iff ask >= r or ar >= r. Signature uses OsRng (NONDETERMINISTIC): replay verifies sig\n"
             "under rk = [ask+ar mod r]G_spend over rk||sighash (derived rk is Rust ask_to_ak((ask+ar) mod r)).");
    auto call = [](const B& ask, const B& ar, const B& sh) {
        B o(64);
        bool ok = librustzcash_sapling_spend_sig(ask.data(), ar.data(), sh.data(), o.data());
        if (!ok) return std::string("F - -");
        B rsk = z2le(md(le2z(ask) + le2z(ar), RJ), 32);
        return "T " + hx(o) + " " + hx(r_ask_to_ak(rsk));
    };
    auto rec = [&](const std::string& l, const B& ask, const B& ar, const B& sh) {
        single(g, l, hx(ask) + " " + hx(ar) + " " + hx(sh), 2, [&] { return call(ask, ar, sh); });
    };
    DRng r("spend_sig");
    B ask = rand_fs(r), ar = rand_fs(r), sh = r.bytes(32);
    for (auto& m : fs_mutations(ask)) rec("mut:ask" + m.first, m.second, ar, sh);
    for (auto& m : fs_mutations(ar)) rec("mut:ar" + m.first, ask, m.second, sh);
    size_t n = NRAND;
    for (size_t i = 0; i < n; i++) rec("rand", (i % 10 == 9) ? mixed_fs(r, 7) : rand_fs(r), rand_fs(r), r.bytes(32));
    finish(g);
}

// ZIP-32 serializations: xsk = depth u8 | tag[4] | index u32 LE | chain[32] | ask | nsk | ovk | dk;
// xfvk = depth | tag | index | chain | ak | nk | ovk | dk (169 bytes each).
static B xsk_to_xfvk(const B& xsk)
{
    B x = xsk;
    B ak = r_ask_to_ak(sub(xsk, 41, 32)), nk = r_nsk_to_nk(sub(xsk, 73, 32));
    std::copy(ak.begin(), ak.end(), x.begin() + 41);
    std::copy(nk.begin(), nk.end(), x.begin() + 73);
    return x;
}
static B r_xsk_master(const B& seed)
{
    B o(169);
    librustzcash_zip32_xsk_master(seed.data(), seed.size(), o.data());
    return o;
}
static B r_xsk_derive(const B& p, uint32_t i)
{
    B o(169);
    librustzcash_zip32_xsk_derive(p.data(), i, o.data());
    return o;
}

static void gen_zip32()
{
    // Vectors (src/gtest/test_zip32.cpp; uint256S values are byte-reversed).
    B seed;
    for (int i = 0; i < 32; i++) seed.push_back((uint8_t)i);
    B m = r_xsk_master(seed);
    auto chk = [](const B& x, size_t off, const char* be, const char* what) {
        if (sub(x, off, 32) != rev(unhex(be))) die("ZIP-32 vector %s mismatch", what);
    };
    chk(m, 9, "8e661820750d557e8b34733ebf7ecdfdf31c6d27724fb47aa372bf034b7c94d0", "m.chain");
    chk(m, 41, "06257454c907f6510ba1c1830ebf60657760a8869ee968a2b93260d3930cc0b6", "m.ask");
    chk(m, 137, "72a196f93e8abc0935280ea2a96fa57d6024c9913e0f9fb3af96775bb77cc177", "m.dk");
    B m1 = r_xsk_derive(m, 1);
    if (sub(m1, 1, 4) != sub(le64(0x3a71c214), 0, 4)) die("ZIP-32 m/1 tag mismatch");
    chk(m1, 41, "0c357a2655b4b8d761794095df5cb402d3ba4a428cf6a88e7c2816a597c12b28", "m1.ask");
    B m12h = r_xsk_derive(m1, 2 | 0x80000000u);
    chk(m12h, 9, "35d4a883737742ca41a4baa92323bdb3c93dcb3b462a26b039971bedf415ce97", "m12h.chain");
    B m12hv = xsk_to_xfvk(m12h);
    chk(m12hv, 41, "4138cffdf7200e52d4e9f4384481b4a4c4d070493a5e401e4ffa850f5a92c5a6", "m12hv.ak");
    B m12hv3(169);
    if (!librustzcash_zip32_xfvk_derive(m12hv.data(), 3, m12hv3.data())) die("ZIP-32 xfvk derive failed");
    chk(m12hv3, 41, "a3a697bdda9d648d32a97553de4754b2fac866d726d3f2c436259c507bc585b1", "m12hv3.ak");
    if (sub(m12hv3, 1, 4) != sub(le64(0x7583c148), 0, 4)) die("ZIP-32 m12hv3 tag mismatch");
    {
        B j(11, 0), jr(11), addr(43);
        if (!librustzcash_zip32_xfvk_address(xsk_to_xfvk(m).data(), j.data(), jr.data(), addr.data()))
            die("ZIP-32 address failed");
        if (hx(sub(addr, 0, 11)) != "d8621b981cf300e9d4cc89") die("ZIP-32 default address d mismatch");
    }

    DRng r("zip32");
    // xsk_master
    {
        Golden g("zip32_xsk_master.golden", "librustzcash_zip32_xsk_master", "seedlen:size seed:hex*",
                 "xsk:hex169", "void; '~' is a zero-length seed.");
        auto rec = [&](const std::string& l, const B& s) {
            single(g, l, u64s(s.size()) + " " + hx(s), 1, [&] { return "OK " + hx(r_xsk_master(s)); });
        };
        rec("vec:zip32", seed);
        for (size_t len : {(size_t)0, (size_t)1, (size_t)16, (size_t)31, (size_t)33, (size_t)64, (size_t)255, (size_t)1024})
            rec("edge:len", r.bytes(len));
        for (size_t i = 0; i < NRAND; i++) rec("rand", r.bytes((i % 4 == 3) ? r.below(129) : 32));
        finish(g);
    }
    // xsk_derive
    {
        Golden g("zip32_xsk_derive.golden", "librustzcash_zip32_xsk_derive", "parent:hex169 i:u32", "xsk:hex169",
                 "void; panics (ABORT) if parent ask or nsk >= r. i >= 2^31 is hardened.");
        auto rec = [&](const std::string& l, const B& p, uint32_t i) {
            single(g, l, hx(p) + " " + std::to_string(i), 1, [&] { return "OK " + hx(r_xsk_derive(p, i)); });
        };
        rec("vec:zip32:m/1", m, 1);
        rec("vec:zip32:m/1/2h", m1, 2 | 0x80000000u);
        for (auto& mm : fs_mutations(sub(m, 41, 32))) {
            B p = m;
            std::copy(mm.second.begin(), mm.second.end(), p.begin() + 41);
            rec("mut:ask" + mm.first, p, 1);
        }
        for (auto& mm : fs_mutations(sub(m, 73, 32))) {
            B p = m;
            std::copy(mm.second.begin(), mm.second.end(), p.begin() + 73);
            rec("mut:nsk" + mm.first, p, 0x80000001u);
        }
        B p = m;
        p[0] = 255;
        rec("edge:depth255", p, 5);
        rec("edge:i=2^31-1", m, 0x7fffffffu);
        rec("edge:i=2^32-1", m, 0xffffffffu);
        std::vector<B> parents = {m, m1, m12h};
        for (size_t i = 0; i < NRAND; i++) {
            B par = (i % 3 == 0) ? r_xsk_master(r.bytes(32)) : parents[r.below(parents.size())];
            uint32_t idx = (uint32_t)r.u64();
            if (i % 2) idx &= 0x7fffffffu;
            rec("rand", par, idx);
            if (parents.size() < 64 && i % 7 == 0) parents.push_back(r_xsk_derive(par, idx));
        }
        finish(g);
    }
    // xfvk_derive
    {
        Golden g("zip32_xfvk_derive.golden", "librustzcash_zip32_xfvk_derive", "parent:hex169 i:u32", "xfvk:hex169",
                 "bool; F for hardened i; panics (ABORT) if parent ak/nk do not decode or are not prime order.");
        auto rec = [&](const std::string& l, const B& p, uint32_t i) {
            single(g, l, hx(p) + " " + std::to_string(i), 1, [&] {
                B o(169);
                bool ok = librustzcash_zip32_xfvk_derive(p.data(), i, o.data());
                return ok ? "T " + hx(o) : std::string("F -");
            });
        };
        rec("vec:zip32:m/1/2h/3", m12hv, 3);
        rec("vec:zip32:hardened", m12hv, 3 | 0x80000000u);
        for (auto& mm : point_mutations(sub(m12hv, 41, 32))) {
            B p = m12hv;
            std::copy(mm.second.begin(), mm.second.end(), p.begin() + 41);
            rec("mut:ak:" + mm.first, p, 3);
        }
        for (auto& mm : point_mutations(sub(m12hv, 73, 32))) {
            B p = m12hv;
            std::copy(mm.second.begin(), mm.second.end(), p.begin() + 73);
            rec("mut:nk:" + mm.first, p, 3);
        }
        for (size_t i = 0; i < NRAND; i++) {
            B par = xsk_to_xfvk((i % 2) ? r_xsk_master(r.bytes(32)) : r_xsk_derive(m, (uint32_t)r.u64()));
            uint32_t idx = (uint32_t)r.u64();
            if (i % 4) idx &= 0x7fffffffu;
            rec("rand", par, idx);
        }
        finish(g);
    }
    // xfvk_address
    {
        Golden g("zip32_xfvk_address.golden", "librustzcash_zip32_xfvk_address", "xfvk:hex169 j:hex11",
                 "j_ret:hex11 addr:hex43",
                 "bool; searches j, j+1, ... (88-bit LE) for a valid diversifier; F if the index space is\n"
                 "exhausted; panics (ABORT) if xfvk ak/nk invalid.");
        auto rec = [&](const std::string& l, const B& x, const B& j) {
            single(g, l, hx(x) + " " + hx(j), 2, [&] {
                B jr(11), a(43);
                bool ok = librustzcash_zip32_xfvk_address(x.data(), j.data(), jr.data(), a.data());
                return ok ? "T " + hx(jr) + " " + hx(a) : std::string("F - -");
            });
        };
        B xm = xsk_to_xfvk(m);
        rec("vec:zip32:m:default", xm, B(11, 0));
        rec("vec:zip32:m12hv3:default", m12hv3, B(11, 0));
        rec("edge:j=max", xm, B(11, 0xff));
        B jm = B(11, 0xff);
        jm[0] = 0xf0;
        rec("edge:j=max-15", xm, jm);
        for (auto& mm : point_mutations(sub(xm, 41, 32))) {
            B p = xm;
            std::copy(mm.second.begin(), mm.second.end(), p.begin() + 41);
            rec("mut:ak:" + mm.first, p, B(11, 0));
        }
        for (size_t i = 0; i < NRAND; i++) {
            B x = xsk_to_xfvk(r_xsk_master(r.bytes(32)));
            B j = (i % 3 == 0) ? B(11, 0) : r.bytes(11);
            rec("rand", x, j);
        }
        finish(g);
    }
}

// ---------------------------------------------------------------------------
// Section 2: parameters

static void init_params_parent()
{
    std::string s = g_params + "/sapling-spend.params", o = g_params + "/sapling-output.params",
                g = g_params + "/sprout-groth16.params";
    librustzcash_init_zksnark_params((const codeunit*)s.c_str(), s.size(), SPEND_HASH, (const codeunit*)o.c_str(),
                                     o.size(), OUTPUT_HASH, (const codeunit*)g.c_str(), g.size(), SPROUT_HASH);
}

static void gen_init_params()
{
    Golden g("init_zksnark_params.golden", "librustzcash_init_zksnark_params",
             "spend_file:name spend_hash:text output_file:name output_hash:text sprout_file:name sprout_hash:text", "",
             "void; files are names inside the Zcash params directory; hashes are the NUL-terminated BLAKE2b-512\n"
             "hex strings passed by src/init.cpp. Rust panics (ABORT) on any missing file, parse error or mismatch.");
    struct C {
        std::string label, sf, sh, of, oh, gf, gh;
    };
    std::string bad = SPEND_HASH;
    bad[0] = (bad[0] == '0') ? '1' : '0';
    std::string up = SPEND_HASH;
    for (auto& c : up) c = (char)toupper((unsigned char)c);
    std::vector<C> cases = {
        {"canonical", "sapling-spend.params", SPEND_HASH, "sapling-output.params", OUTPUT_HASH, "sprout-groth16.params", SPROUT_HASH},
        {"spend_hash_wrong", "sapling-spend.params", bad, "sapling-output.params", OUTPUT_HASH, "sprout-groth16.params", SPROUT_HASH},
        {"spend_hash_upper", "sapling-spend.params", up, "sapling-output.params", OUTPUT_HASH, "sprout-groth16.params", SPROUT_HASH},
        {"output_hash_wrong", "sapling-spend.params", SPEND_HASH, "sapling-output.params", SPEND_HASH, "sprout-groth16.params", SPROUT_HASH},
        {"sprout_hash_wrong", "sapling-spend.params", SPEND_HASH, "sapling-output.params", OUTPUT_HASH, "sprout-groth16.params", OUTPUT_HASH},
        {"spend_missing", "no-such-file.params", SPEND_HASH, "sapling-output.params", OUTPUT_HASH, "sprout-groth16.params", SPROUT_HASH},
        {"files_swapped", "sapling-output.params", SPEND_HASH, "sapling-spend.params", OUTPUT_HASH, "sprout-groth16.params", SPROUT_HASH},
    };
    if (g_quick) cases.resize(2);
    for (auto& c : cases) {
        std::string ins = c.sf + " " + c.sh + " " + c.of + " " + c.oh + " " + c.gf + " " + c.gh;
        single(g, c.label, ins, 0, [&] {
            std::string s = g_params + "/" + c.sf, o = g_params + "/" + c.of, gg = g_params + "/" + c.gf;
            librustzcash_init_zksnark_params((const codeunit*)s.c_str(), s.size(), c.sh.c_str(),
                                             (const codeunit*)o.c_str(), o.size(), c.oh.c_str(),
                                             (const codeunit*)gg.c_str(), gg.size(), c.gh.c_str());
            return std::string("OK");
        });
    }
    finish(g);
}

// ---------------------------------------------------------------------------
// Section 3: proving (Rust-made proofs with full witnesses)

struct SpendIn {
    Keys k;
    B rcm, ar, anchor, witness, nf, sighash;
    uint64_t value, pos;
};
struct OutIn {
    Keys k;
    B esk, rcm, cm, epk;
    uint64_t value;
};

static B make_witness(const B& cm, uint64_t pos, const std::vector<B>& sib, B& anchor_out)
{
    B node = cm;
    for (size_t d = 0; d < 32; d++) node = ((pos >> d) & 1) ? r_merkle(d, sib[d], node) : r_merkle(d, node, sib[d]);
    anchor_out = node;
    B w;
    w.push_back(32);
    for (int d = 31; d >= 0; d--) {
        w.push_back(32);
        w.insert(w.end(), sib[d].begin(), sib[d].end());
    }
    B p = le64(pos);
    w.insert(w.end(), p.begin(), p.end());
    if (w.size() != 1065) die("witness size %zu", w.size());
    return w;
}

static SpendIn make_spend(DRng& r, uint64_t value, uint64_t pos, bool empty_siblings)
{
    SpendIn s;
    s.k = keys_from_sk(r.bytes(32), r);
    s.rcm = rand_fs(r);
    s.ar = rand_fs(r);
    s.value = value;
    s.pos = pos;
    B cm = r_cm(s.k.d, s.k.pkd, value, s.rcm);
    std::vector<B> sib(32);
    for (size_t d = 0; d < 32; d++) sib[d] = empty_siblings ? g_empty[d] : rand_fr(r);
    s.witness = make_witness(cm, pos, sib, s.anchor);
    s.nf = r_nf(s.k.d, s.k.pkd, value, s.rcm, s.k.ak, s.k.nk, pos);
    return s;
}
static OutIn make_out(DRng& r, uint64_t value)
{
    OutIn o;
    o.k = keys_from_sk(r.bytes(32), r);
    o.esk = rand_fs(r);
    o.rcm = rand_fs(r);
    o.value = value;
    o.cm = r_cm(o.k.d, o.k.pkd, value, o.rcm);
    o.epk = B(32);
    if (!librustzcash_sapling_ka_derivepublic(o.k.d.data(), o.esk.data(), o.epk.data())) die("ka_derivepublic failed");
    return o;
}

static std::string ps_ins(const B& ak, const B& nsk, const B& d, const B& rcm, const B& ar, uint64_t v,
                          const B& anchor, const B& w)
{
    return hx(ak) + " " + hx(nsk) + " " + hx(d) + " " + hx(rcm) + " " + hx(ar) + " " + u64s(v) + " " + hx(anchor) + " " + hx(w);
}
static std::string po_ins(const B& esk, const B& d, const B& pkd, const B& rcm, uint64_t v)
{
    return hx(esk) + " " + hx(d) + " " + hx(pkd) + " " + hx(rcm) + " " + u64s(v);
}

// Verification-side data of Rust-made bundles, reused as valid bases.
struct SV {
    B cv, anchor, nf, rk, proof, sig, sighash;
};
struct OV {
    B cv, cm, epk, proof;
};
struct BundleV {
    std::string label;
    std::vector<SV> sp;
    std::vector<OV> out;
    int64_t vb;
    B bsig, sighash;
};
static std::vector<BundleV> g_rustmade;

static void gen_spend_output_proofs()
{
    DRng r("spend_output_proof");
    // spend_proof
    {
        Golden g("sapling_spend_proof.golden", "librustzcash_sapling_spend_proof",
                 "ak:hex32 nsk:hex32 d:hex11 rcm:hex32 ar:hex32 value:u64 anchor:hex32 witness:hex1065",
                 "cv:hex32 rk:hex32 zkproof:hex192 | derived nf:hex32 sighash:hex32 spend_auth_sig:hex64 rust_check_spend:bool",
                 "bool; fresh proving ctx per record. witness = zclassicd serialized MerklePath: 0x20, then 32 x (0x20,\n"
                 "sibling) root level first, then u64 LE position; level-i position bit = (position >> i) & 1.\n"
                 "Proofs, cv and sig are NONDETERMINISTIC (OsRng). Positive records carry the derived nf, a\n"
                 "spend_auth_sig by Rust spend_sig(ask, ar, sighash), and Rust's own check_spend verdict on the\n"
                 "result, so a C verifier can be checked against Rust-made proofs and a C prover fed the inputs.");
        auto rec = [&](const std::string& label, const SpendIn& s, const B& ak, const B& nsk, const B& d, const B& rcm,
                       const B& ar, const B& anchor, const B& w) {
            std::string ins = ps_ins(ak, nsk, d, rcm, ar, s.value, anchor, w);
            single(g, label, ins, 7, [&] {
                void* ctx = librustzcash_sapling_proving_ctx_init();
                B cv(32), rk(32), pr(192);
                bool ok = librustzcash_sapling_spend_proof(ctx, ak.data(), nsk.data(), d.data(), rcm.data(), ar.data(),
                                                           s.value, anchor.data(), w.data(), cv.data(), rk.data(), pr.data());
                librustzcash_sapling_proving_ctx_free(ctx);
                if (!ok) return std::string("F - - - - - - -");
                B sig(64);
                if (!librustzcash_sapling_spend_sig(s.k.ask.data(), ar.data(), s.sighash.data(), sig.data()))
                    return std::string("T ") + hx(cv) + " " + hx(rk) + " " + hx(pr) + " " + hx(s.nf) + " " + hx(s.sighash) + " - F";
                void* v = librustzcash_sapling_verification_ctx_init();
                bool vk = librustzcash_sapling_check_spend(v, cv.data(), anchor.data(), s.nf.data(), rk.data(), pr.data(),
                                                           sig.data(), s.sighash.data());
                librustzcash_sapling_verification_ctx_free(v);
                return "T " + hx(cv) + " " + hx(rk) + " " + hx(pr) + " " + hx(s.nf) + " " + hx(s.sighash) + " " + hx(sig) + " " + TF(vk);
            });
        };
        std::vector<SpendIn> goods;
        goods.push_back(make_spend(r, 1000, 0, true));
        goods.push_back(make_spend(r, 123456789, 0x5a5a5a5aULL & 0xffffffffULL, false));
        goods.push_back(make_spend(r, 0, 0xffffffffULL, false));
        goods.push_back(make_spend(r, UINT64_MAX, 1, false));
        if (g_quick) goods.resize(1);
        for (size_t i = 0; i < goods.size(); i++) {
            auto& s = goods[i];
            s.sighash = r.bytes(32);
            rec("valid:" + std::to_string(i), s, s.k.ak, s.k.nsk, s.k.d, s.rcm, s.ar, s.anchor, s.witness);
        }
        SpendIn& s = goods[0];
        // Cheap rejections (before proving) and aborts.
        for (auto& m : point_mutations(s.k.ak)) rec("mut:ak:" + m.first, s, m.second, s.k.nsk, s.k.d, s.rcm, s.ar, s.anchor, s.witness);
        for (auto& m : fs_mutations(s.k.nsk)) rec("mut:nsk" + m.first, s, s.k.ak, m.second, s.k.d, s.rcm, s.ar, s.anchor, s.witness);
        rec("mut:d:invalid", s, s.k.ak, s.k.nsk, invalid_d(r), s.rcm, s.ar, s.anchor, s.witness);
        for (auto& m : fs_mutations(s.rcm)) rec("mut:rcm" + m.first, s, s.k.ak, s.k.nsk, s.k.d, m.second, s.ar, s.anchor, s.witness);
        for (auto& m : fs_mutations(s.ar)) rec("mut:ar" + m.first, s, s.k.ak, s.k.nsk, s.k.d, s.rcm, m.second, s.anchor, s.witness);
        for (auto& m : fr_mutations(s.anchor)) rec("mut:anchor" + m.first, s, s.k.ak, s.k.nsk, s.k.d, s.rcm, s.ar, m.second, s.witness);
        B w = s.witness;
        w[0] = 31;
        rec("mut:witness:depth31", s, s.k.ak, s.k.nsk, s.k.d, s.rcm, s.ar, s.anchor, w);
        w = s.witness;
        w[0] = 33;
        rec("mut:witness:depth33", s, s.k.ak, s.k.nsk, s.k.d, s.rcm, s.ar, s.anchor, w);
        w = s.witness;
        w[1] = 31;
        rec("mut:witness:inner_len_first", s, s.k.ak, s.k.nsk, s.k.d, s.rcm, s.ar, s.anchor, w);
        w = s.witness;
        w[1 + 33 * 31] = 0;
        rec("mut:witness:inner_len_last", s, s.k.ak, s.k.nsk, s.k.d, s.rcm, s.ar, s.anchor, w);
        for (int lvl : {31, 0}) {
            size_t off = 1 + 33 * (size_t)(31 - lvl) + 1;  // serialized entry for tree level lvl
            for (auto& m : fr_mutations(sub(s.witness, off, 32))) {
                if (m.first == "=q-1") continue;
                w = s.witness;
                std::copy(m.second.begin(), m.second.end(), w.begin() + off);
                rec("mut:witness:sibling_level" + std::to_string(lvl) + m.first, s, s.k.ak, s.k.nsk, s.k.d, s.rcm, s.ar, s.anchor, w);
            }
        }
        // Check order between independent failures.
        w = s.witness;
        w[0] = 31;
        rec("order:nsk>=r+depth31", s, s.k.ak, z2le(RJ, 32), s.k.d, s.rcm, s.ar, s.anchor, w);
        rec("order:anchor>=q+depth31", s, s.k.ak, s.k.nsk, s.k.d, s.rcm, s.ar, z2le(Q, 32), w);
        w = s.witness;
        w[1 + 33 * 31 + 1] = 0xff;  // level-0 sibling >= q
        w[1 + 33 * 31 + 32] = 0xff;
        w[1] = 7;                    // bad inner length at the first serialized (root-level) entry
        rec("order:inner_len_first+sibling0>=q", s, s.k.ak, s.k.nsk, s.k.d, s.rcm, s.ar, s.anchor, w);
        w = s.witness;
        {
            size_t off = 1 + 1;  // root-level sibling >= q, bad inner length on a later entry
            B qq = z2le(Q, 32);
            std::copy(qq.begin(), qq.end(), w.begin() + off);
            w[1 + 33 * 31] = 7;
        }
        rec("order:sibling31>=q+inner_len_last", s, s.k.ak, s.k.nsk, s.k.d, s.rcm, s.ar, s.anchor, w);
        if (!g_quick) {
            // Proving negatives: proof made, then Rust's self-verify decides.
            B anc = rand_fr(r);
            rec("prove:anchor_mismatch", s, s.k.ak, s.k.nsk, s.k.d, s.rcm, s.ar, anc, s.witness);
            w = s.witness;
            B hi = le64(s.pos | (1ULL << 40));
            std::copy(hi.begin(), hi.end(), w.begin() + 1057);
            rec("prove:position_high_bits", s, s.k.ak, s.k.nsk, s.k.d, s.rcm, s.ar, s.anchor, w);
            rec("prove:ak_identity", s, jenc(jid()), s.k.nsk, s.k.d, s.rcm, s.ar, s.anchor, s.witness);
            SpendIn s2 = s;
            s2.value = s.value + 1;
            rec("prove:value_mismatch", s2, s.k.ak, s.k.nsk, s.k.d, s.rcm, s.ar, s.anchor, s.witness);
        }
        finish(g);
    }
    // output_proof
    {
        Golden g("sapling_output_proof.golden", "librustzcash_sapling_output_proof",
                 "esk:hex32 d:hex11 pk_d:hex32 rcm:hex32 value:u64",
                 "cv:hex32 zkproof:hex192 | derived cm:hex32 epk:hex32 rust_check_output:bool",
                 "bool; fresh proving ctx per record. NONDETERMINISTIC proofs; derived cm (Rust compute_cm) and epk\n"
                 "(Rust ka_derivepublic) let a C verifier check the Rust-made proof; '-' where Rust refuses them.");
        auto rec = [&](const std::string& label, const B& esk, const B& d, const B& pkd, const B& rcm, uint64_t v) {
            single(g, label, po_ins(esk, d, pkd, rcm, v), 5, [&] {
                void* ctx = librustzcash_sapling_proving_ctx_init();
                B cv(32), pr(192);
                bool ok = librustzcash_sapling_output_proof(ctx, esk.data(), d.data(), pkd.data(), rcm.data(), v, cv.data(), pr.data());
                librustzcash_sapling_proving_ctx_free(ctx);
                if (!ok) return std::string("F - - - - -");
                B cm(32), epk(32);
                bool cmok = librustzcash_sapling_compute_cm(d.data(), pkd.data(), v, rcm.data(), cm.data());
                bool eok = librustzcash_sapling_ka_derivepublic(d.data(), esk.data(), epk.data());
                if (!cmok || !eok)
                    return "T " + hx(cv) + " " + hx(pr) + " " + (cmok ? hx(cm) : "-") + " " + (eok ? hx(epk) : "-") + " -";
                void* vc = librustzcash_sapling_verification_ctx_init();
                bool vk = librustzcash_sapling_check_output(vc, cv.data(), cm.data(), epk.data(), pr.data());
                librustzcash_sapling_verification_ctx_free(vc);
                return "T " + hx(cv) + " " + hx(pr) + " " + hx(cm) + " " + hx(epk) + " " + TF(vk);
            });
        };
        std::vector<OutIn> goods = {make_out(r, 1000), make_out(r, 0), make_out(r, UINT64_MAX)};
        if (g_quick) goods.resize(1);
        for (size_t i = 0; i < goods.size(); i++)
            rec("valid:" + std::to_string(i), goods[i].esk, goods[i].k.d, goods[i].k.pkd, goods[i].rcm, goods[i].value);
        OutIn& o = goods[0];
        for (auto& m : fs_mutations(o.esk)) {
            if (g_quick && m.first == "=r-1") continue;
            rec("mut:esk" + m.first, m.second, o.k.d, o.k.pkd, o.rcm, o.value);
        }
        for (auto& m : point_mutations(o.k.pkd)) {
            bool proves = false;
            JP p;
            if (jdec(m.second, p) && jprime(p)) proves = true;  // accepted points go on to proving
            if (g_quick && proves) continue;
            rec("mut:pk_d:" + m.first, o.esk, o.k.d, m.second, o.rcm, o.value);
        }
        for (auto& m : fs_mutations(o.rcm)) {
            if (g_quick && m.first == "=r-1") continue;
            rec("mut:rcm" + m.first, o.esk, o.k.d, o.k.pkd, m.second, o.value);
        }
        if (!g_quick) {
            rec("prove:d_invalid", o.esk, invalid_d(r), o.k.pkd, o.rcm, o.value);
            rec("prove:d_other_valid", o.esk, valid_d(r), o.k.pkd, o.rcm, o.value);
        }
        finish(g);
    }
}

// Prove bundles: spends, outputs, spend sigs and the binding signature in one
// proving ctx, then Rust's own verification of the whole bundle.
struct PBundle {
    std::string label;
    std::vector<SpendIn> sp;
    std::vector<OutIn> out;
    std::vector<int> fail_spend;  // indices whose ak is replaced by an off-curve encoding (spend_proof F)
    int64_t vb;
    B sighash;
};

static void gen_binding_bundles()
{
    Golden g("sapling_binding_sig.golden", "librustzcash_sapling_binding_sig (+ prove bundles)",
             "", "",
             "Bundle file. Steps share one proving ctx (init ... free), see FORMAT.md 'Prove bundles':\n"
             "  PS ak nsk d rcm ar value anchor witness | verdict cv rk zkproof\n"
             "  PO esk d pk_d rcm value | verdict cv zkproof\n"
             "  SS ask ar sighash | verdict spend_auth_sig\n"
             "  PB valueBalance:i64 sighash | verdict binding_sig\n"
             "  V  rust_final_verdict  (Rust check_spend/check_output/final_check over the produced bundle;\n"
             "     '-' when a step failed). nf/cm/epk for verification are in sapling_final_check.golden\n"
             "     bundles labelled rustmade:<label>.\n"
             "binding_sig is NONDETERMINISTIC; F results (bad valueBalance, INT64_MIN) are deterministic.");
    DRng r("binding_sig");
    std::vector<PBundle> bs;
    auto mk = [&](const std::string& label, int nsp, int nout, bool empty_sib) {
        PBundle b;
        b.label = label;
        int64_t sum = 0;
        for (int i = 0; i < nsp; i++) {
            uint64_t v = 1000 + r.below(1000000);
            b.sp.push_back(make_spend(r, v, empty_sib ? (uint64_t)i : (r.u64() & 0xffffffffULL), empty_sib));
            sum += (int64_t)v;
        }
        for (int i = 0; i < nout; i++) {
            uint64_t v = 500 + r.below(1000);
            b.out.push_back(make_out(r, v));
            sum -= (int64_t)v;
        }
        b.vb = sum;
        b.sighash = r.bytes(32);
        for (auto& s : b.sp) s.sighash = b.sighash;
        return b;
    };
    bs.push_back(mk("1s1o", 1, 1, true));
    if (!g_quick) {
        bs.push_back(mk("2s2o", 2, 2, false));
        bs.push_back(mk("1s0o", 1, 0, false));
        bs.push_back(mk("0s1o", 0, 1, false));
        bs.push_back(mk("0s0o", 0, 0, false));
        PBundle x = mk("vb+1", 1, 1, false);
        x.vb += 1;
        bs.push_back(x);
        x = mk("vb-1", 1, 1, false);
        x.vb -= 1;
        bs.push_back(x);
        x = mk("vb=INT64_MIN", 1, 1, false);
        x.vb = INT64_MIN;
        bs.push_back(x);
        x = mk("0s0o:vb=5", 0, 0, false);
        x.vb = 5;
        bs.push_back(x);
        x = mk("0s0o:vb=INT64_MIN", 0, 0, false);
        x.vb = INT64_MIN;
        bs.push_back(x);
        x = mk("failed_spend_then_bind", 2, 1, false);
        x.fail_spend.push_back(1);
        x.vb -= (int64_t)x.sp[1].value;
        bs.push_back(x);
    }
    for (auto& b : bs) {
        // Expected step list for the parent to compose lines.
        Iso res = isolate([&](int fd) {
            void* ctx = librustzcash_sapling_proving_ctx_init();
            std::vector<B> cvs, rks, prs;
            bool allok = true;
            for (size_t i = 0; i < b.sp.size(); i++) {
                auto& s = b.sp[i];
                B ak = s.k.ak;
                if (std::find(b.fail_spend.begin(), b.fail_spend.end(), (int)i) != b.fail_spend.end()) ak = OFFCURVE_ENC;
                B cv(32), rk(32), pr(192);
                bool ok = librustzcash_sapling_spend_proof(ctx, ak.data(), s.k.nsk.data(), s.k.d.data(), s.rcm.data(), s.ar.data(),
                                                           s.value, s.anchor.data(), s.witness.data(), cv.data(), rk.data(), pr.data());
                allok = allok && ok;
                emit(fd, ok ? "T " + hx(cv) + " " + hx(rk) + " " + hx(pr) + "\n" : std::string("F - - -\n"));
                cvs.push_back(cv);
                rks.push_back(rk);
                prs.push_back(pr);
            }
            std::vector<B> ocv, opr;
            for (auto& o : b.out) {
                B cv(32), pr(192);
                bool ok = librustzcash_sapling_output_proof(ctx, o.esk.data(), o.k.d.data(), o.k.pkd.data(), o.rcm.data(), o.value,
                                                            cv.data(), pr.data());
                allok = allok && ok;
                emit(fd, ok ? "T " + hx(cv) + " " + hx(pr) + "\n" : std::string("F - -\n"));
                ocv.push_back(cv);
                opr.push_back(pr);
            }
            std::vector<B> sigs;
            for (auto& s : b.sp) {
                B sig(64);
                bool ok = librustzcash_sapling_spend_sig(s.k.ask.data(), s.ar.data(), b.sighash.data(), sig.data());
                allok = allok && ok;
                emit(fd, ok ? "T " + hx(sig) + "\n" : std::string("F -\n"));
                sigs.push_back(sig);
            }
            B bsig(64);
            bool bok = librustzcash_sapling_binding_sig(ctx, b.vb, b.sighash.data(), bsig.data());
            emit(fd, bok ? "T " + hx(bsig) + "\n" : std::string("F -\n"));
            librustzcash_sapling_proving_ctx_free(ctx);
            if (!allok || !bok) {
                emit(fd, "-\n");
                return;
            }
            void* v = librustzcash_sapling_verification_ctx_init();
            bool vok = true;
            for (size_t i = 0; i < b.sp.size(); i++)
                vok = librustzcash_sapling_check_spend(v, cvs[i].data(), b.sp[i].anchor.data(), b.sp[i].nf.data(), rks[i].data(),
                                                       prs[i].data(), sigs[i].data(), b.sighash.data()) && vok;
            for (size_t i = 0; i < b.out.size(); i++)
                vok = librustzcash_sapling_check_output(v, ocv[i].data(), b.out[i].cm.data(), b.out[i].epk.data(), opr[i].data()) && vok;
            vok = librustzcash_sapling_final_check(v, b.vb, bsig.data(), b.sighash.data()) && vok;
            librustzcash_sapling_verification_ctx_free(v);
            emit(fd, std::string(TF(vok)) + "\n");
        });
        auto lines = split_lines(res.out);
        size_t nsteps = b.sp.size() + b.out.size() + b.sp.size() + 1 + 1;
        g.n++;
        g.line("B " + std::to_string(g.n) + " " + b.label);
        if (res.died) g.comment("abort signal " + std::to_string(res.sig) + ": " + first_line(res.err));
        size_t li = 0;
        auto next = [&](size_t nout) {
            if (li < lines.size()) return lines[li++];
            std::string s = (li == lines.size() && res.died) ? "ABORT" + dashes(nout) : "-" + dashes(nout);
            li++;
            return s;
        };
        BundleV bv;
        bv.label = "rustmade:" + b.label;
        bv.vb = b.vb;
        bv.sighash = b.sighash;
        bool usable = !res.died && lines.size() == nsteps;
        for (size_t i = 0; i < b.sp.size(); i++) {
            auto& s = b.sp[i];
            B ak = s.k.ak;
            if (std::find(b.fail_spend.begin(), b.fail_spend.end(), (int)i) != b.fail_spend.end()) ak = OFFCURVE_ENC;
            std::string out = next(3);
            g.tally(split_ws(out)[0]);
            g.line("PS " + ps_ins(ak, s.k.nsk, s.k.d, s.rcm, s.ar, s.value, s.anchor, s.witness) + " " + out);
            auto t = split_ws(out);
            if (t[0] == "T") bv.sp.push_back(SV{unhex(t[1]), s.anchor, s.nf, unhex(t[2]), unhex(t[3]), B(), b.sighash});
            else usable = false;
        }
        for (auto& o : b.out) {
            std::string out = next(2);
            g.tally(split_ws(out)[0]);
            g.line("PO " + po_ins(o.esk, o.k.d, o.k.pkd, o.rcm, o.value) + " " + out);
            auto t = split_ws(out);
            if (t[0] == "T") bv.out.push_back(OV{unhex(t[1]), o.cm, o.epk, unhex(t[2])});
            else usable = false;
        }
        for (size_t i = 0; i < b.sp.size(); i++) {
            std::string out = next(1);
            g.tally(split_ws(out)[0]);
            g.line("SS " + hx(b.sp[i].k.ask) + " " + hx(b.sp[i].ar) + " " + hx(b.sighash) + " " + out);
            auto t = split_ws(out);
            if (t[0] == "T" && i < bv.sp.size()) bv.sp[i].sig = unhex(t[1]);
        }
        std::string out = next(1);
        g.tally(split_ws(out)[0]);
        g.line("PB " + i64s(b.vb) + " " + hx(b.sighash) + " " + out);
        auto t = split_ws(out);
        if (t[0] == "T") bv.bsig = unhex(t[1]);
        else usable = false;
        std::string v = next(0);
        g.tally(split_ws(v)[0]);
        g.line("V " + v);
        g.line("E " + std::to_string(g.n));
        if (usable && v == "T") g_rustmade.push_back(bv);
        else if (usable) die("Rust rejected its own bundle %s", b.label.c_str());
    }
    finish(g);
    if (g_rustmade.empty()) die("no Rust-made bundle");
}

// Sprout Groth16 proving.
struct SproutIn {
    std::string label;
    B phi, rt, hsig;
    B in_sk[2], in_rho[2], in_r[2], in_auth[2];
    uint64_t in_v[2];
    B out_pk[2], out_r[2];
    uint64_t out_v[2];
    uint64_t vpub_old, vpub_new;
};
struct SproutV {
    std::string label;
    B proof, rt, hsig, mac1, mac2, nf1, nf2, cm1, cm2;
    uint64_t vpub_old, vpub_new;
};
static std::vector<SproutV> g_sprout_rustmade;

static B sprout_auth(const std::vector<B>& sib, uint64_t pos)
{
    B w;
    w.push_back(29);
    for (int d = 28; d >= 0; d--) {
        w.push_back(32);
        w.insert(w.end(), sib[d].begin(), sib[d].end());
    }
    B p = le64(pos);
    w.insert(w.end(), p.begin(), p.end());
    if (w.size() != 1 + 33 * 29 + 8) die("sprout auth size");
    return w;
}

static void gen_sprout_prove()
{
    Golden g("sprout_prove.golden", "librustzcash_sprout_prove",
             "phi:hex32 rt:hex32 h_sig:hex32 in_sk1:hex32 in_value1:u64 in_rho1:hex32 in_r1:hex32 in_auth1:hex966 "
             "in_sk2:hex32 in_value2:u64 in_rho2:hex32 in_r2:hex32 in_auth2:hex966 out_pk1:hex32 out_value1:u64 "
             "out_r1:hex32 out_pk2:hex32 out_value2:u64 out_r2:hex32 vpub_old:u64 vpub_new:u64",
             "proof:hex192 | derived nf1 nf2 mac1 mac2 cm1 cm2 (hex32 each) rust_sprout_verify:bool",
             "void; re-reads sprout-groth16.params per call. in_auth = 29, then 29 x (0x20, sibling) root level\n"
             "first, then u64 LE position (asserted: ABORT on bad lengths). NONDETERMINISTIC proof; the derived\n"
             "public inputs are computed with src/zcash/prf.cpp and Note.cpp rules and checked by Rust sprout_verify.");
    DRng r("sprout_prove");
    auto ask252 = [&]() {
        B a = r.bytes(32);
        a[0] &= 0x0f;
        return a;
    };
    auto mk = [&](const std::string& label, uint64_t in1, bool valid_path, uint64_t out1, uint64_t out2, uint64_t vold,
                  uint64_t vnew) {
        SproutIn s;
        s.label = label;
        s.phi = ask252();
        s.hsig = r.bytes(32);
        std::vector<B> sib(29);
        for (auto& x : sib) x = r.bytes(32);
        uint64_t pos = r.u64() & 0x1fffffffULL;
        for (int i = 0; i < 2; i++) {
            s.in_sk[i] = ask252();
            s.in_rho[i] = r.bytes(32);
            s.in_r[i] = r.bytes(32);
            s.in_v[i] = (i == 0) ? in1 : 0;
            s.out_pk[i] = r.bytes(32);
            s.out_r[i] = r.bytes(32);
            s.out_v[i] = (i == 0) ? out1 : out2;
        }
        B cm0 = sprout_cm(sprout_apk(s.in_sk[0]), s.in_v[0], s.in_rho[0], s.in_r[0]);
        B node = cm0;
        for (size_t d = 0; d < 29; d++) node = ((pos >> d) & 1) ? compress(sib[d], node) : compress(node, sib[d]);
        s.rt = valid_path ? node : r.bytes(32);
        s.in_auth[0] = sprout_auth(sib, pos);
        std::vector<B> sib2(29);
        for (auto& x : sib2) x = r.bytes(32);
        s.in_auth[1] = sprout_auth(sib2, r.u64() & 0x1fffffffULL);
        s.vpub_old = vold;
        s.vpub_new = vnew;
        return s;
    };
    std::vector<SproutIn> cases;
    cases.push_back(mk("valid:zero_inputs_vpub_old", 0, true, 300, 200, 500, 0));
    if (!g_quick) {
        cases.push_back(mk("valid:input_with_path", 1000, true, 600, 300, 0, 100));
        cases.push_back(mk("invalid:input_wrong_rt", 1000, false, 600, 300, 0, 100));
        cases.push_back(mk("invalid:unbalanced", 0, true, 300, 200, 499, 0));
    }
    SproutIn bad = mk("abort:auth_depth28", 0, true, 1, 0, 1, 0);
    bad.in_auth[0][0] = 28;
    cases.push_back(bad);
    bad = mk("abort:auth_inner_len31", 0, true, 1, 0, 1, 0);
    bad.in_auth[1][1] = 31;
    cases.push_back(bad);
    for (auto& s : cases) {
        std::string ins = hx(s.phi) + " " + hx(s.rt) + " " + hx(s.hsig);
        for (int i = 0; i < 2; i++)
            ins += " " + hx(s.in_sk[i]) + " " + u64s(s.in_v[i]) + " " + hx(s.in_rho[i]) + " " + hx(s.in_r[i]) + " " + hx(s.in_auth[i]);
        for (int i = 0; i < 2; i++) ins += " " + hx(s.out_pk[i]) + " " + u64s(s.out_v[i]) + " " + hx(s.out_r[i]);
        ins += " " + u64s(s.vpub_old) + " " + u64s(s.vpub_new);
        B nf1 = sprout_nf(s.in_sk[0], s.in_rho[0]), nf2 = sprout_nf(s.in_sk[1], s.in_rho[1]);
        B mac1 = sprout_mac(s.in_sk[0], 0, s.hsig), mac2 = sprout_mac(s.in_sk[1], 1, s.hsig);
        B cm1 = sprout_cm(s.out_pk[0], s.out_v[0], sprout_rho(s.phi, 0, s.hsig), s.out_r[0]);
        B cm2 = sprout_cm(s.out_pk[1], s.out_v[1], sprout_rho(s.phi, 1, s.hsig), s.out_r[1]);
        std::string derived = hx(nf1) + " " + hx(nf2) + " " + hx(mac1) + " " + hx(mac2) + " " + hx(cm1) + " " + hx(cm2);
        Iso res = isolate([&](int fd) {
            B proof(192);
            librustzcash_sprout_prove(proof.data(), s.phi.data(), s.rt.data(), s.hsig.data(), s.in_sk[0].data(), s.in_v[0],
                                      s.in_rho[0].data(), s.in_r[0].data(), s.in_auth[0].data(), s.in_sk[1].data(), s.in_v[1],
                                      s.in_rho[1].data(), s.in_r[1].data(), s.in_auth[1].data(), s.out_pk[0].data(), s.out_v[0],
                                      s.out_r[0].data(), s.out_pk[1].data(), s.out_v[1], s.out_r[1].data(), s.vpub_old, s.vpub_new);
            bool ok = librustzcash_sprout_verify(proof.data(), s.rt.data(), s.hsig.data(), mac1.data(), mac2.data(), nf1.data(),
                                                 nf2.data(), cm1.data(), cm2.data(), s.vpub_old, s.vpub_new);
            emit(fd, "OK " + hx(proof) + " " + derived + " " + TF(ok));
        });
        if (res.died) {
            g.comment("abort signal " + std::to_string(res.sig) + ": " + first_line(res.err));
            g.rec(s.label, ins, "ABORT" + dashes(8));
            continue;
        }
        g.rec(s.label, ins, res.out);
        auto t = split_ws(res.out);
        bool expect_valid = s.label.rfind("valid:", 0) == 0;
        if (expect_valid && t.back() != "T") die("Rust rejected its own Sprout proof %s", s.label.c_str());
        if (expect_valid)
            g_sprout_rustmade.push_back(SproutV{"rustmade:" + s.label, unhex(t[1]), s.rt, s.hsig, mac1, mac2, nf1, nf2, cm1, cm2,
                                                s.vpub_old, s.vpub_new});
    }
    finish(g);
}

static void gen_ctx_lifecycle()
{
    {
        Golden g("sapling_proving_ctx_init.golden", "librustzcash_sapling_proving_ctx_init", "", "non_null:bool",
                 "Returns a non-NULL ctx {bsk = 0, bvk = identity}. Used by every record of sapling_spend_proof,\n"
                 "sapling_output_proof and sapling_binding_sig.golden; a 0s0o bundle binds with valueBalance 0 (T).");
        single(g, "init", "", 1, [] {
            void* c = librustzcash_sapling_proving_ctx_init();
            bool nn = c != nullptr;
            librustzcash_sapling_proving_ctx_free(c);
            return std::string("OK ") + TF(nn);
        });
        single(g, "init_free_x1000", "", 1, [] {
            bool nn = true;
            for (int i = 0; i < 1000; i++) {
                void* c = librustzcash_sapling_proving_ctx_init();
                nn = nn && c;
                librustzcash_sapling_proving_ctx_free(c);
            }
            return std::string("OK ") + TF(nn);
        });
        finish(g);
    }
    {
        Golden g("sapling_proving_ctx_free.golden", "librustzcash_sapling_proving_ctx_free", "", "",
                 "void; frees a ctx from proving_ctx_init (NULL is undefined behaviour in Rust: not exercised).");
        single(g, "free_fresh", "", 0, [] {
            librustzcash_sapling_proving_ctx_free(librustzcash_sapling_proving_ctx_init());
            return std::string("OK");
        });
        finish(g);
    }
    {
        Golden g("sapling_verification_ctx_init.golden", "librustzcash_sapling_verification_ctx_init", "",
                 "non_null:bool",
                 "Returns a non-NULL ctx {bvk = identity}. Every record of sapling_check_spend, sapling_check_output\n"
                 "and sapling_final_check.golden uses a fresh ctx.");
        single(g, "init", "", 1, [] {
            void* c = librustzcash_sapling_verification_ctx_init();
            bool nn = c != nullptr;
            librustzcash_sapling_verification_ctx_free(c);
            return std::string("OK ") + TF(nn);
        });
        single(g, "empty_ctx_final_vb0_zero_sig", "", 1, [] {
            void* c = librustzcash_sapling_verification_ctx_init();
            B sig(64, 0), sh(32, 0);
            bool ok = librustzcash_sapling_final_check(c, 0, sig.data(), sh.data());
            librustzcash_sapling_verification_ctx_free(c);
            return std::string("OK ") + TF(ok);
        });
        finish(g);
    }
    {
        Golden g("sapling_verification_ctx_free.golden", "librustzcash_sapling_verification_ctx_free", "", "",
                 "void; frees a ctx from verification_ctx_init.");
        single(g, "free_fresh", "", 0, [] {
            librustzcash_sapling_verification_ctx_free(librustzcash_sapling_verification_ctx_init());
            return std::string("OK");
        });
        finish(g);
    }
}

// ---------------------------------------------------------------------------
// Section 4: verification with mutation corpora

static std::string spend_ins(const SV& s)
{
    return hx(s.cv) + " " + hx(s.anchor) + " " + hx(s.nf) + " " + hx(s.rk) + " " + hx(s.proof) + " " + hx(s.sig) + " " + hx(s.sighash);
}
static std::string out_ins(const OV& o) { return hx(o.cv) + " " + hx(o.cm) + " " + hx(o.epk) + " " + hx(o.proof); }

static bool r_check_spend(const SV& s)
{
    void* v = librustzcash_sapling_verification_ctx_init();
    bool ok = librustzcash_sapling_check_spend(v, s.cv.data(), s.anchor.data(), s.nf.data(), s.rk.data(), s.proof.data(),
                                               s.sig.data(), s.sighash.data());
    librustzcash_sapling_verification_ctx_free(v);
    return ok;
}
static bool r_check_output(const OV& o)
{
    void* v = librustzcash_sapling_verification_ctx_init();
    bool ok = librustzcash_sapling_check_output(v, o.cv.data(), o.cm.data(), o.epk.data(), o.proof.data());
    librustzcash_sapling_verification_ctx_free(v);
    return ok;
}

struct VBase {
    std::string label;
    SV s;
};
struct OBase {
    std::string label;
    OV o;
};

static SV testnet_spend()
{
    B b = unhex(
        "8c6cf86bbb83bf0d075e5bd9bb4b5cd56141577be69f032880b11e26aa32aa5ef09fd00899e4b469fb11f38e9d09dc0379f0b11c23b5fe541765f76695120a03f0261d32af5d2a2b1e5c9a04200cd87d574dc42349de9790012ce560406a8a876a1e54cfcdc0eb74998abec2a9778330eeb2a0ac0e41d0c9ed5824fbd0dbf7da930ab299966ce333fd7bc1321dada0817aac5444e02c754069e218746bf879d5f2a20a8b028324fb2c73171e63336686aa5ec2e6e9a08eb18b87c14758c572f4531ccf6b55d09f44beb8b47563be4eff7a52598d80959dd9c9fee5ac4783d8370cb7d55d460053d3e067b5f9fe75ff2722623fb1825fcba5e9593d4205b38d1f502ff03035463043bd393a5ee039ce75a5d54f21b395255df6627ef96751566326f7d4a77d828aa21b1827282829fcbc42aad59cdb521e1a3aaa08b99ea8fe7fff0a04da31a52260fc6daeccd79bb877bdd8506614282258e15b3fe74bf71a93f4be3b770119edf99a317b205eea7d5ab800362b97384273888106c77d633600");
    if (b.size() != 384) die("testnet spend size");
    SV s{sub(b, 0, 32), sub(b, 32, 32), sub(b, 64, 32), sub(b, 96, 32), sub(b, 128, 192), sub(b, 320, 64),
         rev(unhex("2dbf83fe7b88a7cbd80fac0c719483906bb9a0c4fc69071e4780d5f2c76e592c"))};
    return s;
}
static OV testnet_output()
{
    B b = unhex(
        "edd742af18857e5ec2d71d346a7fe2ac97c137339bd5268eea86d32e0ff4f38f76213fa8cfed3347ac4e8572dd88aff395c0c10a59f8b3f49d2bc539ed6c726667e29d4763f914ddd0abf1cdfa84e44de87c233434c7e69b8b5b8f4623c8aa444163425bae5cef842972fed66046c1c6ce65c866ad894d02e6e6dcaae7a962d9f2ef95757a09c486928e61f0f7aed90ad0a542b0d3dc5fe140dfa7626b9315c77e03b055f19cbacd21a866e46f06c00e0c7792b2a590a611439b510a9aaffcf1073bad23e712a9268b36888e3727033eee2ab4d869f54a843f93b36ef489fb177bf74b41a9644e5d2a0a417c6ac1c8869bc9b83273d453f878ed6fd96b82a5939903f7b64ecaf68ea16e255a7fb7cc0b6d8b5608a1c6b0ed3024cc62c2f0f9c5cfc7b431ae6e9d40815557aa1d010523f9e1960de77b2274cb6710d229d475c87ae900183206ba90cb5bbc8ec0df98341b82726c705e0308ca5dc08db4db609993a1046dfb43dfd8c760be506c0bed799bb2205fc29dc2e654dce731034a23b0aaf6da0199248702ee0523c159f41f4cbfff6c35ace4dd9ae834e44e09c76a0cbdda1d3f6a2c75ad71212daf9575ab5f09ca148718e667f29ddf18c8a330a86ace18a86e89454653902aa393c84c6b694f27d0d42e24e7ac9fe34733de5ec15f5066081ce912c62c1a804a2bb4dedcef7cc80274f6bb9e89e2fce91dc50d6a73c8aefb9872f1cf3524a92626a0b8f39bbf7bf7d96ca2f770fc04d7f457021c536a506a187a93b2245471ddbfb254a71bc4a0d72c8d639a31c7b1920087ffca05c24214157e2e7b28184e91989ef0b14f9b34c3dc3cc0ac64226b9e337095870cb0885737992e120346e630a416a9b217679ce5a778fb15779c136bcecca5efe79012013d77d90b4e99dd22c8f35bc77121716e160d05bd30d288ee8886390ee436f85bdc9029df888a3a3326d9d4ddba5cb5318b3274928829d662e96fea1d601f7a306251ed8c6cc4e5a3a7a98c35a3650482a0eee08f3b4c2da9b22947c96138f1505c2f081f8972d429f3871f32bef4aaa51aa6945df8e9c9760531ac6f627d17c1518202818a91ca304fb4037875c666060597976144fcbbc48a776a2c61beb9515fa8f3ae6d3a041d320a38a8ac75cb47bb9c866ee497fc3cd13299970c4b369c1c2ceb4220af082fbecdd8114492a8e4d713b5a73396fd224b36c1185bd5e20d683e6c8db35346c47ae7401988255da7cfffdced5801067d4d296688ee8fe424b4a8a69309ce257eefb9345ebfda3f6de46bb11ec94133e1f72cd7ac54934d6cf17b3440800e70b80ebc7c7bfc6fb0fc2c");
    if (b.size() != 948) die("testnet output size");
    return OV{sub(b, 0, 32), sub(b, 32, 32), sub(b, 64, 32), sub(b, 756, 192)};
}

static void gen_check_spend(const std::vector<VBase>& bases)
{
    Golden g("sapling_check_spend.golden", "librustzcash_sapling_check_spend",
             "cv:hex32 anchor:hex32 nf:hex32 rk:hex32 zkproof:hex192 spend_auth_sig:hex64 sighash:hex32", "",
             "bool; fresh verification ctx per record. Bases: testnet spend (src/zcbenchmarks.cpp), mainnet\n"
             "spends (inputs/mainnet_sapling_txs.txt, sighash = ZIP-243 SIGHASH_ALL for the block's branch), and\n"
             "Rust-made spends. Base 0 has every bit of every field flipped.");
    DRng r("check_spend");
    auto rec = [&](const std::string& l, const SV& s) {
        single(g, l, spend_ins(s), 0, [&] { return std::string(TF(r_check_spend(s))); });
    };
    for (size_t bi = 0; bi < bases.size(); bi++) {
        SV s = bases[bi].s;
        const std::string L = bases[bi].label;
        rec(L, s);
        bool full = (bi == 0);
        if (g_quick && bi > 1) continue;
        bitflips({{"cv", &s.cv}, {"anchor", &s.anchor}, {"nf", &s.nf}, {"rk", &s.rk}, {"zkproof", &s.proof},
                  {"sig", &s.sig}, {"sighash", &s.sighash}},
                 full && !g_quick, r, [&](const std::string& m) { rec(L + ":" + m, s); });
        bool structured = bi < 4 || (bi % 3 == 0);
        if (!structured) continue;
        auto with = [&](B SV::*f, const Muts& ms, const std::string& fname) {
            for (auto& m : ms) {
                SV t = s;
                t.*f = m.second;
                rec(L + ":mut:" + fname + ":" + m.first, t);
            }
        };
        with(&SV::cv, point_mutations(s.cv), "cv");
        with(&SV::rk, point_mutations(s.rk), "rk");
        with(&SV::anchor, fr_mutations(s.anchor), "anchor");
        with(&SV::proof, proof_mutations(s.proof), "zkproof");
        with(&SV::sig, sig_mutations(s.sig), "sig");
    }
    finish(g);
}

static void gen_check_output(const std::vector<OBase>& bases)
{
    Golden g("sapling_check_output.golden", "librustzcash_sapling_check_output", "cv:hex32 cm:hex32 epk:hex32 zkproof:hex192",
             "", "bool; fresh verification ctx per record. Base 0 (testnet output) has every bit flipped.");
    DRng r("check_output");
    auto rec = [&](const std::string& l, const OV& o) {
        single(g, l, out_ins(o), 0, [&] { return std::string(TF(r_check_output(o))); });
    };
    for (size_t bi = 0; bi < bases.size(); bi++) {
        OV o = bases[bi].o;
        const std::string L = bases[bi].label;
        rec(L, o);
        if (g_quick && bi > 1) continue;
        bitflips({{"cv", &o.cv}, {"cm", &o.cm}, {"epk", &o.epk}, {"zkproof", &o.proof}}, bi == 0 && !g_quick, r,
                 [&](const std::string& m) { rec(L + ":" + m, o); });
        bool structured = bi < 4 || (bi % 3 == 0);
        if (!structured) continue;
        auto with = [&](B OV::*f, const Muts& ms, const std::string& fname) {
            for (auto& m : ms) {
                OV t = o;
                t.*f = m.second;
                rec(L + ":mut:" + fname + ":" + m.first, t);
            }
        };
        with(&OV::cv, point_mutations(o.cv), "cv");
        with(&OV::epk, point_mutations(o.epk), "epk");
        with(&OV::cm, fr_mutations(o.cm), "cm");
        with(&OV::proof, proof_mutations(o.proof), "zkproof");
    }
    finish(g);
}

// Verification bundles: S/O steps then F, one ctx.
struct VStep {
    char kind;  // 'S' or 'O'
    SV s;
    OV o;
};
struct VBundle {
    std::string label;
    std::vector<VStep> steps;
    bool has_final;
    int64_t vb;
    B bsig, sighash;
};

static VBundle to_vbundle(const BundleV& b)
{
    VBundle v;
    v.label = b.label;
    for (auto& s : b.sp) v.steps.push_back(VStep{'S', s, OV()});
    for (auto& o : b.out) v.steps.push_back(VStep{'O', SV(), o});
    v.has_final = true;
    v.vb = b.vb;
    v.bsig = b.bsig;
    v.sighash = b.sighash;
    return v;
}

static void run_vbundle(Golden& g, const VBundle& b)
{
    Iso res = isolate([&](int fd) {
        void* v = librustzcash_sapling_verification_ctx_init();
        for (auto& st : b.steps) {
            bool ok = st.kind == 'S'
                          ? librustzcash_sapling_check_spend(v, st.s.cv.data(), st.s.anchor.data(), st.s.nf.data(), st.s.rk.data(),
                                                             st.s.proof.data(), st.s.sig.data(), st.s.sighash.data())
                          : librustzcash_sapling_check_output(v, st.o.cv.data(), st.o.cm.data(), st.o.epk.data(), st.o.proof.data());
            emit(fd, std::string(TF(ok)) + "\n");
        }
        if (b.has_final) {
            bool ok = librustzcash_sapling_final_check(v, b.vb, b.bsig.data(), b.sighash.data());
            emit(fd, std::string(TF(ok)) + "\n");
        }
        librustzcash_sapling_verification_ctx_free(v);
    });
    auto lines = split_lines(res.out);
    g.n++;
    g.line("B " + std::to_string(g.n) + " " + b.label);
    if (res.died) g.comment("abort signal " + std::to_string(res.sig) + ": " + first_line(res.err));
    size_t li = 0;
    auto verdict = [&]() {
        std::string s;
        if (li < lines.size()) s = lines[li];
        else s = (li == lines.size() && res.died) ? "ABORT" : "-";
        li++;
        g.tally(s);
        return s;
    };
    for (auto& st : b.steps) {
        if (st.kind == 'S') g.line("S " + spend_ins(st.s) + " " + verdict());
        else g.line("O " + out_ins(st.o) + " " + verdict());
    }
    if (b.has_final) g.line("F " + i64s(b.vb) + " " + hx(b.bsig) + " " + hx(b.sighash) + " " + verdict());
    g.line("E " + std::to_string(g.n));
}

static std::vector<VBundle> g_mainnet_vb;

static void gen_final_check()
{
    Golden g("sapling_final_check.golden", "librustzcash_sapling_final_check (+ verification bundles)", "", "",
             "Bundle file, one verification ctx per bundle (init ... free), see FORMAT.md 'Verification bundles':\n"
             "  S cv anchor nf rk zkproof spend_auth_sig sighash verdict   (check_spend)\n"
             "  O cv cm epk zkproof verdict                                 (check_output)\n"
             "  F valueBalance:i64 binding_sig sighash verdict              (final_check)\n"
             "Every step runs even after an earlier F (ctx mutations before a failing check are part of the\n"
             "contract, e.g. check_spend adds cv to bvk before testing the anchor).");
    std::vector<VBundle> bases = g_mainnet_vb;
    for (auto& b : g_rustmade) bases.push_back(to_vbundle(b));
    for (auto& b : bases) run_vbundle(g, b);
    DRng r("final_check");
    // Mutations on the first Rust-made bundle (1 spend + 1 output) and the first mainnet tx with outputs.
    std::vector<VBundle> mbases;
    mbases.push_back(to_vbundle(g_rustmade[0]));
    for (auto& b : g_mainnet_vb) {
        bool hs = false, ho = false;
        for (auto& st : b.steps) (st.kind == 'S' ? hs : ho) = true;
        if (hs && ho) {
            mbases.push_back(b);
            break;
        }
    }
    for (size_t bi = 0; bi < mbases.size(); bi++) {
        const VBundle& base = mbases[bi];
        auto var = [&](const std::string& name, const std::function<void(VBundle&)>& f) {
            VBundle v = base;
            v.label = base.label + ":" + name;
            f(v);
            run_vbundle(g, v);
        };
        for (int64_t d : {(int64_t)1, (int64_t)-1}) var("vb" + std::string(d > 0 ? "+1" : "-1"), [&](VBundle& v) { v.vb += d; });
        var("vb=INT64_MIN", [](VBundle& v) { v.vb = INT64_MIN; });
        var("vb=INT64_MAX", [](VBundle& v) { v.vb = INT64_MAX; });
        var("vb=-vb", [](VBundle& v) { v.vb = (v.vb == INT64_MIN) ? 0 : -v.vb; });
        for (auto& m : sig_mutations(base.bsig)) var("bsig:" + m.first, [&](VBundle& v) { v.bsig = m.second; });
        B tmp = base.bsig;
        bitflips({{"bsig", &tmp}}, bi == 0 && !g_quick, r, [&](const std::string& m) { var(m, [&](VBundle& v) { v.bsig = tmp; }); });
        tmp = base.sighash;
        bitflips({{"final_sighash", &tmp}}, bi == 0 && !g_quick, r, [&](const std::string& m) { var(m, [&](VBundle& v) { v.sighash = tmp; }); });
        var("no_final", [](VBundle& v) { v.has_final = false; });
        var("drop_last_step", [](VBundle& v) { v.steps.pop_back(); });
        var("drop_first_step", [](VBundle& v) { v.steps.erase(v.steps.begin()); });
        var("reverse_steps", [](VBundle& v) { std::reverse(v.steps.begin(), v.steps.end()); });
        var("duplicate_last_step", [](VBundle& v) { v.steps.push_back(v.steps.back()); });
        // A spend that fails after the bvk update (anchor >= q) still contributes cv.
        var("spend_anchor+q_still_accumulates", [](VBundle& v) {
            for (auto& st : v.steps)
                if (st.kind == 'S') {
                    st.s.anchor = z2le(le2z(st.s.anchor) + Q, 32);
                    break;
                }
        });
        // A spend that fails before the bvk update (small-order cv).
        var("spend_cv_small_order", [](VBundle& v) {
            for (auto& st : v.steps)
                if (st.kind == 'S') {
                    st.s.cv = jenc(TOR[4]);
                    break;
                }
        });
        var("spend_bad_proof_still_accumulates", [](VBundle& v) {
            for (auto& st : v.steps)
                if (st.kind == 'S') {
                    st.s.proof[100] ^= 1;
                    break;
                }
        });
        var("output_cm+q_still_accumulates", [](VBundle& v) {
            for (auto& st : v.steps)
                if (st.kind == 'O') {
                    st.o.cm = z2le(le2z(st.o.cm) + Q, 32);
                    break;
                }
        });
        var("output_cv_mixed_order", [](VBundle& v) {
            for (auto& st : v.steps)
                if (st.kind == 'O') {
                    JP p;
                    if (jdec(st.o.cv, p)) st.o.cv = jenc(jadd(p, TOR[1]));
                    break;
                }
        });
    }
    finish(g);
}

static void gen_sprout_verify(const std::vector<Tx>& sprout_txs)
{
    Golden g("sprout_verify.golden", "librustzcash_sprout_verify",
             "zkproof:hex192 rt:hex32 h_sig:hex32 mac1:hex32 mac2:hex32 nf1:hex32 nf2:hex32 cm1:hex32 cm2:hex32 "
             "vpub_old:u64 vpub_new:u64",
             "",
             "bool; Groth16 JoinSplit verification. Bases: every JoinSplit of mainnet txs at heights 476970 and\n"
             "478544 (inputs/mainnet_sprout_txs.txt, from Z23 fixtures), h_sig = BLAKE2b-256('ZcashComputehSig',\n"
             "randomSeed||nf1||nf2||joinSplitPubKey); plus Rust-made proofs. Base 0 has every bit of zkproof and rt\n"
             "flipped and one bit per byte of the other 32-byte inputs.");
    struct SB {
        std::string label;
        SproutV v;
    };
    std::vector<SB> bases;
    for (auto& t : sprout_txs)
        for (size_t i = 0; i < t.js.size(); i++) {
            auto& j = t.js[i];
            SproutV v{"", j.proof, j.anchor, sprout_hsig(j.seed, j.nf1, j.nf2, t.jspk), j.mac1, j.mac2, j.nf1, j.nf2, j.cm1, j.cm2,
                      j.vpub_old, j.vpub_new};
            bases.push_back(SB{"mainnet:h" + std::to_string(t.height) + ":" + t.txid.substr(0, 16) + ":js" + std::to_string(i), v});
        }
    for (auto& v : g_sprout_rustmade) bases.push_back(SB{v.label, v});
    auto call = [](const SproutV& v) {
        return std::string(TF(librustzcash_sprout_verify(v.proof.data(), v.rt.data(), v.hsig.data(), v.mac1.data(), v.mac2.data(),
                                                         v.nf1.data(), v.nf2.data(), v.cm1.data(), v.cm2.data(), v.vpub_old,
                                                         v.vpub_new)));
    };
    auto ins = [](const SproutV& v) {
        return hx(v.proof) + " " + hx(v.rt) + " " + hx(v.hsig) + " " + hx(v.mac1) + " " + hx(v.mac2) + " " + hx(v.nf1) + " " +
               hx(v.nf2) + " " + hx(v.cm1) + " " + hx(v.cm2) + " " + u64s(v.vpub_old) + " " + u64s(v.vpub_new);
    };
    auto rec = [&](const std::string& l, const SproutV& v) { single(g, l, ins(v), 0, [&] { return call(v); }); };
    DRng r("sprout_verify");
    for (size_t bi = 0; bi < bases.size(); bi++) {
        SproutV v = bases[bi].v;
        const std::string L = bases[bi].label;
        if (call(v) != "T") die("Rust rejects base %s (h_sig or parse error?)", L.c_str());
        rec(L, v);
        if (g_quick && bi > 1) continue;
        bool mut = bi < 3 || bi % 10 == 0 || L.rfind("rustmade", 0) == 0;
        if (!mut) continue;
        // Base 0: every bit of the proof and the anchor, one bit per byte of the hashed inputs.
        bitflips({{"zkproof", &v.proof}, {"rt", &v.rt}}, (bi == 0 && !g_quick) ? 1 : 0, r,
                 [&](const std::string& m) { rec(L + ":" + m, v); });
        bitflips({{"h_sig", &v.hsig}, {"mac1", &v.mac1}, {"mac2", &v.mac2}, {"nf1", &v.nf1}, {"nf2", &v.nf2},
                  {"cm1", &v.cm1}, {"cm2", &v.cm2}},
                 (bi == 0 && !g_quick) ? 2 : 0, r, [&](const std::string& m) { rec(L + ":" + m, v); });
        for (auto& m : proof_mutations(v.proof)) {
            SproutV t = v;
            t.proof = m.second;
            rec(L + ":mut:zkproof:" + m.first, t);
        }
        for (int k = 0; k < 2; k++) {
            uint64_t SproutV::*f = k ? &SproutV::vpub_new : &SproutV::vpub_old;
            const char* fn = k ? "vpub_new" : "vpub_old";
            for (uint64_t nv : {(uint64_t)(v.*f + 1), (uint64_t)(v.*f - 1), (uint64_t)UINT64_MAX, (uint64_t)(v.*f ^ ((uint64_t)1 << 63))}) {
                SproutV t = v;
                t.*f = nv;
                rec(L + ":mut:" + fn + ":" + u64s(nv), t);
            }
        }
    }
    finish(g);
}

// ---------------------------------------------------------------------------

static void write_manifest()
{
    std::string path = g_out_dir + "/MANIFEST.tsv";
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) die("cannot create %s", path.c_str());
    fprintf(f, "# file\trecords\tT\tF\tOK\tABORT\tbytes\tsha256\n");
    unsigned long long total = 0;
    for (auto& s : g_summary) {
        std::string data = read_file(g_out_dir + "/" + s.file);
        uint8_t h[32];
        crypto_hash_sha256(h, (const uint8_t*)data.data(), data.size());
        fprintf(f, "%s\t%u\t%u\t%u\t%u\t%u\t%zu\t%s\n", s.file.c_str(), s.n, s.nT, s.nF, s.nOK, s.nAB, data.size(),
                hx(h, 32).c_str());
        total += data.size();
    }
    fprintf(f, "# total bytes %llu\n", total);
    if (fclose(f) != 0) die("close manifest");
    note("total golden bytes %llu, forks %lu", total, g_forks);
}

int main(int argc, char** argv)
{
    std::string sapling_txs, sprout_txs;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto val = [&]() -> std::string {
            if (i + 1 >= argc) die("missing value for %s", a.c_str());
            return argv[++i];
        };
        if (a == "--src") g_src = val();
        else if (a == "--params") g_params = val();
        else if (a == "--out") g_out_dir = val();
        else if (a == "--sapling-txs") sapling_txs = val();
        else if (a == "--sprout-txs") sprout_txs = val();
        else if (a == "--quick") g_quick = true;
        else die("unknown argument %s", a.c_str());
    }
    if (g_src.empty() || g_params.empty() || g_out_dir.empty() || sapling_txs.empty() || sprout_txs.empty())
        die("usage: gen_golden --src <zclassicd>/src --params <dir> --out <dir> --sapling-txs <f> --sprout-txs <f> [--quick]");
    if (sodium_init() < 0) die("sodium_init failed");
    if (g_quick) NRAND = 40;
    if (mkdir(g_out_dir.c_str(), 0755) != 0 && errno != EEXIST) die("mkdir %s: %s", g_out_dir.c_str(), strerror(errno));
    time_t t0 = time(nullptr);

    init_math();
    g_keyrows.clear();
    for (auto& row : json_rows(read_file(g_src + "/test/data/sapling_key_components.json")))
        if (row.size() == 14) g_keyrows.push_back(row);
    if (g_keyrows.size() != 10) die("expected 10 key component rows, got %zu", g_keyrows.size());

    // Section 1 (no parameters).
    gen_to_scalar();
    gen_fixed_mult("ask_to_ak.golden", "librustzcash_ask_to_ak", 1, 4, false);
    gen_fixed_mult("nsk_to_nk.golden", "librustzcash_nsk_to_nk", 2, 5, true);
    gen_crh_ivk();
    gen_check_diversifier();
    gen_ivk_to_pkd();
    gen_tree();
    gen_note_fns();
    gen_ka();
    gen_generate_r();
    gen_spend_sig();
    gen_zip32();
    note("section 1 done in %lds", (long)(time(nullptr) - t0));

    // Section 2: parameters.
    gen_init_params();
    init_params_parent();
    note("parameters loaded at %lds", (long)(time(nullptr) - t0));

    // Real transactions (parsed before proving so a bad input fails early).
    std::vector<Tx> stx = load_txs(sapling_txs), jtx = load_txs(sprout_txs);
    std::vector<VBase> sbases;
    std::vector<OBase> obases;
    sbases.push_back(VBase{"testnet:abbd823c:spend0", testnet_spend()});
    obases.push_back(OBase{"testnet:abbd823c:output0", testnet_output()});
    if (!r_check_spend(sbases[0].s) || !r_check_output(obases[0].o)) die("testnet vectors rejected");
    for (auto& t : stx) {
        VBundle vb;
        vb.label = "mainnet:h" + std::to_string(t.height) + ":" + t.txid.substr(0, 16);
        for (size_t i = 0; i < t.spends.size(); i++) {
            auto& s = t.spends[i];
            SV sv{s.cv, s.anchor, s.nf, s.rk, s.proof, s.sig, t.sighash};
            if (!r_check_spend(sv)) die("mainnet spend %s/%zu rejected (sighash wrong?)", t.txid.c_str(), i);
            sbases.push_back(VBase{vb.label + ":spend" + std::to_string(i), sv});
            vb.steps.push_back(VStep{'S', sv, OV()});
        }
        for (size_t i = 0; i < t.outs.size(); i++) {
            auto& o = t.outs[i];
            OV ov{o.cv, o.cm, o.epk, o.proof};
            if (!r_check_output(ov)) die("mainnet output %s/%zu rejected", t.txid.c_str(), i);
            obases.push_back(OBase{vb.label + ":output" + std::to_string(i), ov});
            vb.steps.push_back(VStep{'O', SV(), ov});
        }
        vb.has_final = true;
        vb.vb = t.vb;
        vb.bsig = t.bsig;
        vb.sighash = t.sighash;
        g_mainnet_vb.push_back(vb);
    }

    // Section 3: proving.
    gen_ctx_lifecycle();
    gen_spend_output_proofs();
    gen_binding_bundles();
    note("Sapling proving done at %lds", (long)(time(nullptr) - t0));
    gen_sprout_prove();
    note("Sprout proving done at %lds", (long)(time(nullptr) - t0));
    for (auto& b : g_rustmade) {
        for (size_t i = 0; i < b.sp.size(); i++) sbases.push_back(VBase{b.label + ":spend" + std::to_string(i), b.sp[i]});
        for (size_t i = 0; i < b.out.size(); i++) obases.push_back(OBase{b.label + ":output" + std::to_string(i), b.out[i]});
    }

    // Section 4: verification corpora.
    gen_check_spend(sbases);
    gen_check_output(obases);
    gen_final_check();
    gen_sprout_verify(jtx);
    write_manifest();
    note("finished in %lds", (long)(time(nullptr) - t0));
    return 0;
}
