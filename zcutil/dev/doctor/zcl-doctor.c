/*
 * zcl-doctor: what does this host lack to build and test zclassicd, and the exact fix for each gap.
 *
 * Builds alone, because it must work where `make` does not:
 *     cc -std=gnu17 -o zcl-doctor zcutil/dev/doctor/zcl-doctor.c
 * Libc only; also builds with x86_64-w64-mingw32-gcc (-D__USE_MINGW_ANSI_STDIO=1) and clang.
 * Modelled on the structure of Z23 tools/dev/z23_doctor.c (run_cmd, find_prog, probes, JSON); written anew, no Z23 text copied.
 *
 * usage: zcl-doctor [--json] [--after=N] [--group=tools|build|host|repo] [--root=DIR]
 *                   [--selftest] [--purpose]
 * Exit: 0 every check ok or advisory, 1 a required check failed, 2 broken invocation or empty scan.
 * Output stays under 16 KiB; when cut, "next_after" gives the --after value that continues it.
 * Environment: CXX and CC pick the compilers like configure; ZCL_DOCTOR_PKGMGR names the package
 * manager used in fix commands (apt-get, dnf, pacman, brew, pacman-msys); ZCL_DOCTOR_MIN_DISK_GIB.
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#include <ctype.h>
#include <errno.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#define POPEN _popen
#define PCLOSE _pclose
#define PATH_SEP ';'
#define EXE_SUFFIX ".exe"
#else
#include <sys/statvfs.h>
#include <sys/wait.h>
#define POPEN popen
#define PCLOSE pclose
#define PATH_SEP ':'
#define EXE_SUFFIX ""
#endif

#define OUT_CAP 15500
#define MAX_CHECKS 96
#define MIN_DISK_GIB_DEFAULT 15

enum status { ST_OK, ST_ADVISORY, ST_FAIL };
static const char *const status_name[] = {"ok", "advisory", "fail"};

struct check {
    char id[32];
    char group[8];
    enum status st;
    char detail[200];
    char fix[240];
};

static struct check checks[MAX_CHECKS];
static int nchecks;
static char root[1024];
static const char *pkgmgr;

/* ---------- small helpers ---------- */

static void add(const char *group, const char *id, enum status st, const char *fix, const char *fmt, ...)
{
    if (nchecks >= MAX_CHECKS) {
        fprintf(stderr, "zcl-doctor: too many checks (%d)\n", MAX_CHECKS);
        exit(2);
    }
    struct check *c = &checks[nchecks++];
    snprintf(c->id, sizeof c->id, "%s", id);
    snprintf(c->group, sizeof c->group, "%s", group);
    c->st = st;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->detail, sizeof c->detail, fmt, ap);
    va_end(ap);
    snprintf(c->fix, sizeof c->fix, "%s", st == ST_OK || !fix ? "" : fix);
}

/* Run a shell command, capture combined output (up to cap-1 bytes); returns exit status, -1 on spawn failure. */
static int run_cmd(const char *cmd, char *out, size_t cap)
{
    size_t n = 0;
    if (out && cap) out[0] = 0;
#ifdef _WIN32
    /* cmd.exe strips the outer quotes of a command that starts and ends with one and holds more; wrap it once. */
    char wrapped[2600];
    snprintf(wrapped, sizeof wrapped, "\"%s\"", cmd);
    FILE *p = POPEN(wrapped, "r");
#else
    FILE *p = POPEN(cmd, "r");
#endif
    if (!p) return -1;
    char buf[512];
    size_t r;
    while ((r = fread(buf, 1, sizeof buf, p)) > 0) {
        if (out && n + 1 < cap) {
            size_t take = r < cap - 1 - n ? r : cap - 1 - n;
            memcpy(out + n, buf, take);
            n += take;
            out[n] = 0;
        }
    }
    int rc = PCLOSE(p);
#ifdef _WIN32
    return rc;
#else
    if (rc == -1) return -1;
    return WIFEXITED(rc) ? WEXITSTATUS(rc) : 128;
#endif
}

static void first_line(char *s, size_t keep)
{
    char *e = strpbrk(s, "\r\n");
    if (e) *e = 0;
    if (strlen(s) > keep) s[keep] = 0;
}

static int is_regular(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int is_dir(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Search PATH for an executable; out gets the full path. */
static int find_prog(const char *name, char *out, size_t cap)
{
    const char *path = getenv("PATH");
    if (!path || !*path) return 0;
    if (strchr(name, '/')) {
        snprintf(out, cap, "%s", name);
        return is_regular(out);
    }
    const char *p = path;
    while (*p) {
        const char *e = strchr(p, PATH_SEP);
        size_t len = e ? (size_t)(e - p) : strlen(p);
        char dir[1024];
        if (len == 0) {
            snprintf(dir, sizeof dir, ".");
        } else {
            if (len >= sizeof dir) len = sizeof dir - 1;
            memcpy(dir, p, len);
            dir[len] = 0;
        }
        snprintf(out, cap, "%s/%s", dir, name);
#ifdef _WIN32
        char with_exe[1100];
        snprintf(with_exe, sizeof with_exe, "%s" EXE_SUFFIX, out);
        if (is_regular(with_exe)) {
            snprintf(out, cap, "%s", with_exe);
            return 1;
        }
        if (is_regular(out)) return 1;
#else
        if (is_regular(out) && access(out, X_OK) == 0) return 1;
#endif
        if (!e) break;
        p = e + 1;
    }
    return 0;
}

static const char *cmd_prefix(void)
{
    if (!pkgmgr) {
        char tmp[1024] = "";
        pkgmgr = getenv("ZCL_DOCTOR_PKGMGR");
        (void)tmp;
        if (!pkgmgr || !*pkgmgr) {
#ifdef _WIN32
            pkgmgr = "pacman-msys";
#elif defined(__APPLE__)
            pkgmgr = "brew";
#else
            pkgmgr = find_prog("apt-get", tmp, sizeof tmp)  ? "apt-get"
                     : find_prog("dnf", tmp, sizeof tmp)    ? "dnf"
                     : find_prog("pacman", tmp, sizeof tmp) ? "pacman"
                                                            : "apt-get";
#endif
        }
    }
    if (!strcmp(pkgmgr, "brew")) return "brew install";
    if (!strcmp(pkgmgr, "dnf")) return "sudo dnf install -y";
    if (!strcmp(pkgmgr, "pacman")) return "sudo pacman -S --needed";
    if (!strcmp(pkgmgr, "pacman-msys")) return "pacman -S --needed";
    return "sudo apt-get install -y";
}

/* Package name for a logical (apt) name under the active package manager. */
static const char *pkg_name(const char *logical)
{
    (void)cmd_prefix(); /* resolves pkgmgr */
    static const struct {
        const char *mgr, *logical, *name;
    } map[] = {
        {"dnf", "g++", "gcc-c++"},
        {"dnf", "pkg-config", "pkgconf-pkg-config"},
        {"dnf", "qtbase5-dev", "qt5-qtbase-devel"},
        {"pacman", "g++", "gcc"},
        {"pacman", "pkg-config", "pkgconf"},
        {"pacman", "qtbase5-dev", "qt5-base"},
        {"pacman-msys", "g++", "gcc"},
        {"pacman-msys", "gcc", "gcc"},
        {"pacman-msys", "pkg-config", "pkgconf"},
        {"pacman-msys", "qtbase5-dev", "mingw-w64-x86_64-qt5-base"},
        {"brew", "g++", "gcc"},
        {"brew", "qtbase5-dev", "qt@5"},
    };
    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++)
        if (!strcmp(map[i].mgr, pkgmgr) && !strcmp(map[i].logical, logical)) return map[i].name;
    return logical;
}

static void install_fix(char *out, size_t cap, const char *pkgs)
{
    snprintf(out, cap, "%s %s", cmd_prefix(), pkg_name(pkgs));
}

static int write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f) return 0;
    int ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok;
}

static char tmpdir_buf[512];
static const char *tmp_dir(void)
{
    const char *t = getenv("TMPDIR");
    if (!t || !*t) t = getenv("TEMP");
    if (!t || !*t) t = "/tmp";
    snprintf(tmpdir_buf, sizeof tmpdir_buf, "%s", t);
    return tmpdir_buf;
}

/* Paths reach sh command lines inside double quotes; accept only a conservative character set. */
static int safe_path(const char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (isalnum(c) || strchr("._/+:@%~ -", c)) continue;
#ifdef _WIN32
        if (c == '\\') continue;
#endif
        return 0;
    }
    return 1;
}

/* Create a private (mode 0700, unpredictable) directory under TMPDIR; no symlink can be pre-planted. */
static int make_private_dir(char *out, size_t cap, const char *prefix)
{
#ifdef _WIN32
    static int seq;
    snprintf(out, cap, "%s/%s-%ld-%d", tmp_dir(), prefix, (long)getpid(), ++seq);
    return mkdir(out) == 0;
#else
    snprintf(out, cap, "%s/%s-XXXXXX", tmp_dir(), prefix);
    return mkdtemp(out) != 0;
#endif
}

/* Does `compiler flags` accept the source text? Writes a probe file under TMPDIR. */
static int probe_compile(const char *compiler, const char *flags, const char *ext, const char *src)
{
    char dir[700], file[800], cmd[1700], out[512];
    if (!make_private_dir(dir, sizeof dir, "zcl-doctor-probe")) return 0;
    snprintf(file, sizeof file, "%s/probe%s", dir, ext);
    int rc = -1;
    if (write_file(file, src)) {
        snprintf(cmd, sizeof cmd, "\"%s\" %s -fsyntax-only \"%s\" 2>&1", compiler, flags, file);
        rc = run_cmd(cmd, out, sizeof out);
    }
    remove(file);
    rmdir(dir);
    return rc == 0;
}

/* ---------- checks ---------- */

static void check_tool(const char *id, const char *const names[], const char *pkgs, const char *why)
{
    char path[1100], cmd[1200], ver[160] = "";
    for (int i = 0; names[i]; i++) {
        if (!find_prog(names[i], path, sizeof path)) continue;
        snprintf(cmd, sizeof cmd, "\"%s\" --version 2>&1", path);
        run_cmd(cmd, ver, sizeof ver);
        first_line(ver, 80);
        add("tools", id, ST_OK, 0, "%s%s%s", names[i], *ver ? ": " : "", ver);
        return;
    }
    char fix[240];
    install_fix(fix, sizeof fix, pkgs);
    add("tools", id, ST_FAIL, fix, "not on PATH (%s)", why);
}

static char cxx_path[1100], cc_path[1100];
static char cxx_name[64], cc_name[64];

static int pick_compiler(const char *envname, const char *const names[], char *path, size_t cap, char *name, size_t ncap)
{
    const char *e = getenv(envname);
    if (e && *e) {
        char word[64];
        snprintf(word, sizeof word, "%s", e);
        char *sp = strchr(word, ' ');
        if (sp) *sp = 0;
        if (find_prog(word, path, cap)) {
            snprintf(name, ncap, "%s", word);
            return 1;
        }
    }
    for (int i = 0; names[i]; i++)
        if (find_prog(names[i], path, cap)) {
            snprintf(name, ncap, "%s", names[i]);
            return 1;
        }
    return 0;
}

static void group_tools(void)
{
    static const char *const cxxn[] = {"g++", "c++", "clang++", 0};
    static const char *const ccn[] = {"cc", "gcc", "clang", 0};
    char fix[240], ver[160] = "", cmd[1200];
    cxx_path[0] = cc_path[0] = 0;
    if (pick_compiler("CXX", cxxn, cxx_path, sizeof cxx_path, cxx_name, sizeof cxx_name)) {
        snprintf(cmd, sizeof cmd, "\"%s\" --version 2>&1", cxx_path);
        run_cmd(cmd, ver, sizeof ver);
        first_line(ver, 80);
        add("tools", "cxx", ST_OK, 0, "%s: %s", cxx_name, ver);
    } else {
        install_fix(fix, sizeof fix, "g++");
        add("tools", "cxx", ST_FAIL, fix, "no C++ compiler (g++, c++, clang++) on PATH");
    }
    ver[0] = 0;
    if (pick_compiler("CC", ccn, cc_path, sizeof cc_path, cc_name, sizeof cc_name)) {
        snprintf(cmd, sizeof cmd, "\"%s\" --version 2>&1", cc_path);
        run_cmd(cmd, ver, sizeof ver);
        first_line(ver, 80);
        add("tools", "cc", ST_OK, 0, "%s: %s", cc_name, ver);
    } else {
        install_fix(fix, sizeof fix, "gcc");
        add("tools", "cc", ST_FAIL, fix, "no C compiler (cc, gcc, clang) on PATH");
    }
    static const char *const make_n[] = {"make", "gmake", 0};
    static const char *const autoconf_n[] = {"autoconf", 0};
    static const char *const automake_n[] = {"automake", 0};
    static const char *const libtool_n[] = {"libtoolize", "glibtoolize", 0};
    static const char *const pkgconf_n[] = {"pkg-config", "pkgconf", 0};
    static const char *const m4_n[] = {"m4", 0};
    static const char *const git_n[] = {"git", 0};
    static const char *const dl_n[] = {"curl", "wget", 0};
    static const char *const patch_n[] = {"patch", 0};
    check_tool("make", make_n, "make", "drives depends and src");
    check_tool("autoconf", autoconf_n, "autoconf", "autogen.sh runs it");
    check_tool("automake", automake_n, "automake", "autogen.sh runs it");
    check_tool("libtool", libtool_n, "libtool", "autogen.sh runs libtoolize");
    check_tool("pkg-config", pkgconf_n, "pkg-config", "configure locates libraries");
    check_tool("m4", m4_n, "m4", "autoconf needs it");
    check_tool("git", git_n, "git", "source control");
    check_tool("curl-or-wget", dl_n, "curl", "depends downloads sources");
    check_tool("patch", patch_n, "patch", "depends applies patches");
}

static void group_build(void)
{
    char fix[240];
    if (cxx_path[0]) {
        int ok = probe_compile(cxx_path, "-std=c++11", ".cpp",
                               "#include <memory>\nint main() { auto p = std::unique_ptr<int>(new int(1)); return *p - 1; }\n");
        if (ok)
            add("build", "cxx11", ST_OK, 0, "%s accepts -std=c++11 (configure.ac AX_CXX_COMPILE_STDCXX([11]))", cxx_name);
        else {
            install_fix(fix, sizeof fix, "g++");
            add("build", "cxx11", ST_FAIL, fix, "%s rejects -std=c++11; install a newer g++ or set CXX", cxx_name);
        }
    } else {
        add("build", "cxx11", ST_FAIL, "install a C++ compiler first (see the cxx check)", "no C++ compiler to probe");
    }
    if (cc_path[0]) {
        /* Mirrors the ZCL_C23_STD probe in configure.ac. */
        static const char c23src[] =
            "#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n#include <time.h>\n"
            "#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202000L\n#error not C23\n#endif\n"
            "static_assert(sizeof(uint64_t) == 8, \"u64\");\n"
            "static bool zcl_probe(const void *p) { return p != nullptr; }\n"
            "constexpr size_t zcl_probe_n = 4;\n"
            "int zcl_probe_main(void)\n{\n    struct timespec ts = {};\n    typeof(ts.tv_sec) s = 0;\n"
            "    char buf = (char)zcl_probe_n;\n    (void)strnlen(&buf, 0);\n    return zcl_probe(&s) ? (int)s : 1;\n}\n";
        if (probe_compile(cc_path, "-std=c23 -D_GNU_SOURCE", ".c", c23src))
            add("build", "c23-std", ST_OK, 0, "%s compiles C23: configure picks -std=c23", cc_name);
        else if (probe_compile(cc_path, "-std=gnu17 -D_GNU_SOURCE", ".c", "int main(void) { return 0; }\n"))
            add("build", "c23-std", ST_ADVISORY, "optional: install gcc 14 or clang 18 for native -std=c23",
                "%s lacks -std=c23: configure falls back to -std=gnu17 (fine)", cc_name);
        else {
            install_fix(fix, sizeof fix, "gcc");
            add("build", "c23-std", ST_FAIL, fix, "%s accepts neither -std=c23 nor -std=gnu17", cc_name);
        }
    } else {
        add("build", "c23-std", ST_FAIL, "install a C compiler first (see the cc check)", "no C compiler to probe");
    }

    /* depends/<triplet> built for this host. */
    char guess[1100], cmd[1300], triplet[160] = "", cfg[1400];
    snprintf(guess, sizeof guess, "%s/depends/config.guess", root);
    if (!is_regular(guess)) {
        add("build", "depends", ST_FAIL, "run from a zclassicd checkout or pass --root=DIR", "no depends/config.guess under %s", root);
    } else {
        snprintf(cmd, sizeof cmd, "sh \"%s\" 2>&1", guess);
        run_cmd(cmd, triplet, sizeof triplet);
        first_line(triplet, 100);
        snprintf(cfg, sizeof cfg, "%s/depends/%s/share/config.site", root, triplet);
        if (*triplet && is_regular(cfg))
            add("build", "depends", ST_OK, 0, "depends/%s built", triplet);
        else {
            char cs[1400];
            snprintf(cs, sizeof cs, "%s/config.status", root);
            snprintf(fix, sizeof fix, "make -C depends HOST=%s -j\"$(nproc)\"", *triplet ? triplet : "<triplet>");
            if (is_regular(cs))
                add("build", "depends", ST_ADVISORY, fix, "depends/%s not built; the tree is configured (config.status present)", *triplet ? triplet : "<triplet>");
            else
                add("build", "depends", ST_FAIL, fix, "depends/%s/share/config.site missing and the tree is not configured", *triplet ? triplet : "<triplet>");
        }
    }

    /* mingw-w64 cross compiler with the posix thread model. */
    char gpp[1100], out[2048];
    if (!find_prog("x86_64-w64-mingw32-g++", gpp, sizeof gpp)) {
        add("build", "mingw", ST_ADVISORY, "sh zcutil/setup-mingw-toolchain.sh", "x86_64-w64-mingw32-g++ not on PATH (only needed for Windows builds)");
    } else {
        snprintf(cmd, sizeof cmd, "\"%s\" -v 2>&1", gpp);
        run_cmd(cmd, out, sizeof out);
        char *tm = strstr(out, "Thread model: ");
        char model[32] = "unknown";
        if (tm) sscanf(tm + 14, "%31s", model);
        if (!strcmp(model, "posix"))
            add("build", "mingw", ST_OK, 0, "x86_64-w64-mingw32-g++ thread model posix");
        else
            add("build", "mingw", ST_ADVISORY, "sh zcutil/setup-mingw-toolchain.sh", "mingw thread model is %s, std::thread needs posix", model);
    }
}

static const char *const params_files[] = {"sprout-proving.key", "sprout-verifying.key", "sapling-spend.params",
                                           "sapling-output.params", "sprout-groth16.params", 0};

static long long avail_bytes(const char *path)
{
#ifdef _WIN32
    ULARGE_INTEGER a;
    if (GetDiskFreeSpaceExA(path, &a, 0, 0)) return (long long)a.QuadPart;
    return -1;
#else
    struct statvfs sv;
    if (statvfs(path, &sv) != 0) return -1;
    return (long long)sv.f_bavail * (long long)sv.f_frsize;
#endif
}

static long long ram_bytes(void)
{
#ifdef _WIN32
    MEMORYSTATUSEX m;
    m.dwLength = sizeof m;
    return GlobalMemoryStatusEx(&m) ? (long long)m.ullTotalPhys : -1;
#elif defined(__APPLE__)
    char out[64];
    if (run_cmd("sysctl -n hw.memsize 2>/dev/null", out, sizeof out) != 0) return -1;
    return atoll(out);
#else
    FILE *f = fopen("/proc/meminfo", "r");
    char line[256];
    long long kb = -1;
    if (!f) return -1;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "MemTotal: %lld kB", &kb) == 1) break;
    fclose(f);
    return kb < 0 ? -1 : kb * 1024;
#endif
}

static int cpu_count(void)
{
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
#endif
}

static void home_path(char *out, size_t cap, const char *rel)
{
    const char *h = getenv("HOME");
    if (!h || !*h) h = getenv("USERPROFILE");
    snprintf(out, cap, "%s/%s", h && *h ? h : ".", rel);
}

static void group_host(void)
{
    char dir[1100], f[1300], fix[240], missing[200] = "";
    int nmiss = 0;
    home_path(dir, sizeof dir, ".zcash-params");
    for (int i = 0; params_files[i]; i++) {
        snprintf(f, sizeof f, "%s/%s", dir, params_files[i]);
        if (!is_regular(f)) {
            nmiss++;
            if (strlen(missing) + strlen(params_files[i]) + 2 < sizeof missing) {
                if (*missing) strcat(missing, ",");
                strcat(missing, params_files[i]);
            }
        }
    }
    if (!nmiss)
        add("host", "params", ST_OK, 0, "all 5 Zcash parameter files in ~/.zcash-params");
    else
        add("host", "params", ST_FAIL, "sh zcutil/fetch-params.sh", "%d of 5 parameter files missing in ~/.zcash-params: %s", nmiss, missing);

    char cc[1100];
    if (find_prog("ccache", cc, sizeof cc))
        add("host", "ccache", ST_OK, 0, "ccache present");
    else {
        install_fix(fix, sizeof fix, "ccache");
        add("host", "ccache", ST_ADVISORY, fix, "ccache not found (rebuilds are slower)");
    }

    const char *mg = getenv("ZCL_DOCTOR_MIN_DISK_GIB");
    long long min_gib = mg && *mg ? atoll(mg) : MIN_DISK_GIB_DEFAULT;
    long long av = avail_bytes(root);
    if (av < 0)
        add("host", "disk", ST_ADVISORY, "check free space with df -h", "cannot read free space under %s", root);
    else if (av / (1LL << 30) >= min_gib)
        add("host", "disk", ST_OK, 0, "%lld GiB free (need %lld)", av / (1LL << 30), min_gib);
    else
        add("host", "disk", ST_FAIL, "free space, or point the build at another disk", "%lld GiB free, need at least %lld", av / (1LL << 30), min_gib);

    long long ram = ram_bytes();
    if (ram < 0)
        add("host", "ram", ST_ADVISORY, 0, "cannot read RAM size");
    else if (ram / (1LL << 30) >= 4)
        add("host", "ram", ST_OK, 0, "%lld GiB RAM", ram / (1LL << 30));
    else
        add("host", "ram", ST_ADVISORY, "build with make -j2, or add swap", "%lld GiB RAM; the C++ build wants 4 or more", ram / (1LL << 30));
    int cores = cpu_count();
    add("host", "cores", ST_OK, 0, "%d cores (make -j%d)", cores, cores);

    /* proot rootfs for local-ci.sh. */
    const char *env = getenv("ZCL_CI_ENV");
    if (env && *env)
        snprintf(dir, sizeof dir, "%s", env);
    else
        home_path(dir, sizeof dir, "work/zc23-localci-env");
    if (is_dir(dir))
        add("host", "local-ci-env", ST_OK, 0, "rootfs %s present", dir);
    else
        add("host", "local-ci-env", ST_ADVISORY, "see the setup notes at the top of zcutil/local-ci.sh",
            "local-ci rootfs %s absent (only zcutil/local-ci.sh needs it)", dir);

    if (find_prog("qmake", cc, sizeof cc))
        add("host", "qmake", ST_OK, 0, "qmake present (wallet GUI)");
    else {
        install_fix(fix, sizeof fix, "qtbase5-dev");
        add("host", "qmake", ST_ADVISORY, fix, "qmake not found (only the Qt wallet needs it)");
    }

#ifdef __APPLE__
    if (run_cmd("xcode-select -p 2>/dev/null", dir, sizeof dir) == 0)
        add("host", "xcode-clt", ST_OK, 0, "Xcode command line tools installed");
    else
        add("host", "xcode-clt", ST_FAIL, "xcode-select --install", "Xcode command line tools missing");
    static const char *const brewpk[] = {"autoconf", "automake", "libtool", "pkg-config", "coreutils", 0};
    for (int i = 0; brewpk[i]; i++) {
        char cmd[200], id[40];
        snprintf(cmd, sizeof cmd, "brew --prefix %s >/dev/null 2>&1", brewpk[i]);
        snprintf(id, sizeof id, "brew-%s", brewpk[i]);
        if (run_cmd(cmd, 0, 0) == 0)
            add("host", id, ST_OK, 0, "brew package %s installed", brewpk[i]);
        else {
            snprintf(fix, sizeof fix, "brew install %s", brewpk[i]);
            add("host", id, ST_FAIL, fix, "brew package %s missing (zcutil/local-ci-macos.sh needs it)", brewpk[i]);
        }
    }
#endif
}

static void group_repo(void)
{
    static const char *const bins[] = {"zcl-dev", "jsonq", "zcl-lint", 0};
    char f[1300], missing[160] = "";
    int nmiss = 0;
    for (int i = 0; bins[i]; i++) {
        snprintf(f, sizeof f, "%s/zcutil/bin/%s%s", root, bins[i], EXE_SUFFIX);
        if (!is_regular(f)) {
            nmiss++;
            if (strlen(missing) + strlen(bins[i]) + 2 < sizeof missing) {
                if (*missing) strcat(missing, ",");
                strcat(missing, bins[i]);
            }
        }
    }
    if (!nmiss)
        add("repo", "zcutil-bin", ST_OK, 0, "zcl-dev, jsonq, zcl-lint built in zcutil/bin");
    else
        add("repo", "zcutil-bin", ST_ADVISORY, "make -C zcutil", "not built in zcutil/bin: %s", missing);

    /* git hooks (installed by the hooks unit; absent before it lands). */
    char out[300], cmd[1300];
    snprintf(cmd, sizeof cmd, "git -C \"%s\" config --get core.hooksPath 2>&1", root);
    int rc = run_cmd(cmd, out, sizeof out);
    first_line(out, 200);
    if (rc == 0 && *out)
        add("repo", "git-hooks", ST_OK, 0, "core.hooksPath = %s", out);
    else {
        snprintf(f, sizeof f, "%s/.git/hooks/pre-commit", root);
        if (is_regular(f))
            add("repo", "git-hooks", ST_OK, 0, ".git/hooks/pre-commit present");
        else
            add("repo", "git-hooks", ST_ADVISORY, "zcl-dev hooks install", "no pre-commit hook installed");
    }

    /* vendored Z23 manifests. */
    char chk[1300], tsv[1300];
    snprintf(chk, sizeof chk, "%s/src/c23/tools/check-vendor.sh", root);
    snprintf(tsv, sizeof tsv, "%s/zcutil/tools/Z23_SOURCE.tsv", root);
    if (!is_regular(chk) || !is_regular(tsv)) {
        add("repo", "vendor", ST_ADVISORY, 0, "no vendored manifest to verify");
    } else {
        snprintf(cmd, sizeof cmd, "cd \"%s\" && sh src/c23/tools/check-vendor.sh zcutil/tools/Z23_SOURCE.tsv 2>&1", root);
        char vo[400];
        rc = run_cmd(cmd, vo, sizeof vo);
        first_line(vo, 120);
        if (rc == 0)
            add("repo", "vendor", ST_OK, 0, "vendored Z23 files match zcutil/tools/Z23_SOURCE.tsv");
        else
            add("repo", "vendor", ST_FAIL, "git checkout zcutil/tools/vendor, or sh zcutil/tools/revendor.sh <z23-repo> <commit>", "vendor check failed: %s", vo);
    }
}

/* ---------- output ---------- */

static void json_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\')
            fprintf(f, "\\%c", c);
        else if (c < 0x20)
            fprintf(f, "\\u%04x", c);
        else
            fputc(c, f);
    }
    fputc('"', f);
}

static void tally(int *nok, int *nadv, int *nfail)
{
    *nok = *nadv = *nfail = 0;
    for (int i = 0; i < nchecks; i++) {
        if (checks[i].st == ST_OK) (*nok)++;
        else if (checks[i].st == ST_ADVISORY) (*nadv)++;
        else (*nfail)++;
    }
}

/* Output budget; ZCL_DOCTOR_OUT_CAP lowers it so tests can force a cut. */
static int out_cap(void)
{
    const char *e = getenv("ZCL_DOCTOR_OUT_CAP");
    long v = e ? strtol(e, 0, 10) : 0;
    return v > 0 && v < OUT_CAP ? (int)v : OUT_CAP;
}

static int line_len_json(const struct check *c)
{
    return (int)(strlen(c->id) + strlen(c->group) + (strlen(c->detail) + strlen(c->fix)) * 6 + 100);
}

static void report(int json, int after)
{
    int nok, nadv, nfail, used = 0, i, next = -1;
    tally(&nok, &nadv, &nfail);
    if (json) {
        printf("{\"schema\":\"zcl-doctor/1\",\"root\":");
        json_str(stdout, root);
        printf(",\"ok\":%d,\"advisory\":%d,\"fail\":%d,\"total\":%d,\"checks\":[", nok, nadv, nfail, nchecks);
        int first = 1;
        for (i = after; i < nchecks; i++) {
            int l = line_len_json(&checks[i]);
            if (used + l > out_cap()) {
                next = i;
                break;
            }
            used += l;
            printf("%s{\"id\":", first ? "" : ",");
            first = 0;
            json_str(stdout, checks[i].id);
            printf(",\"group\":");
            json_str(stdout, checks[i].group);
            printf(",\"status\":\"%s\",\"detail\":", status_name[checks[i].st]);
            json_str(stdout, checks[i].detail);
            printf(",\"fix\":");
            json_str(stdout, checks[i].fix);
            printf("}");
        }
        printf("],\"next_after\":");
        if (next < 0) printf("null");
        else printf("%d", next);
        printf("}\n");
        return;
    }
    for (i = after; i < nchecks; i++) {
        const struct check *c = &checks[i];
        int l = (int)(strlen(c->id) + strlen(c->detail) + strlen(c->fix) + 40);
        if (used + l > out_cap()) {
            next = i;
            break;
        }
        used += l;
        printf("[%-8s] %-14s %s\n", c->st == ST_OK ? "ok" : c->st == ST_ADVISORY ? "advisory" : "FAIL", c->id, c->detail);
        if (c->fix[0]) printf("           fix: %s\n", c->fix);
    }
    if (next >= 0) printf("... output cut; continue with --after=%d\n", next);
    else printf("%d ok, %d advisory, %d fail\n", nok, nadv, nfail);
}

/* ---------- repo root ---------- */

static int find_root(const char *explicit_root)
{
    char cwd[1024];
    if (explicit_root) {
        snprintf(root, sizeof root, "%s", explicit_root);
        return 1;
    }
    if (!getcwd(cwd, sizeof cwd)) return 0;
    for (;;) {
        char probe[1100];
        snprintf(probe, sizeof probe, "%s/configure.ac", cwd);
        if (is_regular(probe)) {
            snprintf(root, sizeof root, "%s", cwd);
            return 1;
        }
        char *slash = strrchr(cwd, '/');
#ifdef _WIN32
        char *bslash = strrchr(cwd, '\\');
        if (bslash && (!slash || bslash > slash)) slash = bslash;
#endif
        if (!slash || slash == cwd) break;
        *slash = 0;
    }
    return getcwd(root, sizeof root) != 0;
}

/* ---------- selftest: stub executables on a fake PATH ---------- */

static int failures;
#define EXPECT(cond, ...)                                                       \
    do {                                                                        \
        if (!(cond)) {                                                          \
            failures++;                                                         \
            fprintf(stderr, "selftest FAIL line %d: ", __LINE__);               \
            fprintf(stderr, __VA_ARGS__);                                       \
            fputc('\n', stderr);                                                \
        }                                                                       \
    } while (0)

static const struct check *find_check(const char *id)
{
    for (int i = 0; i < nchecks; i++)
        if (!strcmp(checks[i].id, id)) return &checks[i];
    return 0;
}

static void stub(const char *dir, const char *name, const char *body)
{
    char path[900], text[900];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    snprintf(text, sizeof text, "#!/bin/sh\n%s\n", body);
    if (!write_file(path, text)) {
        failures++;
        fprintf(stderr, "selftest: cannot write %s\n", path);
        return;
    }
#ifndef _WIN32
    chmod(path, 0755);
#endif
}

static void make_stubs(const char *dir)
{
    static const char *const plain[] = {"make",       "autoconf", "automake", "libtoolize", "pkg-config",
                                        "m4",         "git",      "curl",     "patch",      "apt-get", 0};
    for (int i = 0; plain[i]; i++) stub(dir, plain[i], "echo \"stub 1.0\"");
    stub(dir, "g++", "echo \"g++ stub 13.0\"");
    stub(dir, "cc", "echo \"cc stub 14.0\"");
}

static int selftest(void)
{
    char dir[700], p[900];
    static char pathenv[800], restore[8200];
    const char *old = getenv("PATH");
    snprintf(restore, sizeof restore, "PATH=%s", old ? old : "");
    if (!make_private_dir(dir, sizeof dir, "zcl-doctor-selftest")) {
        fprintf(stderr, "selftest: cannot mkdir %s\n", dir);
        return 2;
    }
    snprintf(pathenv, sizeof pathenv, "PATH=%s", dir);
    putenv(pathenv);
    putenv((char *)"ZCL_DOCTOR_PKGMGR=apt-get");
    putenv((char *)"CXX=");
    putenv((char *)"CC=");
    snprintf(root, sizeof root, "%s", dir);

    /* found: every tool present and both probes pass */
    make_stubs(dir);
    nchecks = 0;
    group_tools();
    group_build();
    EXPECT(find_check("automake") && find_check("automake")->st == ST_OK, "automake should be ok");
    EXPECT(find_check("cxx11") && find_check("cxx11")->st == ST_OK, "cxx11 should be ok");
    EXPECT(find_check("c23-std") && find_check("c23-std")->st == ST_OK, "c23-std should be ok");
    EXPECT(find_check("libtool") && find_check("libtool")->st == ST_OK, "libtool via libtoolize");

    /* missing: no automake turns exactly that tool red, with the exact fix */
    snprintf(p, sizeof p, "%s/automake", dir);
    remove(p);
    nchecks = 0;
    group_tools();
    const struct check *c = find_check("automake");
    EXPECT(c && c->st == ST_FAIL, "missing automake must fail");
    EXPECT(c && !strcmp(c->fix, "sudo apt-get install -y automake"), "fix was '%s'", c ? c->fix : "(none)");
    int nfail = 0;
    for (int i = 0; i < nchecks; i++) nfail += checks[i].st == ST_FAIL;
    EXPECT(nfail == 1, "only automake should fail, got %d failures", nfail);

    /* wrong version: g++ rejects -std=c++11 */
    stub(dir, "g++", "case \"$*\" in *-std=c++11*) echo 'error: unrecognized -std=c++11' >&2; exit 1;; esac\necho \"g++ stub 4.8\"");
    nchecks = 0;
    group_tools();
    group_build();
    c = find_check("cxx11");
    EXPECT(c && c->st == ST_FAIL, "old g++ must fail cxx11");

    /* fallback: cc rejects -std=c23 but takes gnu17: advisory, not failure */
    stub(dir, "g++", "echo \"g++ stub 13.0\"");
    stub(dir, "cc", "case \"$*\" in *-std=c23*) exit 1;; esac\necho \"cc stub 9.0\"");
    nchecks = 0;
    group_tools();
    group_build();
    c = find_check("c23-std");
    EXPECT(c && c->st == ST_ADVISORY && strstr(c->detail, "gnu17"), "c23 fallback must be advisory");

    /* mingw thread model */
    stub(dir, "x86_64-w64-mingw32-g++", "echo 'Thread model: win32' >&2");
    nchecks = 0;
    group_build();
    c = find_check("mingw");
    EXPECT(c && c->st == ST_ADVISORY && strstr(c->detail, "win32"), "win32 thread model must be advisory");
    stub(dir, "x86_64-w64-mingw32-g++", "echo 'Thread model: posix' >&2");
    nchecks = 0;
    group_build();
    c = find_check("mingw");
    EXPECT(c && c->st == ST_OK, "posix thread model must be ok");

    putenv(restore);
    snprintf(p, sizeof p, "rm -rf \"%s\"", dir);
    run_cmd(p, 0, 0);
    if (failures) {
        fprintf(stderr, "zcl-doctor selftest: %d failure(s)\n", failures);
        return 1;
    }
    puts("zcl-doctor selftest: ok");
    return 0;
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
    int json = 0, after = 0, want_self = 0;
    const char *group = 0, *explicit_root = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--json")) json = 1;
        else if (!strcmp(a, "--selftest")) want_self = 1;
        else if (!strcmp(a, "--purpose")) {
            puts("what this host lacks to build and test zclassicd, with the fix for each gap");
            return 0;
        } else if (!strncmp(a, "--after=", 8)) {
            char *end;
            errno = 0;
            long v = strtol(a + 8, &end, 10);
            if (a[8] == 0 || *end != 0 || errno != 0 || v < 0 || v > MAX_CHECKS) {
                fprintf(stderr, "zcl-doctor: --after wants an integer between 0 and the number of checks, got '%s'\n", a + 8);
                return 2;
            }
            after = (int)v;
        }
        else if (!strncmp(a, "--group=", 8)) group = a + 8;
        else if (!strncmp(a, "--root=", 7)) explicit_root = a + 7;
        else if (!strcmp(a, "--help") || !strcmp(a, "-h")) {
            puts("usage: zcl-doctor [--json] [--after=N] [--group=tools|build|host|repo] [--root=DIR] [--selftest]\n"
                 "exit 0 all ok or advisory, 1 a required check failed, 2 broken invocation or empty scan");
            return 0;
        } else {
            fprintf(stderr, "zcl-doctor: unknown argument '%s' (try --help)\n", a);
            return 2;
        }
    }
    if (!safe_path(tmp_dir())) {
        fprintf(stderr, "zcl-doctor: TMPDIR/TEMP holds characters outside [A-Za-z0-9._/+:@%%~ -]; refusing\n");
        return 2;
    }
    if (want_self) return selftest();
    if (group && strcmp(group, "tools") && strcmp(group, "build") && strcmp(group, "host") && strcmp(group, "repo")) {
        fprintf(stderr, "zcl-doctor: unknown group '%s' (tools, build, host, repo)\n", group);
        return 2;
    }
    if (!find_root(explicit_root)) {
        fprintf(stderr, "zcl-doctor: cannot determine the repository root\n");
        return 2;
    }
    if (!safe_path(root)) {
        fprintf(stderr, "zcl-doctor: root holds characters outside [A-Za-z0-9._/+:@%%~ -]; refusing (paths reach sh command lines)\n");
        return 2;
    }
    /* tools always runs: build needs its compiler paths; rows of other groups are filtered out below. */
    group_tools();
    if (!group || !strcmp(group, "build")) group_build();
    if (!group || !strcmp(group, "host")) group_host();
    if (!group || !strcmp(group, "repo")) group_repo();
    if (group) {
        int w = 0;
        for (int i = 0; i < nchecks; i++)
            if (!strcmp(checks[i].group, group)) checks[w++] = checks[i];
        nchecks = w;
    }
    if (nchecks == 0) {
        fprintf(stderr, "zcl-doctor: no checks ran (empty scan is a failure)\n");
        return 2;
    }
    if (after > nchecks) {
        fprintf(stderr, "zcl-doctor: --after=%d is past the %d checks\n", after, nchecks);
        return 2;
    }
    report(json, after);
    int nok, nadv, nfail;
    tally(&nok, &nadv, &nfail);
    return nfail ? 1 : 0;
}
