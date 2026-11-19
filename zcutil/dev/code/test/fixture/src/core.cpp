// core.cpp: lexer fixture. Braces in comments { } and strings must not count.
#include "a.h"
#include "common.h"
#include <vector>

/* a block comment with an open brace { and a fake function void fake() { */
namespace fx {
namespace {
const char *kRaw = R"x(int fake_raw() { return 1; } // }})x";
const char *kStr = "} { brace in a string \" still in it }";
char kOpen = '{';
char kQuote = '\'';
int kBig = 1'000'000;
int helper(int v) { return v + 1; }
} // namespace

#define TWICE(x) ((x) * 2) /* directive with a { brace */

class Counter {
public:
    Counter() : n_(0), tag_{1} {}
    int Next() const noexcept { return ++n_; }
    bool operator==(const Counter &o) const { return n_ == o.n_; }
    int Twice(int x);
    template <typename T> T Pick(T a, T b) { return a ? a : b; }

private:
    mutable int n_;
    int tag_;
};

int Counter::Twice(int x)
{
    auto l = [&](int y) { return y * 2; };
    if (x > 0) {
        return l(x);
    }
    return helper(x);
}

template <typename T> T Max(T a, T b)
{
    return a > b ? a : b;
}

struct Pt {
    int x;
    int y;
};

enum Mode { MODE_A, MODE_B };

static const int table[] = {1, 2, 3};

int Default(int a = 3, int b = 4) { return a + b; }

void Annotated(int a) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    (void)a;
}

auto Trailing(int a) -> int { return a; }
} // namespace fx

extern "C" {
int c_entry(int x) { return x; }
}

int a_value() { return fx::Default(); }
int b_value() { return 2; }

extern "C" int c_one_liner(int x)
{
    return x + 1;
}

template <typename T, int N> struct Blob { void Set(int v); int Get() const; };
template <typename T, int N>
void Blob<T, N>::Set(int v)
{
    (void)v;
}
template <typename T, int N>
int Blob<T, N>::Get() const
{
    return N;
}
