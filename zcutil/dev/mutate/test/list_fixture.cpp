// list_fixture.cpp: golden input for `zcl-dev mutate list`. A line marked NOSITE must yield no site.
#include <map> // NOSITE
#include <string> // NOSITE
#include <vector> // NOSITE

template <typename T> // NOSITE
static bool less_than(const T& a, const T& b) { return a < b; }

static std::vector<int> make(int n) // NOSITE
{
    std::vector<int> v; // NOSITE
    std::map<int, std::vector<int> > m; // NOSITE
    for (int i = 0; i < n; i++) v.push_back(i * 2);
    return v;
}

static const char *raw = R"x(a < b && c == 1; f(1);)x"; // NOSITE
static const char *raw2 = u8R"(x >= 4)"; // NOSITE
static const long big = 1'000'000; // NOSITE

bool check(const std::vector<int>& v, size_t n)
{
    /* v.size() == n NOSITE */
    if (v.size() == n && n != 0)
        return true;
    std::cout << v.size() << std::endl;
    ::fflush(stdout);
    v.front();
    return less_than<int>(v[0], 3) || v.size() >= 10;
}
