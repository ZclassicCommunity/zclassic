// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Standalone driver for the fuzz targets when libFuzzer is unavailable:
// runs LLVMFuzzerTestOneInput on every file under the given paths
// (files, or directories searched recursively).

#include <boost/filesystem.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

namespace fs = boost::filesystem;

static void collect(const fs::path& p, std::vector<fs::path>& out)
{
    if (fs::is_directory(p)) {
        std::vector<fs::path> kids;
        for (fs::directory_iterator it(p), end; it != end; ++it) kids.push_back(it->path());
        std::sort(kids.begin(), kids.end());
        for (const fs::path& k : kids) collect(k, out);
    } else if (fs::is_regular_file(p)) {
        out.push_back(p);
    }
}

int main(int argc, char** argv)
{
    std::vector<fs::path> files;
    for (int i = 1; i < argc; i++) collect(fs::path(argv[i]), files);
    size_t n = 0;
    for (const fs::path& f : files) {
        std::ifstream in(f.string().c_str(), std::ios::binary);
        if (!in) {
            fprintf(stderr, "cannot read %s\n", f.string().c_str());
            return 2;
        }
        std::vector<uint8_t> buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        static const uint8_t empty = 0;
        LLVMFuzzerTestOneInput(buf.empty() ? &empty : buf.data(), buf.size());
        n++;
    }
    printf("replayed %zu inputs\n", n);
    return 0;
}
