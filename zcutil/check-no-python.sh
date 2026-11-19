#!/bin/sh
# Guard: Python and hosted CI must not come back (POSIX sh).
#
# Fails when the source tree contains
#   - a Python file by extension, case-insensitively: .py .pyw .pyc .pyi .pyx .ipynb,
#   - a python shebang on any line of a text file (not only line 1),
#   - python / pip / python3 invoked as a command in any tracked text file (word-boundary
#     match; PROSE_OK lists the path prefixes whose prose may merely mention the word),
#   - a pip/packaging file (requirements*.txt, constraints*.txt, setup.cfg, pyproject.toml,
#     Pipfile, Pipfile.lock, poetry.lock, tox.ini),
#   - hosted-CI configuration: .github/workflows, .github/actions, .github/dependabot.yml,
#     .buildkite, .circleci, .woodpecker(.yml), .drone.yml, .travis.yml, .gitlab-ci.yml,
#     .cirrus.yml, appveyor.yml, azure-pipelines.yml, bitbucket-pipelines.yml, Jenkinsfile.
# Builds and tests run only on project machines (zcutil/local-ci.sh).
#
# In a git checkout it examines the tracked files; elsewhere (a make dist tree) every file.
# The exceptions list below is empty and stays empty: a Python tool is ported to C23 or
# POSIX sh, or deleted.
#
# usage: check-no-python.sh [--root DIR]      exit 0 clean, 1 offenders found, 2 usage
#        check-no-python.sh --self-test       proves each kind of offender is caught
set -u
EXCEPTIONS=""   # exact repository paths, space separated; keep empty
PROSE_OK="doc/history/ zcutil/check-no-python.sh"   # path prefixes whose prose may mention python/pip (the scan for invocations skips them)

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)

list_files() {   # relative paths, one per line
    if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1 &&
       [ "$(git -C "$root" rev-parse --show-toplevel 2>/dev/null)" = "$(CDPATH= cd -- "$root" && pwd -P)" ]; then
        git -C "$root" ls-files
    else
        (cd "$root" && find . \( -type f -o -type l \) | sed 's|^\./||')
    fi
}

scan() {
    files=$(mktemp) || exit 2
    bad=$(mktemp) || exit 2
    list_files > "$files"
    # 1. by name and location (extensions case-insensitively)
    while IFS= read -r f; do
        base=${f##*/}
        case $f in
            .github/workflows|.github/workflows/*|.github/actions|.github/actions/*|.github/dependabot.yml|.github/dependabot.yaml) echo "$f: GitHub CI configuration" ;;
            .circleci|.circleci/*|*/.circleci/*|.buildkite|.buildkite/*|*/.buildkite/*|.woodpecker|.woodpecker/*|*/.woodpecker/*) echo "$f: hosted CI configuration" ;;
            *) case $base in
                   *.[Pp][Yy]|*.[Pp][Yy][Ww]|*.[Pp][Yy][Cc]|*.[Pp][Yy][Ii]|*.[Pp][Yy][Xx]|*.[Ii][Pp][Yy][Nn][Bb]) echo "$f: Python source or bytecode" ;;
                   requirements*.txt|constraints*.txt|setup.cfg|pyproject.toml|Pipfile|Pipfile.lock|poetry.lock|tox.ini) echo "$f: Python packaging file" ;;
                   .travis.yml|.gitlab-ci.yml|.cirrus.yml|.drone.yml|.woodpecker.yml|.woodpecker.yaml|appveyor.yml|.appveyor.yml|azure-pipelines.yml|Jenkinsfile|bitbucket-pipelines.yml) echo "$f: hosted CI configuration" ;;
               esac ;;
        esac
    done < "$files" >> "$bad"
    # 2. python shebangs on any line (a shebang is only honoured on line 1, but a copied or
    #    generated script keeps working wherever it sits); text files only
    ( cd "$root" && tr '\n' '\0' < "$files" | xargs -0 grep -HnIE '^#![[:space:]]*([^[:space:]]*/)?(env[[:space:]]+)?[^[:space:]]*python' 2>/dev/null ) |
        sed 's/^\([^:]*\):\([0-9]*\):.*/\1: Python shebang on line \2/' >> "$bad"
    # 3. python / pip invoked as a command in any tracked text file. Prose that merely names
    #    the word (history of the project, release notes) is allowed by path prefix.
    ( cd "$root" && tr '\n' '\0' < "$files" | xargs -0 grep -HnIE "(^|[[:space:];&|(\`\"'])(/usr/bin/env[[:space:]]+)?(python[0-9.]*|pip[0-9.]*)[[:space:]]+(-[a-zA-Z-]+|[^[:space:]]*\.py|install|download|list|freeze)([[:space:]]|\$)|[|;&\`(][[:space:]]*(python[0-9.]*|pip[0-9.]*)[[:space:]]*(\$|[|;&)\`])|env[[:space:]]+(python[0-9.]*|pip[0-9.]*)([[:space:]]|\$)" 2>/dev/null ) |
        sed 's/^\([^:]*\):\([0-9]*\):.*/\1: python or pip invocation on line \2/' |
        while IFS= read -r l; do
            p=${l%%: *}; skip=0
            for a in $PROSE_OK; do case $p in "$a"*) skip=1 ;; esac; done
            [ "$skip" = 1 ] || printf '%s\n' "$l"
        done >> "$bad"
    # exceptions (empty by policy)
    for e in $EXCEPTIONS; do grep -v "^$e: " "$bad" > "$bad.x"; mv "$bad.x" "$bad"; done
    n=$(wc -l < "$bad" | tr -d ' ')
    if [ "$n" -ne 0 ]; then
        echo "check-no-python: FAIL, $n offender(s):" >&2
        sort -u "$bad" | sed 's/^/  /' >&2
        echo "Port the tool to C23 or POSIX sh, or delete it; CI runs only through zcutil/local-ci.sh." >&2
        rm -f "$files" "$bad"
        return 1
    fi
    echo "check-no-python: OK ($(wc -l < "$files" | tr -d ' ') files, no Python, pip files or hosted CI configuration)"
    rm -f "$files" "$bad"
}

self_test() {
    t=$(mktemp -d)
    trap 'rm -rf "$t"' EXIT HUP INT TERM
    fails=0
    case_() {   # <name> <path> [content]
        rm -rf "$t/tree"; mkdir -p "$t/tree/zcutil" "$t/tree/sub"
        cp "$0" "$t/tree/zcutil/check-no-python.sh"
        printf 'int main(void){return 0;}\n' > "$t/tree/sub/ok.c"
        if [ -n "$2" ]; then mkdir -p "$t/tree/$(dirname "$2")"; printf '%s\n' "${3:-x}" > "$t/tree/$2"; fi
        if sh "$t/tree/zcutil/check-no-python.sh" > "$t/out" 2>&1; then got=pass; else got=fail; fi
        want=fail; [ -n "$2" ] || want=pass
        if [ "$got" = "$want" ]; then echo "PASS $1"; else echo "FAIL $1 (got $got, want $want)" >&2; cat "$t/out" >&2; fails=$((fails + 1)); fi
    }
    case_ "clean tree passes" ""
    case_ "a .py file" "tools/x.py"
    case_ "a python3 shebang without .py" "bin/tool" '#!/usr/bin/env python3'
    case_ "a python2 shebang" "bin/tool2" '#!/usr/bin/python2'
    case_ "requirements.txt" "qa/requirements.txt"
    case_ "requirements-dev.txt" "requirements-dev.txt"
    case_ "pyproject.toml" "pyproject.toml"
    case_ "setup.cfg" "setup.cfg"
    case_ "Pipfile" "Pipfile"
    case_ "a GitHub workflow" ".github/workflows/ci.yml"
    case_ "dependabot" ".github/dependabot.yml"
    case_ "a vendored .travis.yml" "src/lib/.travis.yml"
    case_ ".gitlab-ci.yml" ".gitlab-ci.yml"
    case_ "a .circleci config" ".circleci/config.yml"
    case_ "appveyor.yml" "appveyor.yml"
    case_ "a .PY file (upper case)" "tools/X.PY"
    case_ "a mixed-case .Py file" "tools/y.Py"
    case_ "a .pyc file" "tools/z.pyc"
    case_ "a .pyi file" "tools/z.pyi"
    case_ "a .pyx file" "tools/z.pyx"
    case_ "a Jupyter notebook" "doc/n.ipynb"
    case_ "a shebang that is not on line 1" "bin/late" "$(printf '# header
#
#!/usr/bin/env %s' python3)"
    case_ "python3 invoked on a script" "build/gen.sh" 'python3 tools/gen.py --x'
    case_ "python -c in a command" "build/c.sh" 'x=$(python -c "print(1)")'
    case_ "pip install" "build/p.sh" 'pip install foo'
    case_ "pip3 -m" "build/p3.sh" 'sudo pip3 --version'
    case_ "python at the end of a pipe" "build/pipe.sh" 'echo {} | python3'
    case_ "env python in a recipe" "Makefile.inc" '	/usr/bin/env python tool'
    case_ ".github/actions" ".github/actions/setup/action.yml"
    case_ ".buildkite" ".buildkite/pipeline.yml"
    case_ ".drone.yml" ".drone.yml"
    case_ ".woodpecker.yml" ".woodpecker.yml"
    case_ ".woodpecker directory" ".woodpecker/build.yml"
    case_ "a .travis.yml in the root" ".travis.yml"
    # prose that merely names python is fine, in a normal file and in the allowed history tree
    rm -rf "$t/tree"; mkdir -p "$t/tree/zcutil" "$t/tree/doc/history"; cp "$0" "$t/tree/zcutil/check-no-python.sh"
    printf 'We removed python from the build; the python era is over.\n' > "$t/tree/README.md"
    printf 'Need `ca-certificates` and `python` for LXC builds\n' > "$t/tree/doc/history/notes.md"
    if sh "$t/tree/zcutil/check-no-python.sh" >/dev/null 2>&1; then echo "PASS prose that mentions python"; else echo "FAIL prose that mentions python" >&2; fails=$((fails + 1)); fi
    # shell and C files that merely mention python are fine
    rm -rf "$t/tree"; mkdir -p "$t/tree/zcutil"; cp "$0" "$t/tree/zcutil/check-no-python.sh"
    printf '#!/bin/sh\n# no python here\n' > "$t/tree/s.sh"
    if sh "$t/tree/zcutil/check-no-python.sh" >/dev/null 2>&1; then echo "PASS a sh file that mentions python"; else echo "FAIL a sh file that mentions python" >&2; fails=$((fails + 1)); fi
    # a git checkout is examined through its tracked files
    rm -rf "$t/tree"; mkdir -p "$t/tree/zcutil"; cp "$0" "$t/tree/zcutil/check-no-python.sh"
    ( cd "$t/tree" && git init -q . && printf 'x\n' > a.py && git add zcutil/check-no-python.sh ) >/dev/null 2>&1
    if sh "$t/tree/zcutil/check-no-python.sh" >/dev/null 2>&1; then echo "PASS an untracked .py in a git tree is not examined"; else echo "FAIL untracked .py was examined" >&2; fails=$((fails + 1)); fi
    ( cd "$t/tree" && git add a.py ) >/dev/null 2>&1
    if sh "$t/tree/zcutil/check-no-python.sh" >/dev/null 2>&1; then echo "FAIL a tracked .py in a git tree passed" >&2; fails=$((fails + 1)); else echo "PASS a tracked .py in a git tree fails"; fi
    [ "$fails" -eq 0 ] && { echo "check-no-python: self-test passed"; return 0; }
    echo "check-no-python: $fails self-test(s) failed" >&2
    return 1
}

case ${1:-} in
    --self-test) self_test ;;
    --root) [ -d "${2:-}" ] || { echo "usage: $0 [--root DIR | --self-test]" >&2; exit 2; }; root=$(CDPATH= cd -- "$2" && pwd); scan ;;
    "") scan ;;
    *) echo "usage: $0 [--root DIR | --self-test]" >&2; exit 2 ;;
esac
