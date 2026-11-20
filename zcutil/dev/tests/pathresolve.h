/* Physical paths for zcl-dev-tests (included by zcl-dev-tests.c after xstrdup/xfmt; not a standalone header). MIT. */
#ifndef ZCL_PATHRESOLVE_H
#define ZCL_PATHRESOLVE_H

/* Physical form of an existing path: symlinks resolved (realpath), `\` turned into `/`. Windows has no
 * realpath; _fullpath only normalizes there, which is all that platform needs here. */
static int real_path(const char *path, char *out, size_t cap)
{
    struct stat st;
    if (stat(path, &st)) return 0;
#ifdef _WIN32
    if (!_fullpath(out, path, cap)) return 0;
#else
    char *rp = realpath(path, NULL);
    if (!rp) return 0;
    int fits = strlen(rp) < cap;
    if (fits) memcpy(out, rp, strlen(rp) + 1);
    free(rp);
    if (!fits) return 0;
#endif
    for (char *c = out; *c; c++) if (*c == '\\') *c = '/';
    return 1;
}

/* An absolute path with its longest existing leading part made physical, so $TMPDIR=/var/x and a cwd of
 * /private/var/x (macOS), or any symlinked root, compare equal. The unresolved tail (a file that may not
 * exist, `..` segments) is kept as text and collapsed, and policed, by norm_path. */
static char *resolve_abs(const char *abs)
{
    char *tmp = xstrdup(abs), real[4096];
    size_t len = strlen(tmp), floor = (tmp[0] && tmp[1] == ':') ? 2 : 0;
    while (len > floor + 1) {
        if (real_path(tmp, real, sizeof real)) {
            char *res = xfmt("%s%s", real, abs + len);
            free(tmp);
            return res;
        }
        while (len > floor + 1 && tmp[len - 1] != '/') len--;
        if (len > floor + 1) len--; /* drop the '/' */
        tmp[len] = 0;
    }
    free(tmp);
    return xstrdup(abs);
}

#endif
