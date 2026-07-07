/* user/url.c — see url.h. */
#include "url.h"

static int str_len(const char *s) { int n = 0; while (s[n]) n++; return n; }

static int ci_eq_n(const char *a, const char *b, int n)
{
    for (int i = 0; i < n; i++) {
        int x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y) return 0;
    }
    return 1;
}

/* Copy up to cap-1 bytes of src[0..n) into dst, NUL-terminated. Returns the
 * number of bytes actually copied (n if it fit, fewer if truncated). */
static int copy_bounded(char *dst, int cap, const char *src, int n)
{
    if (n < 0) n = 0;
    if (n > cap - 1) n = cap - 1;
    for (int i = 0; i < n; i++) dst[i] = src[i];
    dst[n] = 0;
    return n;
}

static int strip_fragment(const char *s, int len)
{ for (int i = 0; i < len; i++) if (s[i] == '#') return i; return len; }

/* RFC 3986 §5.2.4, simplified: collapse "." and ".." segments. Extra ".." at
 * the root are dropped (cannot go above "/") rather than erroring -- the same
 * forgiving behavior browsers use. `in` is NUL-terminated and starts with '/'.
 * Returns 1 on success, 0 if a path has too many segments or doesn't fit. */
static int remove_dot_segments(const char *in, char *out, int outcap)
{
    const char *segs[64]; int seglens[64]; int n = 0;
    int len = str_len(in);
    int i = (len > 0 && in[0] == '/') ? 1 : 0;
    while (i < len) {
        int start = i;
        while (i < len && in[i] != '/') i++;
        int sl = i - start;
        if (sl == 0 || (sl == 1 && in[start] == '.')) {
            /* skip "//" and "." segments */
        } else if (sl == 2 && in[start] == '.' && in[start + 1] == '.') {
            if (n > 0) n--;
        } else {
            if (n >= 64) return 0;
            segs[n] = in + start; seglens[n] = sl; n++;
        }
        if (i < len) i++;          /* skip the '/' */
    }
    int trailing_slash = (len > 0 && in[len - 1] == '/');
    if (outcap < 2) return 0;
    int oi = 0;
    out[oi++] = '/';
    for (int s = 0; s < n; s++) {
        if (s > 0) { if (oi + 1 >= outcap) return 0; out[oi++] = '/'; }
        if (oi + seglens[s] >= outcap) return 0;
        for (int k = 0; k < seglens[s]; k++) out[oi++] = segs[s][k];
    }
    if (trailing_slash && n > 0) { if (oi + 1 >= outcap) return 0; out[oi++] = '/'; }
    out[oi] = 0;
    return 1;
}

/* Append loc[qpos..loclen) (a "?query", or nothing) to out->path, which must
 * already hold a NUL-terminated path. */
static int append_query(struct url *out, const char *loc, int qpos, int loclen)
{
    if (qpos >= loclen) return 1;
    int plen = str_len(out->path);
    int qlen = loclen - qpos;
    if (plen + qlen >= (int)sizeof out->path) return 0;
    for (int k = 0; k < qlen; k++) out->path[plen + k] = loc[qpos + k];
    out->path[plen + qlen] = 0;
    return 1;
}

/* "host[:port]" only (no scheme, no path). out->https must already be set. */
static int parse_authority(const char *s, int len, struct url *out)
{
    int hlen = 0; while (hlen < len && s[hlen] != ':') hlen++;
    if (hlen == 0 || copy_bounded(out->host, sizeof out->host, s, hlen) != hlen) return -1;
    if (hlen >= len) { out->port = out->https ? 443 : 80; return 0; }
    int i = hlen + 1;
    if (i >= len) return -1;                       /* trailing ':' with no digits */
    int p = 0;
    for (; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        p = p * 10 + (s[i] - '0');
        if (p > 65535) return -1;
    }
    if (p == 0) return -1;
    out->port = p;
    return 0;
}

/* Dot-segment-normalize a path slice (not NUL-terminated in the source) into
 * out->path. */
static int remove_dot_segments_copy(const char *path, int pathlen, struct url *out)
{
    char raw[URL_PATH_MAX];
    if (copy_bounded(raw, sizeof raw, path, pathlen) != pathlen) return 0;
    return remove_dot_segments(raw, out->path, sizeof out->path);
}

/* "host[:port][/path...]" -- splits at the first '/'. out->https must already
 * be set; fills host, port and path. */
static int parse_host_and_path(const char *s, int len, struct url *out)
{
    int i = 0; while (i < len && s[i] != '/') i++;
    if (parse_authority(s, i, out) != 0) return -1;
    if (i >= len) { out->path[0] = '/'; out->path[1] = 0; return 0; }
    int qpos = i; while (qpos < len && s[qpos] != '?') qpos++;
    if (!remove_dot_segments_copy(s + i, qpos - i, out)) return -1;
    return append_query(out, s, qpos, len) ? 0 : -1;
}

int url_parse(const char *s, int len, struct url *out)
{
    len = strip_fragment(s, len);
    int https, skip;
    if (len >= 8 && ci_eq_n(s, "https://", 8))      { https = 1; skip = 8; }
    else if (len >= 7 && ci_eq_n(s, "http://", 7))  { https = 0; skip = 7; }
    else return -1;
    out->https = https;
    out->host[0] = 0; out->path[0] = 0; out->port = 0;
    return parse_host_and_path(s + skip, len - skip, out);
}

int url_resolve(const struct url *base, const char *loc, int loclen, struct url *out)
{
    loclen = strip_fragment(loc, loclen);
    if (loclen <= 0) return -1;

    if ((loclen >= 8 && ci_eq_n(loc, "https://", 8)) ||
        (loclen >= 7 && ci_eq_n(loc, "http://", 7)))
        return url_parse(loc, loclen, out);                 /* absolute URI */

    out->https = base->https;                                /* every case below keeps the scheme */

    if (loclen >= 2 && loc[0] == '/' && loc[1] == '/')
        return parse_host_and_path(loc + 2, loclen - 2, out);   /* network-path: "//host/path" */

    out->port = base->port;
    if (copy_bounded(out->host, sizeof out->host, base->host, str_len(base->host)) == 0) return -1;

    if (loc[0] == '/') {                                      /* absolute-path: "/path?q" */
        int qpos = 0; while (qpos < loclen && loc[qpos] != '?') qpos++;
        if (!remove_dot_segments_copy(loc, qpos, out)) return -1;
        return append_query(out, loc, qpos, loclen) ? 0 : -1;
    }

    if (loc[0] == '?') {                                      /* query-only: keep base path */
        int bp = 0; while (base->path[bp] && base->path[bp] != '?') bp++;
        if (copy_bounded(out->path, sizeof out->path, base->path, bp) != bp) return -1;
        return append_query(out, loc, 0, loclen) ? 0 : -1;
    }

    /* relative-path reference: merge() with all-but-last segment of the base
     * path (RFC 3986 §5.3), then collapse dot segments. */
    int qpos = 0; while (qpos < loclen && loc[qpos] != '?') qpos++;
    int bp = 0; while (base->path[bp] && base->path[bp] != '?') bp++;
    int dir = 0; for (int k = 0; k < bp; k++) if (base->path[k] == '/') dir = k + 1;

    char merged[URL_PATH_MAX];
    int n;
    if (dir > 0) { n = copy_bounded(merged, sizeof merged, base->path, dir); if (n != dir) return -1; }
    else { merged[0] = '/'; n = 1; }
    if (n + qpos >= (int)sizeof merged) return -1;
    for (int k = 0; k < qpos; k++) merged[n + k] = loc[k];
    n += qpos; merged[n] = 0;

    if (!remove_dot_segments(merged, out->path, sizeof out->path)) return -1;
    return append_query(out, loc, qpos, loclen) ? 0 : -1;
}
