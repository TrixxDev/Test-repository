/* HTTP cookie jar (RFC 6265) -- see cookiejar.h. */
#include "cookiejar.h"

/* freestanding string helpers (no libc, same discipline as url.c) */
static int c_len(const char *s) { int n = 0; while (s[n]) n++; return n; }
static int lower_ch(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

static int ci_eq(const char *a, int alen, const char *b, int blen)
{
    if (alen != blen) return 0;
    for (int i = 0; i < alen; i++) if (lower_ch((unsigned char)a[i]) != lower_ch((unsigned char)b[i])) return 0;
    return 1;
}
static int ci_eq_str(const char *a, int alen, const char *b) { return ci_eq(a, alen, b, c_len(b)); }
static int mem_eq(const char *a, const char *b, int n) { for (int i = 0; i < n; i++) if (a[i] != b[i]) return 0; return 1; }
static int str_eq(const char *a, const char *b) { int i = 0; while (a[i] && b[i]) { if (a[i] != b[i]) return 0; i++; } return a[i] == b[i]; }

static void copy_bounded(char *dst, int cap, const char *src, int n)
{
    int m = n < cap - 1 ? n : cap - 1;
    if (m < 0) m = 0;
    for (int i = 0; i < m; i++) dst[i] = src[i];
    dst[m] = 0;
}

static void trim(const char **s, int *n)
{
    while (*n > 0 && (**s == ' ' || **s == '\t')) { (*s)++; (*n)--; }
    while (*n > 0 && ((*s)[*n - 1] == ' ' || (*s)[*n - 1] == '\t')) (*n)--;
}

/* ------------------------------------------------------------------ */
/* RFC 6265 SS5.1.3 domain-match / SS5.1.4 path-match + default-path     */
/* ------------------------------------------------------------------ */

static int domain_match(const char *host, int hlen, const char *domain, int dlen)
{
    if (ci_eq(host, hlen, domain, dlen)) return 1;
    if (hlen <= dlen) return 0;
    int offset = hlen - dlen;
    if (host[offset - 1] != '.') return 0;
    return ci_eq(host + offset, dlen, domain, dlen);
}

static int path_match(const char *reqpath, int reqlen, const char *cpath, int clen)
{
    if (reqlen == clen) return mem_eq(reqpath, cpath, clen);
    if (reqlen > clen && mem_eq(reqpath, cpath, clen)) {
        if (clen > 0 && cpath[clen - 1] == '/') return 1;
        if (reqpath[clen] == '/') return 1;
    }
    return 0;
}

/* RFC 6265 SS5.1.4 "default-path" algorithm. `reqpath` is always '/'-prefixed
 * here (struct url's invariant, see url.h), which simplifies step 2 away. */
static void default_path(const char *reqpath, int reqlen, char *out, int outcap)
{
    if (reqlen == 0 || reqpath[0] != '/') { copy_bounded(out, outcap, "/", 1); return; }
    int slash_count = 0, last_slash = 0;
    for (int i = 0; i < reqlen; i++) if (reqpath[i] == '/') { slash_count++; last_slash = i; }
    if (slash_count <= 1) { copy_bounded(out, outcap, "/", 1); return; }
    copy_bounded(out, outcap, reqpath, last_slash);
}

/* ------------------------------------------------------------------ */
/* Max-Age / Expires parsing                                          */
/* ------------------------------------------------------------------ */

static int parse_signed(const char *s, int n, int64_t *out)
{
    if (n == 0) return 0;
    int neg = 0, i = 0;
    if (s[0] == '-') { neg = 1; i = 1; } else if (s[0] == '+') { i = 1; }
    if (i >= n) return 0;
    int64_t v = 0;
    for (; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return 0;
        v = v * 10 + (s[i] - '0');
    }
    *out = neg ? -v : v;
    return 1;
}

static int month_index(const char *s)
{
    static const char *names = "janfebmaraprmayjunjulaugsepoctnovdec";
    for (int m = 0; m < 12; m++) {
        if (lower_ch((unsigned char)s[0]) == names[m*3] &&
            lower_ch((unsigned char)s[1]) == names[m*3+1] &&
            lower_ch((unsigned char)s[2]) == names[m*3+2])
            return m + 1;
    }
    return -1;
}

/* Days since 1970-01-01 for a proleptic-Gregorian y/m(1-12)/d -- the
 * standard public-domain algorithm (Howard Hinnant, "chrono-Compatible
 * Low-Level Date Algorithms"). */
static int64_t days_from_civil(int y, int m, int d)
{
    y -= (m <= 2);
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int yoe = (int)(y - era * 400);
    int doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

/* A tolerant scan for an HTTP-date, rather than a fixed-format parser: pull
 * the first bare integer as the day, the first 3+ letter word as the month
 * name, the next bare integer as the year (2- or 4-digit, RFC 6265 SS5.1.1's
 * pivot-at-70 rule), and an HH:MM[:SS] wherever it appears. Every Expires
 * value seen in practice -- RFC 1123 ("Wed, 21 Oct 2025 07:28:00 GMT") and
 * its close variants -- fits this shape without demanding exact placement. */
static int parse_http_date(const char *s, int n, uint64_t *out)
{
    int day = -1, month = -1, year = -1, hh = -1, mm = -1, ss = -1;
    int i = 0;
    while (i < n) {
        if (s[i] >= '0' && s[i] <= '9') {
            int j = i, v = 0, digits = 0;
            while (j < n && s[j] >= '0' && s[j] <= '9') { v = v * 10 + (s[j] - '0'); j++; digits++; }
            if (j < n && s[j] == ':') {
                hh = v;
                j++; int v2 = 0; while (j < n && s[j] >= '0' && s[j] <= '9') { v2 = v2 * 10 + (s[j] - '0'); j++; }
                mm = v2;
                if (j < n && s[j] == ':') {
                    j++; int v3 = 0; while (j < n && s[j] >= '0' && s[j] <= '9') { v3 = v3 * 10 + (s[j] - '0'); j++; }
                    ss = v3;
                }
            } else if (day < 0) {
                day = v;
            } else if (year < 0) {
                year = v;
            }
            (void)digits;
            i = j;
        } else if ((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z')) {
            int j = i; while (j < n && ((s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= 'a' && s[j] <= 'z'))) j++;
            if (j - i >= 3 && month < 0) { int mi = month_index(s + i); if (mi > 0) month = mi; }
            i = j;
        } else {
            i++;
        }
    }
    if (day < 1 || day > 31 || month < 1 || year < 0 || hh < 0 || mm < 0) return 0;
    if (ss < 0) ss = 0;
    if (year < 100) year += (year < 70) ? 2000 : 1900;
    int64_t days = days_from_civil(year, month, day);
    int64_t secs = days * 86400 + hh * 3600 + mm * 60 + ss;
    if (secs < 0) return 0;
    *out = (uint64_t)secs;
    return 1;
}

/* ------------------------------------------------------------------ */
/* jar                                                                 */
/* ------------------------------------------------------------------ */

void cookie_jar_init(cookie_jar *jar)
{
    for (int i = 0; i < COOKIE_JAR_N; i++) jar->entries[i].valid = 0;
    jar->clock = 0;
}

void cookie_jar_set(cookie_jar *jar, const char *v, int vlen,
                    const char *request_host, const char *request_path,
                    int request_is_https, uint64_t now)
{
    (void)request_is_https;

    /* cookie-pair = name "=" value, up to the first ';' (or end) */
    int p = 0;
    while (p < vlen && v[p] != ';') p++;
    const char *pair = v; int pair_len = p;
    if (p < vlen) p++;

    int eq = 0; while (eq < pair_len && pair[eq] != '=') eq++;
    if (eq >= pair_len) return;   /* no '=' at all: malformed, ignore */
    const char *name = pair; int name_len = eq;
    const char *value = pair + eq + 1; int value_len = pair_len - eq - 1;
    trim(&name, &name_len);
    trim(&value, &value_len);
    if (name_len <= 0 || name_len >= COOKIE_NAME_MAX || value_len >= COOKIE_VALUE_MAX) return;

    char domain_buf[COOKIE_DOMAIN_MAX]; int domain_len = 0; int explicit_domain = 0;
    char path_buf[COOKIE_PATH_MAX]; int path_len = 0; int explicit_path = 0;
    int secure = 0, http_only = 0;
    int has_max_age = 0; int64_t max_age = 0;
    int has_expires = 0; uint64_t expires_val = 0;

    while (p < vlen) {
        int as = p;
        while (p < vlen && v[p] != ';') p++;
        const char *attr = v + as; int attr_len = p - as;
        if (p < vlen) p++;
        trim(&attr, &attr_len);
        if (attr_len == 0) continue;

        int aeq = 0; while (aeq < attr_len && attr[aeq] != '=') aeq++;
        const char *an = attr; int an_len = aeq < attr_len ? aeq : attr_len;
        const char *av = aeq < attr_len ? attr + aeq + 1 : attr + attr_len;
        int av_len = aeq < attr_len ? attr_len - aeq - 1 : 0;
        trim(&an, &an_len); trim(&av, &av_len);

        if (ci_eq_str(an, an_len, "Domain")) {
            if (av_len > 0 && av[0] == '.') { av++; av_len--; }   /* leading dot ignored, RFC 6265 SS5.2.3 */
            if (av_len > 0 && av_len < COOKIE_DOMAIN_MAX) {
                for (int i = 0; i < av_len; i++) domain_buf[i] = (char)lower_ch((unsigned char)av[i]);
                domain_buf[av_len] = 0; domain_len = av_len; explicit_domain = 1;
            }
        } else if (ci_eq_str(an, an_len, "Path")) {
            if (av_len > 0 && av[0] == '/' && av_len < COOKIE_PATH_MAX) {
                copy_bounded(path_buf, sizeof path_buf, av, av_len);
                path_len = av_len; explicit_path = 1;
            }
        } else if (ci_eq_str(an, an_len, "Secure")) {
            secure = 1;
        } else if (ci_eq_str(an, an_len, "HttpOnly")) {
            http_only = 1;
        } else if (ci_eq_str(an, an_len, "Max-Age")) {
            int64_t val; if (parse_signed(av, av_len, &val)) { max_age = val; has_max_age = 1; }
        } else if (ci_eq_str(an, an_len, "Expires")) {
            uint64_t val; if (parse_http_date(av, av_len, &val)) { expires_val = val; has_expires = 1; }
        }
        /* unknown attributes (SameSite, Priority, ...) silently ignored */
    }

    int host_only;
    char domain_final[COOKIE_DOMAIN_MAX];
    int hostlen = c_len(request_host);
    if (explicit_domain) {
        if (!domain_match(request_host, hostlen, domain_buf, domain_len)) return;   /* not ours to set */
        copy_bounded(domain_final, sizeof domain_final, domain_buf, domain_len);
        host_only = 0;
    } else {
        copy_bounded(domain_final, sizeof domain_final, request_host, hostlen);
        for (char *pc = domain_final; *pc; pc++) *pc = (char)lower_ch((unsigned char)*pc);
        host_only = 1;
    }

    char path_final[COOKIE_PATH_MAX];
    if (explicit_path) copy_bounded(path_final, sizeof path_final, path_buf, path_len);
    else default_path(request_path, c_len(request_path), path_final, sizeof path_final);

    uint64_t expires_at = 0;
    int is_deletion = 0;
    if (has_max_age) {
        if (max_age <= 0) is_deletion = 1;
        else expires_at = now + (uint64_t)max_age;
    } else if (has_expires) {
        if (expires_val <= now) is_deletion = 1;
        else expires_at = expires_val;
    }

    cookie_entry *found = 0, *slot;
    int free_slot = -1, evict_slot = 0;
    uint64_t evict_lru = 0; int have_evict = 0;
    for (int i = 0; i < COOKIE_JAR_N; i++) {
        cookie_entry *e = &jar->entries[i];
        if (!e->valid) { if (free_slot < 0) free_slot = i; continue; }
        if (!have_evict || e->last_used < evict_lru) { evict_lru = e->last_used; evict_slot = i; have_evict = 1; }
        if ((int)c_len(e->name) == name_len && mem_eq(e->name, name, name_len) &&
            str_eq(e->domain, domain_final) && str_eq(e->path, path_final))
            found = e;
    }

    if (is_deletion) { if (found) found->valid = 0; return; }

    slot = found ? found : (free_slot >= 0 ? &jar->entries[free_slot] : &jar->entries[evict_slot]);
    slot->valid = 1;
    copy_bounded(slot->name, sizeof slot->name, name, name_len);
    copy_bounded(slot->value, sizeof slot->value, value, value_len);
    copy_bounded(slot->domain, sizeof slot->domain, domain_final, c_len(domain_final));
    copy_bounded(slot->path, sizeof slot->path, path_final, c_len(path_final));
    slot->expires_at = expires_at;
    slot->secure = secure;
    slot->http_only = http_only;
    slot->host_only = host_only;
    slot->last_used = ++jar->clock;
}

int cookie_jar_build_header(cookie_jar *jar, const char *host, const char *path,
                            int is_https, uint64_t now, char *out, int outcap)
{
    int hlen = c_len(host), plen = c_len(path);
    int n = 0;
    for (int i = 0; i < COOKIE_JAR_N; i++) {
        cookie_entry *e = &jar->entries[i];
        if (!e->valid) continue;
        if (e->expires_at != 0 && e->expires_at <= now) { e->valid = 0; continue; }
        if (e->secure && !is_https) continue;
        int dlen = c_len(e->domain);
        if (e->host_only) { if (!ci_eq(host, hlen, e->domain, dlen)) continue; }
        else if (!domain_match(host, hlen, e->domain, dlen)) continue;
        if (!path_match(path, plen, e->path, c_len(e->path))) continue;

        int namelen = c_len(e->name), vallen = c_len(e->value);
        int need = namelen + 1 + vallen + (n > 0 ? 2 : 0);
        if (n + need > outcap) continue;   /* skip rather than truncate mid-cookie */
        if (n > 0) { out[n++] = ';'; out[n++] = ' '; }
        for (int k = 0; k < namelen; k++) out[n++] = e->name[k];
        out[n++] = '=';
        for (int k = 0; k < vallen; k++) out[n++] = e->value[k];
        e->last_used = ++jar->clock;
    }
    return n;
}
