/* Shared helpers for the KAT tests: the deterministic data generator and digest
 * that tools/gen_kats.py mirrors, and a parser for "Name = value" KAT files. */
#ifndef CA_KAT_COMMON_H
#define CA_KAT_COMMON_H
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void kat_bytes(uint32_t seed, uint8_t *out, size_t n)
{
    uint32_t x = (uint32_t)(seed * 0x9E3779B9u + 0x7F4A7C15u);
    if (!x) x = 1;
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        out[i] = (uint8_t)x;
    }
}

static uint64_t fnv1a64(const uint8_t *p, size_t n)
{
    uint64_t h = 0xCBF29CE484222325ull;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x100000001B3ull;
    }
    return h;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Strict: every byte must be exactly two hex digits and the whole field must be
 * consumed; anything else (odd length, stray character, overflow) aborts the test
 * run rather than decoding to something plausible. */
static size_t hex2bin(const char *h, uint8_t *out, size_t cap)
{
    if (!h) { fprintf(stderr, "kat: missing field\n"); exit(2); }
    size_t n = 0;
    while (*h) {
        int a = hexval(h[0]), b = a < 0 ? -1 : hexval(h[1]);
        if (a < 0 || b < 0) { fprintf(stderr, "kat: malformed hex near '%.8s'\n", h); exit(2); }
        if (n >= cap) { fprintf(stderr, "kat: hex field overflow\n"); exit(2); }
        out[n++] = (uint8_t)(a << 4 | b);
        h += 2;
    }
    return n;
}

/* A fixed-size field: decodes and insists on exactly `want` bytes. */
static void hex_exact(const char *h, uint8_t *out, size_t want)
{
    if (hex2bin(h, out, want) != want) { fprintf(stderr, "kat: field length != %zu\n", want); exit(2); }
}

/* Unsigned numeric field that must be present and well formed: digits only (no
 * sign, no space), no overflow, and at most `max`. */
static unsigned long long kat_num_max(const char *v, int base, unsigned long long max)
{
    if (!v || !*v) { fprintf(stderr, "kat: missing numeric field\n"); exit(2); }
    for (const char *q = v; *q; q++)
        if (hexval(*q) < 0 || hexval(*q) >= base) { fprintf(stderr, "kat: malformed number '%s'\n", v); exit(2); }
    char *end;
    errno = 0;
    unsigned long long x = strtoull(v, &end, base);
    if (*end || errno == ERANGE || x > max) { fprintf(stderr, "kat: number '%s' out of range\n", v); exit(2); }
    return x;
}
#define kat_num(v, base) kat_num_max((v), (base), ~0ULL)
#define kat_u32(v) ((uint32_t)kat_num_max((v), 10, 0xffffffffULL))
#define kat_size(v) ((size_t)kat_num_max((v), 10, (size_t)-1 > (1ULL << 32) ? (1ULL << 32) : (size_t)-1))

/* One record of a KAT file: up to 12 fields. */
typedef struct {
    char name[12][16];
    char *val[12];
    int n;
} kat_rec;

/* A KAT file embedded in the binary (tools/embed_kats.py). */
typedef struct { const char *p, *end; } kat_src;

static int kat_getline(kat_src *s, char *line, size_t cap)
{
    if (s->p >= s->end || !*s->p) return 0;
    size_t n = 0;
    while (s->p < s->end && *s->p && *s->p != '\n') {
        if (n + 2 >= cap) { fprintf(stderr, "kat: line too long\n"); exit(2); }
        line[n++] = *s->p++;
    }
    if (s->p < s->end && *s->p == '\n') s->p++;
    line[n++] = '\n';
    line[n] = 0;
    return 1;
}

/* Reads the next blank-line-separated record; returns 0 at EOF. Values are
 * malloc'd and freed by kat_free. */
#ifndef KAT_LINE_MAX
#define KAT_LINE_MAX 300000 /* the on-board build sets 4096 (longest KAT line: 1029); overflow is fatal */
#endif
static int kat_next(kat_src *f, kat_rec *r)
{
    static char line[KAT_LINE_MAX];
    r->n = 0;
    while (kat_getline(f, line, sizeof line)) {
        if (line[0] == '#') continue;
        if (line[0] == '\n' || line[0] == '\r') {
            if (r->n) return 1;
            continue;
        }
        char *eq = strstr(line, " = ");
        char *val;
        if (eq) val = eq + 3;
        else if ((eq = strstr(line, " =")) != NULL) val = eq + 2;
        else continue;
        *eq = 0;
        if (r->n >= 12) { fprintf(stderr, "kat: too many fields\n"); exit(2); }
        snprintf(r->name[r->n], sizeof r->name[0], "%s", line);
        size_t L = strlen(val);
        while (L && (val[L - 1] == '\n' || val[L - 1] == '\r')) val[--L] = 0;
        r->val[r->n] = strdup(val);
        r->n++;
    }
    return r->n > 0;
}

static const char *kat_get(const kat_rec *r, const char *name)
{
    for (int i = 0; i < r->n; i++)
        if (!strcmp(r->name[i], name)) return r->val[i];
    return NULL;
}

static void kat_free(kat_rec *r)
{
    for (int i = 0; i < r->n; i++) free(r->val[i]);
    r->n = 0;
}
#endif
