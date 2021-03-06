/*
    this is free and unencumbered software released into the
    public domain

    refer to the attached UNLICENSE or http://unlicense.org/

    see jniproxy.c for documentation
*/

static int hooks_init();

#define JNIPROXY_IMPLEMENTATION
#define JNIPROXY_MONOLITHIC
#define JNIPROXY_INIT hooks_init
#include "jniproxy.c"

#define log_traceback(L, msg) \
    luaL_traceback_(L, L, msg, 1), \
    log1(lua_tolstring_(L, -1, 0)), \
    lua_settop_(L, -2)

/* ------------------------------------------------------------- */

/* just some macros to reduce redundancy */

#define PRE_(x, pre) pre##x
#define PRE(x, pre) PRE_(x, pre)

#define SIMPLE_TRAMPOLINE(fname) \
typedef sig(PRE(fname, fn)); \
static PRE(fname, fn) * fname = 0;

#define TRAMPOLINE SIMPLE_TRAMPOLINE(f)
#define AOB static const uint8_t PRE(aob, f)[]
#define HOOK static sig(PRE(hook, f))

/* TODO: see how well wildcarding bytes works on arm */
/* TODO: wildcards for x86 at least */

/* ------------------------------------------------------------- */

#define f HMAC_SHA1_
#define sig(name) \
int name(void* this, uint8_t const* data, int datalen, \
    uint8_t const* key, int keylen, uint8_t *digest)

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x55,
    0x53,
    0x57,
    0x56,
    0x83, 0xEC, 0x0C,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x5B,
    0x81, 0xC3, 0x54, 0xA1, 0x25, 0x00, /* TODO: wildcard this */
    0x8B, 0x74, 0x24, 0x30,
    0x8B, 0x44, 0x24, 0x28,
    0x8B, 0x7C, 0x24, 0x20
};
#else
AOB = {
    0xF0, 0x4F, 0x2D, 0xE9, 0x04, 0xD0, 0x4D, 0xE2,
    0x02, 0x50, 0xA0, 0xE1, 0x40, 0xA0, 0x85, 0xE2,
};
#endif

TRAMPOLINE

HOOK {
    char* buf = 0;
    size_t nb = 0;
    int res;

    log_return_address();
    log_bytes("key", key, keylen, &buf, &nb);
    log("data = %s", (char const*)data);
    log_bytes("data", data, datalen, &buf, &nb);
    res = f(this, data, datalen, key, keylen, digest);
    log_bytes("digest", digest, 20, &buf, &nb);
    free(buf);

    return res;
}

#undef sig
#undef f

/* ------------------------------------------------------------- */

#if JNIPROXY_ARCH == JNIPROXY_ARM
#define f CKLBUtility__SHA1BigEndianDWords_
#define sig(name) \
int name(uint8_t* dst, uint8_t const* data, uint32_t len)

AOB = {
    0xF0, 0x41, 0x2D, 0xE9, 0x70, 0xD0, 0x4D, 0xE2,
    0x00, 0x40, 0xA0, 0xE1, 0x18, 0x01, 0x9F, 0xE5
};

TRAMPOLINE

HOOK {
    char* buf = 0;
    size_t nb = 0;
    int res;

    log_return_address();
    log("data = %s", (char const*)data);
    log_bytes("data", data, len, &buf, &nb);
    res = f(dst, data, len);
    log_bytes("digest", dst, 20, &buf, &nb);
    free(buf);

    return res;
}

#undef sig
#undef f
#endif

/* ------------------------------------------------------------- */

#define f make_auth_stuff_
#define sig(name) \
int name(void *a1, char *username, char *password, char **pheader)

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x55,
    0x53,
    0x57,
    0x56,
    0x81, 0xEC, 0x1C, 0x04, 0x00, 0x00,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x5B,
    0x81, 0xC3, 0x81, 0x7B, 0x25, 0x00 /* TODO: wildcard this */
};
#else
AOB = {
    0xF0, 0x4F, 0x2D, 0xE9, 0x14, 0xD0, 0x4D, 0xE2,
    0x01, 0xDB, 0x4D, 0xE2, 0x0C, 0x03, 0x9F, 0xE5
};
#endif

TRAMPOLINE

HOOK {
    int res;

    log_return_address();
    log("a1 = %s", a1);
    log("username = %s", username);
    log("password = %s", password);
    res = f(a1, username, password, pheader);
    log("*pheader = %s", *pheader);

    return res;
}

#undef sig
#undef f

/* ------------------------------------------------------------- */

#define f base64_encode_wrapper_
#define sig(name) \
int name(uint8_t const* data, int len, char* dst, int *err)

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x53,
    0x56,
    0x83, 0xEC, 0x14,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x5B,
    0x81, 0xC3, 0x06, 0x8F, 0x26, 0x00 /* TODO: wildcard this */
};
#else
AOB = {
    0x10, 0x40, 0x2D, 0xE9, 0x03, 0x40, 0xA0, 0xE1,
    0x01, 0x30, 0xA0, 0xE1, 0x00, 0x10, 0xA0, 0xE1
};
#endif

TRAMPOLINE

HOOK {
    int res;
    char* hexstr = 0;
    size_t nb = 0;

    log_return_address();
    log("data: %s", (char const*)data);
    log_bytes("data", data, len, &hexstr, &nb);
    res = f(data, len, dst, err);
    log("result: %s", dst);
    free(hexstr);

    return res;
}

#undef sig
#undef f

/* ------------------------------------------------------------- */

#define f base64_decode_wrapper_
#define sig(name) \
int name(char const* src, uint8_t* dst, int* err)

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x53,
    0x56,
    0x83, 0xEC, 0x14,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x5B,
    0x81, 0xC3, 0xC6, 0x8E, 0x26, 0x00 /* TODO: wildcard this */
};
#else
AOB = {
    0x10, 0x40, 0x2D, 0xE9, 0x02, 0x40, 0xA0, 0xE1,
    0x00, 0x20, 0xA0, 0xE1, 0x01, 0x00, 0xA0, 0xE1
};
#endif

TRAMPOLINE

HOOK {
    int res;
    char* buf = 0;
    size_t nb = 0;
    size_t len;

    log_return_address();
    log("src = %s", src);
    res = f(src, dst, err);
    len = (strlen(src) * 3) / 4;
    log_bytes("dst", dst, len, &buf, &nb);
    free(buf);

    return res;
}

#undef sig
#undef f

/* ------------------------------------------------------------- */

#define f encrypt_string_
#define sig(name) \
int name(int len, char *data, int datalen, \
    uint8_t* key, int keylen, char **result)

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x55,
    0x53,
    0x57,
    0x56,
    0x83, 0xEC, 0x2C,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x5B,
    0x81, 0xC3, 0x54, 0x7D, 0x25, 0x00 /* TODO: wildcard this */
};
#else
AOB = {
    0xF0, 0x4B, 0x2D, 0xE9, 0x10, 0xD0, 0x4D, 0xE2,
    0x02, 0x60, 0xA0, 0xE1, 0x64, 0x70, 0x86, 0xE2
};
#endif

TRAMPOLINE

HOOK {
    int res;
    char* buf = 0;
    size_t nb = 0;

    log_return_address();
    log("data: %s", data);
    log_bytes("key", key, keylen, &buf, &nb);
    res = f(len, data, datalen, key, keylen, result);
    log("*result: %s", *result);
    free(buf);

    return res;
}

#undef sig
#undef f

/* ------------------------------------------------------------- */

#define f generate_key_
#define sig(name) \
int name(void* this, char const* data, char** pdst)

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x55,
    0x53,
    0x57,
    0x56,
    0x83, 0xEC, 0x1C,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x5B,
    0x81, 0xC3, 0x04, 0x80, 0x25, 0x00 /* TODO: wildcard this */
};
#else
AOB = {
    0xF0, 0x48, 0x2D, 0xE9, 0x08, 0xD0, 0x4D, 0xE2,
    0x02, 0x40, 0xA0, 0xE1, 0x01, 0x70, 0xA0, 0xE1
};
#endif

TRAMPOLINE

HOOK {
    char *buf = 0;
    size_t nb = 0;
    int res;

    log_return_address();
    log("data = %s", data);
    res = f(this, data, pdst);
    log("*pdst = %s", *pdst);
    log_bytes("*pdst", (uint8_t const*)*pdst, 32, &buf, &nb);
    free(buf);

    return res;
}

#undef sig
#undef f

/* ------------------------------------------------------------- */

#if JNIPROXY_ARCH == JNIPROXY_ARM
#define f CAndroidRequest__getRandomBytes_
#define sig(name) int name(void* this, uint8_t* data, int n)

AOB = {
    0x10, 0x40, 0x2D, 0xE9, 0x18, 0xD0, 0x4D, 0xE2,
    0x4C, 0x00, 0x9F, 0xE5, 0x44, 0xE0, 0x9F, 0xE5
};

TRAMPOLINE

HOOK {
    int res;
    char* buf = 0;
    size_t nb = 0;

    log_return_address();
    res = f(this, data, n);
    log_bytes("data", data, n, &buf, &nb);
    free(buf);

    return res;
}

#undef sig
#undef f
#endif

/* ------------------------------------------------------------- */

#define f luaL_traceback_
#define sig(name) \
void name(void* L, void* L1, char const* msg, int level)

TRAMPOLINE

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x55,
    0x53,
    0x57,
    0x56,
    0x81, 0xEC, 0xFC, 0x00, 0x00, 0x00,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x5B,
    0x81, 0xC3, 0x71, 0x7F, 0x3D, 0x00 /* TODO: wildcard this */
};
#else
AOB = {
    0xF0, 0x4F, 0x2D, 0xE9, 0x41, 0xDF, 0x4D, 0xE2,
    0x00, 0x80, 0xA0, 0xE1, 0x84, 0x03, 0x9F, 0xE5
};
#endif

#undef sig
#undef f

/* ------------------------------------------------------------- */

#define f lua_tolstring_
#define sig(name) char const* name(void* L, int idx, size_t *len)

TRAMPOLINE

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x55,
    0x53,
    0x57,
    0x56,
    0x83, 0xEC, 0x0C,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x5B,
    0x81, 0xC3, 0xC4, 0xA1, 0x3D, 0x00 /* TODO: wildcard this */
};
#else
AOB = {
    0x70, 0x40, 0x2D, 0xE9, 0x00, 0x60, 0xA0, 0xE1,
    0x01, 0x50, 0xA0, 0xE1, 0x10, 0x00, 0x96, 0xE5
};
#endif

#undef sig
#undef f

/* ------------------------------------------------------------- */

#define f lua_settop_
#define sig(name) void name(void* L, int index)

TRAMPOLINE

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x56,
    0x8B, 0x54, 0x24, 0x0C,
    0x8B, 0x44, 0x24, 0x08,
    0x85, 0xD2,
    0x78, 0x29,
    0x8B, 0x48, 0x08
};
#else
AOB = {
    0x00, 0x48, 0x2D, 0xE9, 0x00, 0x00, 0x51, 0xE3,
    0x15, 0x00, 0x00, 0xBA, 0x10, 0x20, 0x90, 0xE5
};
#endif

#undef sig
#undef f

/* ------------------------------------------------------------- */

#define f lua_gettop_
#define sig(name) int name(void* L)

TRAMPOLINE

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x8B, 0x44, 0x24, 0x04,
    0x8B, 0x48, 0x08,
    0x8B, 0x40, 0x10,
    0x8B, 0x00,
    0x83, 0xC0, 0x0C
};
#else
AOB = {
    0x08, 0x10, 0x90, 0xE5, 0x10, 0x00, 0x90, 0xE5,
    0x00, 0x00, 0x90, 0xE5, 0x10, 0x00, 0x80, 0xE2
};
#endif

#undef sig
#undef f

/* ------------------------------------------------------------- */

#define f lua_isstring_
#define sig(name) int name(void* L, int idx);

TRAMPOLINE

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x56,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x58,
    0x81, 0xC0, 0x0A, 0xAA, 0x3D, 0x00, /* TODO: wildcard this */
    0x8B, 0x4C, 0x24, 0x0C
};
#else
AOB = {
    0x10, 0x20, 0x90, 0xE5, 0x01, 0x00, 0x51, 0xE3,
    0x06, 0x00, 0x00, 0xBA, 0x00, 0x20, 0x92, 0xE5
};
#endif

#undef sig
#undef f

/* ------------------------------------------------------------- */

#define f CKLBLuaLibCRYPTO__luaRandomBytes_
#define sig(name) int name(void* L)

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x55,
    0x53,
    0x57,
    0x56,
    0x83, 0xEC, 0x1C,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x5B,
    0x81, 0xC3, 0x84, 0x87, 0x24, 0x00 /* TODO: wildcard this */
};
#else
AOB = {
    0x30, 0x48, 0x2D, 0xE9, 0x08, 0xD0, 0x4D, 0xE2,
    0x00, 0x10, 0xA0, 0xE1, 0x0D, 0x00, 0xA0, 0xE1
};
#endif

TRAMPOLINE

HOOK {
#if JNIPROXY_ARCH == JNIPROXY_X86
    char* buf = 0;
    size_t nb = 0;
    size_t reslen = 0;
    uint8_t* rand = 0;
#endif
    int res;

    log_traceback(L, "");
    res = f(L);
#if JNIPROXY_ARCH == JNIPROXY_X86
    rand = (uint8_t*)lua_tolstring_(L, -1, &reslen);
    log_bytes("data", rand, reslen, &buf, &nb);
#endif

    return res;
}

#undef f

/* ------------------------------------------------------------- */

#define f CKLBLuaLibCRYPTO__luaXorCipher_

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x55,
    0x53,
    0x57,
    0x56,
    0x83, 0xEC, 0x3C,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x5B,
    0x81, 0xC3, 0x24, 0x8F, 0x24, 0x00 /* TODO: wildcard this */
};
#else
AOB = {
    0xF0, 0x48, 0x2D, 0xE9, 0x10, 0xD0, 0x4D, 0xE2,
    0x00, 0x10, 0xA0, 0xE1, 0x08, 0x00, 0x8D, 0xE2
};
#endif

TRAMPOLINE

HOOK {
    char const* str1 = 0;
    size_t str1len = 0;
    char const* str2 = 0;
    size_t str2len = 0;
    int res;
    char* buf = 0;
    size_t nb = 0;

    log_traceback(L, "");
    if (lua_gettop_(L) != 2) {
        log1("invalid number of args");
        goto exit;
    }

    if (!lua_isstring_(L, 1)) {
        log1("invalid str1");
        goto exit;
    }

    str1 = lua_tolstring_(L, 1, &str1len);
    if (!str1) {
        log1("null str1");
        goto exit;
    }

    log("str1: %s", str1);
    log_bytes("str1", (uint8_t const*)str1, str1len, &buf, &nb);

    str2 = lua_tolstring_(L, 2, &str2len);
    if (!str2) {
        log1("null str1");
        goto exit;
    }

    log_bytes("str2", (uint8_t const*)str2, str2len, &buf, &nb);

    if (str1len != str2len) {
        log1("strings length mismatch");
    }

exit:
    free(buf);
    res = f(L);

    if (res)
    {
        size_t resultlen = 0;
        char const* result = lua_tolstring_(L, -1, &resultlen);
        log("result: %s", result);

        log_bytes("result",
            (uint8_t const*)result, resultlen, &buf, &nb);
    }

    return res;
}

#undef sig
#undef f

/* ------------------------------------------------------------- */

#define f CAndroidRequest__callJavaMethod_
#define sig(name) \
int name(int this, void *unk, void* jval, char const* method, \
    char rettype, char const* form, void* a1, void* a2, void* a3, \
    void* a4, void* a5, void* a6, void* a7, void* a8, void* a9, \
    void* a10, void* a11, void* a12, void* a13, void* a14, \
    void* a15, void* a16)

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x55,
    0x53,
    0x57,
    0x56,
    0x81, 0xEC, 0x8C, 0x04, 0x00, 0x00,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x5B,
    0x81, 0xC3, 0x91, 0xAF, 0x1B, 0x00 /* TODO: wildcard this */
};
#else
AOB = {
    0xF0, 0x4F, 0x2D, 0xE9, 0x74, 0xD0, 0x4D, 0xE2,
    0x01, 0xDB, 0x4D, 0xE2, 0xA4, 0x09, 0x9F, 0xE5
};
#endif

TRAMPOLINE

HOOK {
    static char const* const blacklist[] = {
        "webview_getText",
        "webview_update",
        "textbox_getText",
        0
    };

    char const* const* p;

    for (p = blacklist; *p; ++p) {
        if (!strcmp(method, *p)) {
            goto exit;
        }
    }

    log1(method);

exit:
    return f(this, unk, jval, method, rettype, form, a1, a2, a3,
        a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16);
}

#undef sig
#undef f

/* ------------------------------------------------------------- */

#define f CAndroidRequest__publicKeyEncrypt_
#define sig(name) \
int name(void *this, uint8_t const* data, int len, \
    uint8_t* result, int result_size)

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x53,
    0x57,
    0x56,
    0x83, 0xEC, 0x40,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x5B,
    0x81, 0xC3, 0x95, 0xC5, 0x1A, 0x00 /* TODO: wildcard this */
};
#endif

TRAMPOLINE

HOOK {
    int res;
    char* buf = 0;
    size_t nb = 0;

    log_return_address();
    log("data: %s", data);
    log_bytes("data", data, len, &buf, &nb);
    res = f(this, data, len, result, result_size);
    log_bytes("result", result, res, &buf, &nb);
    free(buf);

    return res;
}

#undef sig
#undef f

/* ------------------------------------------------------------- */

#define f curl_easy_setopt_
#define sig(name) \
int __cdecl name(void* handle, CURLoption option, ...)

#define CURLOPTTYPE_LONG          0
#define CURLOPTTYPE_FUNCTIONPOINT 20000

#define CINIT(na,t,nu) CURLOPT_ ## na = CURLOPTTYPE_ ## t + nu

typedef enum
{
    CINIT(DEBUGFUNCTION, FUNCTIONPOINT, 94),
    CINIT(VERBOSE, LONG, 41),
}
CURLoption;

TRAMPOLINE

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x53,
    0xE8, 0x2A, 0x92, 0xD1, 0xFF
};
#endif

#undef sig
#undef f

/* ------------------------------------------------------------- */

#define f Curl_open_
#define sig(name) \
int __cdecl name(void* data)

TRAMPOLINE

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x8D, 0x64, 0x24, 0xD4,
    0x89, 0x5C, 0x24, 0x1C,
    0x89, 0x74, 0x24, 0x20,
    0xE8, 0x5F, 0x94, 0xD0, 0xFF /* TODO: wildcard this */
};
#endif

#undef sig
#undef f

/* ------------------------------------------------------------- */

#define f curl_global_init_
#define sig(name) \
int __cdecl name(int a1)

#define CURL_GLOBAL_SSL (1<<0)
#define CURL_GLOBAL_WIN32 (1<<1)
#define CURL_GLOBAL_ALL (CURL_GLOBAL_SSL|CURL_GLOBAL_WIN32)
#define CURL_GLOBAL_DEFAULT CURL_GLOBAL_ALL

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x53,
    0xE8, 0x0A, 0x94, 0xD1, 0xFF
};
#endif

TRAMPOLINE

#undef sig
#undef f

/* ------------------------------------------------------------- */

#define f curl_easy_init_
#define sig(name) \
void* name()

#if JNIPROXY_ARCH == JNIPROXY_X86
AOB = {
    0x53,
    0xE8, 0x7A, 0x92, 0xD1, 0xFF
};
#endif

TRAMPOLINE

typedef enum
{
    CURLINFO_TEXT = 0,
    CURLINFO_HEADER_IN,    /* 1 */
    CURLINFO_HEADER_OUT,   /* 2 */
    CURLINFO_DATA_IN,      /* 3 */
    CURLINFO_DATA_OUT,     /* 4 */
    CURLINFO_SSL_DATA_IN,  /* 5 */
    CURLINFO_SSL_DATA_OUT, /* 6 */
    CURLINFO_END
}
curl_infotype;

int curl_dump(void* handle, curl_infotype type, char* data,
    size_t size, void* userp)
{
    char const* text = "?? Unknown";
    char* sdata;

    (void)handle;
    (void)userp;

    switch (type) {
    case CURLINFO_HEADER_OUT:
        text = "=> Send header";
        break;
    case CURLINFO_DATA_OUT:
        text = "=> Send data";
        break;
    case CURLINFO_SSL_DATA_OUT:
        text = "=> Send SSL data";
        break;
    case CURLINFO_HEADER_IN:
        text = "<= Recv header";
        break;
    case CURLINFO_DATA_IN:
        text = "<= Recv data";
        break;
    case CURLINFO_SSL_DATA_IN:
        text = "<= Recv SSL data";
        break;
    default:
    case CURLINFO_TEXT:
        return 0;
    }

    sdata = malloc(size + 1);
    if (sdata) {
        memcpy(sdata, data, size);
        sdata[size] = 0;
    }
    log("(%s) %s", text, sdata);
    free(sdata);

    return 0;
}

int* pcurl_initialized = 0;

/* for some reason the trampoline crashes so i rewrote the func */
/* most likely rip-relative stuff that I didn't notice */
void* original_curl_easy_init()
{
    int result;
    void* data;

    if (!*pcurl_initialized)
    {
        result = curl_global_init_(CURL_GLOBAL_DEFAULT);
        if (result) {
            return 0;
        }
    }

    result = Curl_open_(&data);
    if (result) {
        return 0;
    }

    return data;
}

HOOK {
    void* res;

    log_return_address();
    res = original_curl_easy_init();

    curl_easy_setopt_(res, CURLOPT_DEBUGFUNCTION, curl_dump);
    curl_easy_setopt_(res, CURLOPT_VERBOSE, 1L);

    return res;
}

#undef sig
#undef f

/* ------------------------------------------------------------- */

static
int hooks_init()
{
    int err;
    void* base;

    base = m_base("libGame.so",
        "app_klb_android_GameEngine_PFInterface_frameFlip");
    if (!base) {
        return -1;
    }

    err = 0;
#ifdef JNIPROXY_JP
    #define h(a, b, nops) \
        m_hook(#b, base, 0x04000000, \
            (void*)a, b##aob, sizeof(b##aob), (void**)&b, \
            b##hook, nops)

    #define t(a, b, nops) \
        m_hook(#b, base, 0x04000000, \
            (void*)a, b##aob, sizeof(b##aob), (void**)&b, 0, nops)

    err |= h(0x0020C160, HMAC_SHA1_, 2);
    err |= h(0x0020E730, make_auth_stuff_, 5);
    err |= h(0x001FD3B0, base64_encode_wrapper_, 0);
    err |= h(0x0020E560, encrypt_string_, 2);
    err |= h(0x001FD3F0, base64_decode_wrapper_, 0);
    err |= h(0x0020E2B0, generate_key_, 2);
    err |= h(0x0021DB30, CKLBLuaLibCRYPTO__luaRandomBytes_, 2);
    err |= h(0x0021D390, CKLBLuaLibCRYPTO__luaXorCipher_, 2);
    err |= h(0x002AB320, CAndroidRequest__callJavaMethod_, 5);
    err |= h(0x002B9D20, CAndroidRequest__publicKeyEncrypt_, 1);
    err |= h(0x003115D0, curl_easy_init_, 1);
    err |= t(0x0008E340, luaL_traceback_, 5);
    err |= t(0x0008C0F0, lua_tolstring_, 2);
    err |= t(0x0008B1E0, lua_settop_, 0);
    err |= t(0x0008B1C0, lua_gettop_, 2);
    err |= t(0x0008B8B0, lua_isstring_, 1);
    err |= t(0x00311620, curl_easy_setopt_, 1);
    err |= t(0x003213E0, Curl_open_, 3);
    err |= t(0x00311440, curl_global_init_, 1);

    /* can be found in the original curl_easy_init */
    pcurl_initialized = (int*)((char*)base + 0x00517A8C);
#else
    #define h(a, b) \
        m_hook(#b, base, 0x04000000, \
            (void*)a, b##aob, sizeof(b##aob), (void**)&b, b##hook)

    #define t(a, b) \
        m_hook(#b, base, 0x04000000, \
            (void*)a, b##aob, sizeof(b##aob), (void**)&b, 0)

    err |= h(0x002FB350, HMAC_SHA1_);
    err |= h(0x00292C4C, CKLBUtility__SHA1BigEndianDWords_);
    err |= h(0x002FDA44, make_auth_stuff_);
    err |= h(0x00292C08, base64_encode_wrapper_);
    err |= h(0x002FD8C4, encrypt_string_);
    err |= h(0x00292C2C, base64_decode_wrapper_);
    err |= h(0x002FD69C, generate_key_);
    err |= h(0x00363600, CAndroidRequest__getRandomBytes_);
    err |= h(0x00326D64, CKLBLuaLibCRYPTO__luaRandomBytes_);
    err |= h(0x00323A54, CKLBLuaLibCRYPTO__luaXorCipher_);
    err |= h(0x00357AB0, CAndroidRequest__callJavaMethod_);
    err |= t(0x00245450, luaL_traceback_);
    err |= t(0x0025EA24, lua_tolstring_);
    err |= t(0x0025D5A8, lua_settop_);
    err |= t(0x0025D58C, lua_gettop_);
    err |= t(0x0025DF40, lua_isstring_);
#endif

    if (err) {
        return err;
    }

    #undef h
    #undef t

    log1("ready");

    return 0;
}
