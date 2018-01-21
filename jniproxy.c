/*
    this is free and unencumbered software released into the
    public domain

    refer to the attached UNLICENSE or http://unlicense.org/

    introduction
    -----------------------------------------------------------
    ARM hooking framework for love live school idol festival

    ![](https://i.imgur.com/zcmcjD5.png)

    this is a proxy/stub library for libjniproxy.so. it can be
    used to easily read memory, hook, and call the
    game's functions from within the game process without
    relying on LD_PRELOAD or existing hooking frameworks

    it comes with some hooks that log calls for crypto
    function and a few others as well as printing the lua
    stacktrace for functions called from lua

    rationale: I couldn't get LD_PRELOAD to work on my qemu
    android x86 virtual machine and I'm too lazy to use a real
    android device lol

    NOTE: it's highly recommended that you compile this from
    source and check the code yourself, as malicious code could
    be easily injected through it. always get binaries
    and source from a trusted source (in this case my github,
    Francesco149). never share the logcat from this tool
    with other people, it may contain your account and device
    information!

    compile and install the built-in hooks
    -----------------------------------------------------------
    compiling is linux-only for the time being. if you're a
    windows user and know how to set a build up, feel free to
    write a guide and pull request

    ```sh
    chmod +x ./build
    CC=~/arm/bin/clang ./build
    # change clang path to where your arm compiler is
    # you can also download a pre-built .so from github if you
    # are on windows or don't want to compile

    adb root
    adb shell
    cd /data/app/klb.lovelive_en-1/lib/arm/
    mv libjniproxy.so libjniproxy.so.bak
    exit
    adb push libjniproxy.so /data/app/klb.lovelive_en-1/lib/arm/
    adb shell
    cd /data/app/klb.lovelive_en-1/lib/arm/
    chmod 755 libjniproxy.so
    chown system:system libjniproxy.so

    # start the game and do whatever you need to log

    adb shell logcat -d | grep jniproxy
    ```

    framework
    -----------------------------------------------------------
    example that hooks CAndroidRequest::getRandomBytes

    read the declarations at the top of jniproxy.c for more
    information

    myhook.c

    ```c
    int hooks_init();

    #define JNIPROXY_IMPLEMENTATION
    #define JNIPROXY_MONOLITHIC
    #define JNIPROXY_INIT hooks_init
    #include "jniproxy.c"

    #define sig(name) int name(void* this, uint8_t* data, int n)

    typedef sig(func);
    static func* trampoline = 0;

    static sig(hook)
    {
        int res;
        char* buf = 0;
        size_t nb = 0;

        log("> called from %p", __builtin_return_address(0));
        res = trampoline(this, data, n);
        log_bytes("data", data, n, &buf, &nb);
        free(buf);

        return res;
    }

    static
    int hooks_init()
    {
        int err;
        void* base = m_base("libGame.so",
            "app_klb_android_GameEngine_PFInterface_frameFlip");

        if (!base) {
            return -1;
        }

        m_hook("CAndroidRequest::getRandomBytes",
            base, 0, (void*)0x003490A0, 0, 0,
            (void**)&trampoline, hook);

        return 0;
    }
    ```

    build

    ```sh
    #!/bin/sh

    CFLAGS="-fPIC $CFLAGS"
    LDFLAGS="-shared -llog -ldl $LDFLAGS"
    $CC $CFLAGS myhook.c $LDFLAGS -o libjniproxy.so

    ```

    see main.c for advanced usage examples
*/

#ifndef WHOAMI
#define WHOAMI "jniproxy_stub"
#endif

#ifndef JNIPROXY_H
#define JNIPROXY_H

#define JNIPROXY_VERSION_MAJOR 1
#define JNIPROXY_VERSION_MINOR 0
#define JNIPROXY_VERSION_PATCH 0

/* tested on the 20180106 dump */

#define CLIENT_VERSION_MAJOR 14
#define CLIENT_VERSION_MINOR 0
#define CLIENT_VERSION_PATCH 76

#define BUNDLE_VERSION_MAJOR 5
#define BUNDLE_VERSION_MINOR 2
#define BUNDLE_VERSION_PATCH 1

#include <stdint.h>
#include <stdio.h>
#include <android/log.h>
#include <sys/mman.h>
#include <dlfcn.h>

/* ------------------------------------------------------------- */

/* logging functions, they print to logcat */

#define log(fmt, ...) \
    __android_log_print( \
        ANDROID_LOG_DEBUG, WHOAMI, \
        "[%s:%d:%s] " fmt, __FILE__, __LINE__, __func__, \
        __VA_ARGS__ \
    )

#define log1(msg) log("%s", msg)
#define log_return_address() \
    log("> called from %p", __builtin_return_address(0))

/* perror-like functions for dl errors and errno */
#define pdlerror(msg) log("%s: %s\n", msg, dlerror())
#define perror(msg) log("%s: %s\n", msg, strerror(errno))

/*
    automatically allocates and formats a byte array using m_hexstr
    and logs it. see m_hexstr for info
*/
#define log_bytes(name, b, n, p, max) \
    log("%s (bytes) = %s", name, m_hexstr(b, n, p, max));

/* ------------------------------------------------------------- */

/*
    make memory readadable, writable and executable. size is
    ceiled to a multiple of PAGESIZE and addr is aligned to
    PAGESIZE
*/
#define m_rwx(addr, n) \
    mprotect(PAGEOF(addr), PAGE_ROUND_UP(n), PROT_RWX)

#define PROT_RWX (PROT_READ | PROT_WRITE | PROT_EXEC)
#define PAGESIZE sysconf(_SC_PAGESIZE)
#define PAGEOF(addr) (void*)((int)(addr) & ~(PAGESIZE - 1))
#define PAGE_ROUND_UP(x) \
    ((((uintptr_t)(x)) + PAGESIZE - 1) & (~(PAGESIZE - 1)))

/* ------------------------------------------------------------- */

#define nvoid void __attribute__((naked))

#ifdef JNIPROXY_MONOLITHIC
#define JNIPROXYEXPORT static
#else
#define JNIPROXYEXPORT
#endif

/* ------------------------------------------------------------- */

/*
    dlsym with error handling, sets err to -1 on errors and prints
    the error to logcat
*/
JNIPROXYEXPORT
void* dlsym_(void* lib, char const* name, int* err);

/*
    formats bytes into a hex string such as AA BB CC.

    p is a pointer to the destination buffer, max is a pointer to
    the maximum size of the destination buffer.

    if *p is NULL or *max is less than n * 3 + 1, *p will be
    reallocated and *max will be updated accordingly

    returns *p
*/
JNIPROXYEXPORT
char* m_hexstr(uint8_t const* bytes, size_t n, char** p,
    size_t* max);

/*
    hooks base + address to unconditionally jump to hook

    if trampoline is non-null, a trampoline to call the original
    function is generated and *trampoline points to it

    trampoline generation only works with code that doesn't have
    instruction-relative opcodes at the moment

    if pattern is non-null, base + address will be checked against
    this it. if it doesn't match, the memory from base to base +
    size is scanned until pattern is matched

    if hook is null, no hooking will be performed but the trampoline
    will still be generated and the pattern will still be scanned
*/
JNIPROXYEXPORT
int m_hook(char const* description,
    void* base, size_t size, void* address,
    const uint8_t* pattern, size_t pattern_size,
    void** trampoline, void* hook);

/*
    finds the base address in memory of a shared library given
    its name and the name of a known exported function

    returns null on failure

    NOTE: this loads the library if it isn't already
*/
JNIPROXYEXPORT
void* m_base(char const* module_name, char const* known_export);

#endif /* JNIPROXY_H */

/* ############################################################# */
/* ############################################################# */
/* ############################################################# */

#ifdef JNIPROXY_IMPLEMENTATION

#include <stdlib.h>
#include <string.h>

#define JAVA_FUNC(func) \
    Java_klb_android_GameEngine_PFInterface_##func

static void* lib = 0;
static void* self = 0;

typedef int fnJNI_OnLoad(void* vm, void* reserved);
static fnJNI_OnLoad* JNI_OnLoad_ = 0;

JNIPROXYEXPORT
void* dlsym_(void* lib, char const* name, int* err)
{
    void* addr;
    char* errstr;

    *err = 0;
    dlerror(); /* clear dlerror */
    addr = dlsym(lib, name);
    errstr = dlerror();
    if (errstr) {
        log("dlsym: %s", errstr);
        *err = -1;
        return 0;
    }

    return addr;
}

JNIPROXYEXPORT
char* m_hexstr(uint8_t const* bytes, size_t n, char** p,
    size_t* max)
{
    size_t i;
    size_t req = n * 3 + 1;
    char* pfmt;

    if (!*p || *max < req)
    {
        *p = realloc(*p, req);
        if (!*p) {
            log1("out of memory");
            return 0;
        }

        *max = req;
    }

    for (pfmt = *p, i = 0; i < n; ++i) {
        pfmt += sprintf(pfmt, "%02X ", bytes[i]);
    }

    return *p;
}

JNIPROXYEXPORT
int m_hook(char const* description,
    void* base, size_t size, void* address,
    const uint8_t* pattern, size_t pattern_size,
    void** trampoline, void* hook)
{
    uint32_t* code = 0;
    size_t i;
    uint8_t* u8base = (uint8_t*)base;

    log("> %s", description);

    if (!address && !pattern) {
        log1("you must provide at least address or pattern");
        return -1;
    }

    if (address)
    {
        char* buf = 0;
        size_t nb = 0;
        uint8_t* absaddr = u8base + (uintptr_t)address;

        if (!memcmp(absaddr, pattern, pattern_size)) {
            code = (uint32_t*)absaddr;
            goto scandone;
        }

        log("W: %p did not match the pattern", absaddr);
        log_bytes("W: expected", pattern, pattern_size, &buf, &nb);
        log_bytes("W: got", absaddr, pattern_size, &buf, &nb);
        free(buf);
    }

    log1("scanning for the byte pattern");

    /* ghetto scan method TODO: enumerate memory mappings */
    for (i = 0; i < size; ++i)
    {
        if (!memcmp(u8base + i, pattern, pattern_size)) {
            code = (uint32_t*)(u8base + i);
            break;
        }
    }

    if (!code) {
        log1("scan failed");
        return -1;
    }

scandone:
    log("%p: %08X %08X", code, code[0], code[1]);

    if (trampoline)
    {
        uint32_t* trampoline_code;

        log1("generating trampoline");

        trampoline_code = (uint32_t*)malloc(4 * 4);
        if (!trampoline_code) {
            log1("out of memory");
            return -1;
        }

        if (m_rwx(trampoline_code, 4 * 4) < 0)
        {
            perror("mprotect");
            return -1;
        }

        memcpy(trampoline_code, code, 4 * 2);
        trampoline_code[2] = 0xE51FF004; /* ldr pc,[pc,#-4] */
        trampoline_code[3] = (uint32_t)(code + 2);
        *trampoline = trampoline_code;
    }

    if (!hook) {
        return 0;
    }

    log1("making memory rwx");

    if (m_rwx(code, 8) < 0) {
        perror("mprotect");
        return -1;
    }

    code[0] = 0xE51FF004; /* ldr pc,[pc,#-4] */
    code[1] = (uint32_t)hook;

    log("hooked %p -> %p", code, hook);

    return 0;
}

JNIPROXYEXPORT
void* m_base(char const* module_name, char const* known_export)
{
    int err;
    void* lib;
    void* export;
    Dl_info info;

    lib = dlopen(module_name, RTLD_LAZY);
    if (!lib) {
        pdlerror("dlopen");
        return 0;
    }

    export = dlsym_(lib, known_export, &err);
    if (err) {
        return 0;
    }

    if (!dladdr(export, &info)) {
        perror("dladdr");
        return 0;
    }

    log("%s is at %p", module_name, info.dli_fbase);

    return info.dli_fbase;
}

/* ------------------------------------------------------------- */

#define j2(x) #x
#define j1(x) j2(x)
#define j(x) j1(JAVA_FUNC(x))

static
char const* const functions[] = {
    j(initSequence),
    j(onKLabIdResult),
    j(setLoadAppPath),
    j(OnLocationCallback),
    j(OnNotificationCallback),
    j(frameFlip),
    j(inputPoint),
    j(inputDeviceKey),
    j(rotateScreenOrientation),
    j(toNativeSignal),
    j(getGLVersion),
    j(transformSignature),
    j(resetViewport),
    j(onActivityPause),
    j(onActivityResume),
    j(clientControlEvent),
    j(WebViewControlEvent),
    j(clientResumeGame),
    j(internalGetLocalizedMessage),
    "Java_extension_klb_LovelivePlatformGameAccountsIntegration_PFInterface_pfExtensionCallback",
    "Java_extension_klb_PfGameAccount_PFInterface_gpgsExtensionCallback",
    0
};

#undef j
#undef j1
#undef j2

static
int generate_trampoline(char const* name)
{
    int err;
    void* func;
    uint32_t* trampoline;

    func = dlsym_(lib, name, &err);
    if (err) {
        return -1;
    }

    trampoline = (uint32_t*)dlsym_(self, name, &err);
    if (err) {
        return -1;
    }

    log("%s | %p -> %p", name, trampoline, func);

    /* overwrite the jump placeholder */

    err = m_rwx(trampoline + 1, 4);
    if (err < 0) {
        perror("mprotect");
        return -1;
    }

    trampoline[1] = (uint32_t)func;

    return 0;
}

static
int generate_trampolines()
{
    char const* const* name;

    for (name = functions; *name; ++name)
    {
        int err = generate_trampoline(*name);
        if (err < 0) {
            return err;
        }
    }

    return 0;
}

static
int init()
{
    Dl_info info;
    char* original_name;
    int err;

    if (lib) {
        log1("W: tried to initialize stub twice");
        return 0;
    }

    log1("");
    log1("######################################################");
    log1("######################################################");
    log1("######################################################");
    log1("");

    log(
        "version %d.%d.%d initializing",
        JNIPROXY_VERSION_MAJOR,
        JNIPROXY_VERSION_MINOR,
        JNIPROXY_VERSION_PATCH
    );

    log(
        "target client version: %d.%d.%d",
        CLIENT_VERSION_MAJOR,
        CLIENT_VERSION_MINOR,
        CLIENT_VERSION_PATCH
    );

    log(
        "target bundle version: %d.%d.%d",
        BUNDLE_VERSION_MAJOR,
        BUNDLE_VERSION_MINOR,
        BUNDLE_VERSION_PATCH
    );

    if (!dladdr(init, &info)) {
        perror("dladdr");
        return -1;
    }

    log("running as %s", info.dli_fname);

    self = dlopen(info.dli_fname, RTLD_LAZY);
    if (!self) {
        pdlerror("dlopen (on self)");
        return -1;
    }

    /* load original .so (assumed to be name.bak) */

    original_name = malloc(strlen(info.dli_fname) + 5);
    if (!original_name) {
        log1("out of memory");
        return -1;
    }

    sprintf(original_name, "%s.bak", info.dli_fname);
    log("loading %s\n", original_name);
    lib = dlopen(original_name, RTLD_LAZY);
    if (!lib) {
        pdlerror("dlopen");
        return -1;
    }

    JNI_OnLoad_ = (fnJNI_OnLoad*)dlsym_(lib, "JNI_OnLoad", &err);
    if (err) {
        return -1;
    }

    err = generate_trampolines();
    if (err) {
        return -1;
    }

#ifdef JNIPROXY_INIT
    err = JNIPROXY_INIT();
    if (err < 0) {
        log("JNIPROXY_INIT failed with error %d", err);
        return err;
    }
#endif

    return 0;
}

int JNI_OnLoad(void* vm, void* reserved)
{
    init();
    return JNI_OnLoad_(vm, reserved);
}

static
void __attribute__((destructor)) cleanup()
{
    log1("terminating");

    if(!lib) {
        return;
    }

    if (dlclose(lib)) {
        pdlerror("dlclose");
    }
}

#define t(x) \
nvoid x() { \
    asm("ldr pc,[pc,#-4]"); \
    asm(".word 0xBAADF00D"); \
}
#define j(x) t(JAVA_FUNC(x))

/*
    since arm doesn't allow 32-bit immediate values I have to leave
    a placeholder (0xBAADF00D) after the code and reference it
    using [pc,#-4]. pc is 8 bytes after the current instructions,
    so #-4 reads 4 bytes after the current instruction.
    0xBAADF00D is then replaced by the correct address at runtime
*/

j(initSequence)
j(onKLabIdResult)
j(setLoadAppPath)
j(OnLocationCallback)
j(OnNotificationCallback)
j(frameFlip)
j(inputPoint)
j(inputDeviceKey)
j(rotateScreenOrientation)
j(toNativeSignal)
j(getGLVersion)
j(transformSignature)
j(resetViewport)
j(onActivityPause)
j(onActivityResume)
j(clientControlEvent)
j(WebViewControlEvent)
j(clientResumeGame)
j(internalGetLocalizedMessage)
t(Java_extension_klb_LovelivePlatformGameAccountsIntegration_PFInterface_pfExtensionCallback)
t(Java_extension_klb_PfGameAccount_PFInterface_gpgsExtensionCallback)

#undef t
#undef j
#undef nkd

#endif /* JNIPROXY_IMPLEMENTATION */
