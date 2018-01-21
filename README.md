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
