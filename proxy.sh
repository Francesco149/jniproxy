#!/system/bin/sh

libdir="$SIF_LIBDIR"
rcname="$SIF_RCNAME"

if [ ! -e $libdir/libjniproxy.so.bak ]; then
    su -c \
        "cp -v '$libdir/libjniproxy.so' '$libdir/libjniproxy.so.bak'"
fi

fix_permissions()
{
    su -c "chown -v system:system '$1'"
    su -c "chmod -v 0755 '$1'"
}

su -c "cp -v '$HOME/libjniproxy.so' '$libdir'"
fix_permissions "$libdir/libjniproxy.so"
fix_permissions "$libdir/libjniproxy.so.bak"

ln -svf "$rcname" "$HOME/.sifrc"
sif start
