#!/bin/sh
set -eu

# Prevent the Nix compiler wrapper from adding search paths that mask the test.
export NIX_DONT_SET_RPATH=1

# Both graphs are top -> middle -> leaf. In chain, each object finds its direct
# dependency; in scope, only top can find leaf, exposing RUNPATH inheritance rules.
# Single quotes keep `$ORIGIN` for the loader rather than expanding it in this shell.
for variant in chain scope; do
    directory="runpath/$variant"
    mkdir -p "$directory/middle" "$directory/leaf"

    cc -std=c11 -O0 -g -Wall -Wextra -Werror -shared -fPIC -nostdlib /src/libc/runpath/leaf.c \
        -Wl,-soname,libmatrix_leaf.so -o "$directory/leaf/libmatrix_leaf.so"

    if [ "$variant" = chain ]; then
        middle_runpath='$ORIGIN/../leaf'
        top_runpath='$ORIGIN/middle'
    else
        middle_runpath='$ORIGIN/missing'
        top_runpath='$ORIGIN/middle:$ORIGIN/leaf'
    fi

    cc -std=c11 -O0 -g -Wall -Wextra -Werror -shared -fPIC -nostdlib /src/libc/runpath/middle.c \
        -L"$directory/leaf" -lmatrix_leaf -Wl,-z,defs \
        -Wl,--enable-new-dtags -Wl,-rpath,"$middle_runpath" \
        -Wl,-soname,libmatrix_middle.so -o "$directory/middle/libmatrix_middle.so"

    cc -std=c11 -O0 -g -Wall -Wextra -Werror -shared -fPIC -nostdlib /src/libc/runpath/top.c \
        -L"$directory/middle" -lmatrix_middle -Wl,-z,defs \
        -Wl,--enable-new-dtags -Wl,-rpath,"$top_runpath" \
        -Wl,-soname,libmatrix_top.so -o "$directory/top.so"

    # Verify actual tags: older RPATH semantics would test a different contract.
    top_dynamic=$(readelf -d "$directory/top.so")
    middle_dynamic=$(readelf -d "$directory/middle/libmatrix_middle.so")
    printf '%s\n' "$top_dynamic" | grep -F '(RUNPATH)' | grep -F "[$top_runpath]"
    printf '%s\n' "$middle_dynamic" | grep -F '(RUNPATH)' | grep -F "[$middle_runpath]"
    printf '%s\n' "$top_dynamic" | grep -F '(NEEDED)' | grep -F '[libmatrix_middle.so]'
    printf '%s\n' "$middle_dynamic" | grep -F '(NEEDED)' | grep -F '[libmatrix_leaf.so]'
    if printf '%s\n%s\n' "$top_dynamic" "$middle_dynamic" | grep -F '(RPATH)'; then
        exit 1
    fi
done
