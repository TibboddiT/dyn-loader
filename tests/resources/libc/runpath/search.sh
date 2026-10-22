#!/bin/sh
set -eu
export NIX_DONT_SET_RPATH=1

directory=runpath/search
source=/src/libc/runpath/search.c
mkdir -p "$directory/leaf" "$directory/override" "$directory/alias/leaf" \
    "$directory/middle" "$directory/blocked" "$directory/owner"

build() {
    output=$1
    shift
    cc -std=c11 -O0 -g -Wall -Wextra -Werror -shared -fPIC -nostdlib "$source" -o "$directory/$output" "$@"
}

# Distinct answers identify the directory selected by the loader.
build leaf/libsearch_leaf.so -DSEARCH_LEAF -DSEARCH_VALUE=11 -Wl,-soname,libsearch_leaf.so
build override/libsearch_leaf.so -DSEARCH_LEAF -DSEARCH_VALUE=22 -Wl,-soname,libsearch_leaf.so
build alias/leaf/libsearch_leaf.so -DSEARCH_LEAF -DSEARCH_VALUE=33 -Wl,-soname,libsearch_leaf.so

# Direct dependencies: individual path tags and environment precedence.
for output in rpath runpath bare relative empty empty-component both; do
    case "$output" in
        rpath) set -- '-Wl,--disable-new-dtags,-rpath,$ORIGIN/leaf';;
        runpath) set -- '-Wl,--enable-new-dtags,-rpath,$ORIGIN/leaf';;
        relative) set -- '-Wl,--enable-new-dtags,-rpath,runpath/search/leaf';;
        empty) set -- '-Wl,-soname,empty-search-path';;
        empty-component) set -- '-Wl,--enable-new-dtags,-rpath,:';;
        both) set -- '-Wl,--disable-new-dtags,-rpath,$ORIGIN/leaf' '-Wl,-soname,$ORIGIN/override';;
        bare) set -- ;;
    esac
    build "$output.so" -L"$directory/leaf" -lsearch_leaf "$@"
done

# Two-level graphs: inheritance, suppression, and each owner's ORIGIN.
for output in middle blocked owner; do
    case "$output" in
        middle) set -- ;;
        blocked) set -- '-Wl,--enable-new-dtags,-rpath,$ORIGIN/missing';;
        owner) set -- '-Wl,--disable-new-dtags,-rpath,$ORIGIN/../leaf';;
    esac
    build "$output/libsearch_middle.so" -DSEARCH_MIDDLE -L"$directory/leaf" -lsearch_leaf -Wl,-soname,libsearch_middle.so "$@"
done

build inherited.so -DSEARCH_INDIRECT -L"$directory/middle" -lsearch_middle '-Wl,--disable-new-dtags,-rpath,$ORIGIN/middle:$ORIGIN/leaf'
build alternate.so -DSEARCH_INDIRECT -L"$directory/middle" -lsearch_middle '-Wl,--disable-new-dtags,-rpath,$ORIGIN/middle:$ORIGIN/override'
build scoped.so -DSEARCH_INDIRECT -L"$directory/middle" -lsearch_middle '-Wl,--enable-new-dtags,-rpath,$ORIGIN/middle:$ORIGIN/leaf'
build blocked.so -DSEARCH_INDIRECT -L"$directory/blocked" -lsearch_middle '-Wl,--disable-new-dtags,-rpath,$ORIGIN/blocked:$ORIGIN/leaf'
build owner.so -DSEARCH_INDIRECT -L"$directory/owner" -lsearch_middle '-Wl,--enable-new-dtags,-rpath,$ORIGIN/owner'

# dlopen caller context, reload, and relative pathname identity.
build dynamic-rpath.so -DSEARCH_DYNAMIC '-DSEARCH_LIBRARY="libsearch_middle.so"' '-DSEARCH_SYMBOL="search_middle"' -lc -ldl '-Wl,--disable-new-dtags,-rpath,$ORIGIN/middle:$ORIGIN/leaf'
build dynamic-runpath.so -DSEARCH_DYNAMIC '-DSEARCH_LIBRARY="libsearch_middle.so"' '-DSEARCH_SYMBOL="search_middle"' -lc -ldl '-Wl,--enable-new-dtags,-rpath,$ORIGIN/middle:$ORIGIN/leaf'
build dynamic-direct.so -DSEARCH_DYNAMIC '-DSEARCH_LIBRARY="libsearch_leaf.so"' '-DSEARCH_SYMBOL="search_answer"' -lc -ldl '-Wl,--disable-new-dtags,-rpath,$ORIGIN/leaf'
build reload.so -DSEARCH_RELOAD -lc -ldl
build change-cwd.so -DSEARCH_CWD -lc -ldl
build leaf/relative-root.so -DSEARCH_CONSTANT -DSEARCH_VALUE=11
build override/relative-root.so -DSEARCH_CONSTANT -DSEARCH_VALUE=22
ln -sf ../runpath.so "$directory/alias/runpath.so"

# The linker cannot directly produce both tags or the required empty tag.
cc -std=c11 -Wall -Wextra -Werror /src/libc/runpath/tag_patch.c -o "$directory/tag-patch"
"$directory/tag-patch" "$directory/both.so"
"$directory/tag-patch" "$directory/empty.so" empty
rm "$directory/tag-patch"

readelf -d "$directory/rpath.so" | grep -F '(RPATH)'
readelf -d "$directory/runpath.so" | grep -F '(RUNPATH)'
readelf -d "$directory/both.so" | grep -F '(RPATH)'
readelf -d "$directory/both.so" | grep -F '(RUNPATH)'
readelf -d "$directory/empty.so" | grep -F '(RUNPATH)' | grep -F '[]'
