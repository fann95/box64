#!/bin/sh
# SPDX-License-Identifier: MIT
# Keep the game's normal launch path, excluding only Steam's overlay preload.

without_steam_overlay() (
    set -f
    IFS=' :'
    filtered_preloads=
    for preload_entry in $1; do
        case "${preload_entry##*/}" in
            ''|gameoverlayrenderer.so) ;;
            *) filtered_preloads="${filtered_preloads:+$filtered_preloads:}$preload_entry" ;;
        esac
    done
    printf '%s' "$filtered_preloads"
)

if [ "${LD_PRELOAD+x}" = x ]; then
    LD_PRELOAD=$(without_steam_overlay "$LD_PRELOAD")
    export LD_PRELOAD
fi
if [ "${BOX64_LD_PRELOAD+x}" = x ]; then
    BOX64_LD_PRELOAD=$(without_steam_overlay "$BOX64_LD_PRELOAD")
    export BOX64_LD_PRELOAD
fi

exec "$@"
