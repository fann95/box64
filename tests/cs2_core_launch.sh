#!/bin/sh
# SPDX-License-Identifier: MIT
# Launch CS2 with the installed Box64, excluding Steam's overlay preload.
# Keep this filename for existing Steam launch options; diagnostics are opt-in
# through external tools, not enabled by this launcher.

box64_binary="/usr/local/bin/box64"
if [ ! -x "$box64_binary" ]; then
    printf '%s\n' "Box64 is not executable: $box64_binary" >&2
    exit 1
fi

# An inactive overlay can fill its X-event ring and block input for 50 ms.
# Filter only that preload, preserving other libraries and their order.
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

# Apply the filter only to the game, not --version or other tools.
case "${1-}" in
    cs2|*/cs2)
        if [ "${LD_PRELOAD+x}" = x ]; then
            LD_PRELOAD=$(without_steam_overlay "$LD_PRELOAD")
            export LD_PRELOAD
        fi
        if [ "${BOX64_LD_PRELOAD+x}" = x ]; then
            BOX64_LD_PRELOAD=$(without_steam_overlay "$BOX64_LD_PRELOAD")
            export BOX64_LD_PRELOAD
        fi
        ;;
esac

exec "$box64_binary" "$@"
