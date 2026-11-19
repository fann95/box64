![Official logo](docs/img/Box64Logo.png "Official Logo")

# Box64: Linux Userspace x86-64 Emulator with a Twist

> **Local fork:** AI-assisted fixes tested on ASUS Ascent GX10 (NVIDIA GB10) with Ubuntu 24.04, based on upstream commit [`27c8275d8`](https://github.com/ptitSeb/box64/commit/27c8275d8295f521bb40faf920788ac5116dbfb0). See the [Steam launch configuration](#steam-overlay-on-nvidia-gb10) below for the setup used with CS2 and CS 1.6.

[Website](https://box86.org/) | [Changelog](https://github.com/ptitSeb/box64/blob/main/docs/CHANGELOG.md) | [中文](https://github.com/ptitSeb/box64/blob/main/README_CN.md) | [Українська](https://github.com/ptitSeb/box64/blob/main/README_UK.md) | [Report an Error](https://github.com/ptitSeb/box64/issues/new)

![Build Status](https://github.com/ptitSeb/box64/actions/workflows/release.yml/badge.svg) ![Stars](https://img.shields.io/github/stars/ptitSeb/box64) ![Forks](https://img.shields.io/github/forks/ptitSeb/box64) ![Contributors](https://img.shields.io/github/contributors/ptitSeb/box64) ![Pull Requests](https://img.shields.io/github/issues-pr/ptitSeb/box64) ![Issues](https://img.shields.io/github/issues/ptitSeb/box64)

---

**Check out our game compatibility list at [https://box86.org/app/](https://box86.org/app/), please help us [improve it](https://github.com/ptitSeb/box86-compatibility-list/issues)!**

---

Box64 enables running x86_64 Linux programs, including games, on non-x86_64 Linux systems such as Arm (64-bit little-endian host system required).

Box64 leverages native system libraries (libc, libm, SDL, OpenGL), offering ease of integration and surprising performance in many applications. For performance benchmarks, check [this analysis](https://box86.org/index.php/2021/06/game-performances/).

With DynaRec for Arm, RISC-V and LoongArch platforms, Box64 achieves a speed boost 5-10x faster than the interpreter alone. For a deeper look at DynaRec, see [Inner workings](https://box86.org/2021/07/inner-workings-a-high%e2%80%91level-view-of-box86-and-a-low%e2%80%91level-view-of-the-dynarec/). For a more detailed look at Box64 internals and optimization strategies, see our EuroSys 2026 paper, [Practical and Efficient x86-64 Emulation on RISC-V](https://doi.org/10.1145/3767295.3803574), which focuses on RISC-V but covers many techniques that apply more broadly to Box64.

<img src="docs/img/Box64Icon.png" width="96" height="96" alt="Box64 Icon">

_Logo and icon by @grayduck - Thank you!_

---

## Usage

- `$ box64 ./program [args]` to run Linux x86_64 programs.
- `$ box64 -k` to kill all the emulated processes.
- `$ box64-bash` to have an x86_64 bash environment.
- Want to use wine? see [Wine Documentation](docs/WINE.md).

Box64 also offers environment variables and rcfile to control its behavior. For details, see [Usage Documentation](docs/USAGE.md).

---

## Compiling and Installation

- [Compilation Instructions](https://github.com/ptitSeb/box64/blob/main/docs/COMPILE.md)
- [Bundle x86 Libraries](https://github.com/ptitSeb/box64/blob/main/docs/BUNDLE-X86-LIBS.md)
- [Wine Installation for Box64](https://github.com/ptitSeb/box64/blob/main/docs/WINE.md)

---

## Version History

See the [Changelog](docs/CHANGELOG.md) for version updates.

---

## Platform Compatibility Notes

Box64 requires 64-bit libraries on the host system, as it directly translates x86_64 function calls. For 32-bit binaries, use Box86 or Box32.

**Notes** 

1. Box32 is still experimental, but it's pretty stable now and can be used.
2. Some shell scripts (such as the GOG game installer) may rely on `uname -m` to determine the current architecture. Please run them as `box64 script.sh` to allow Box64 to take over.

Note that DynaCache is now enabled by default (with compression). This will creates files in `~/.cache/box64` to save generated code for executed binaries and libraries, so launch time can be greatly reduced on second run. The files are compressed and will take up to 2Gb by default. You can disable DynaCache writing, by switching it to a Read-only mode by creating (or modifying) `~/.box64rc` and writing there

```ini
[*]
BOX64_DYNACACHE=2
```

(or 0 to completely disabled it). Please refer to [Usage Documentation](docs/USAGE.md) for more details on how to configure Box64.

---

## Configuration

Box64 has configuration files located in `/etc/box64.box64rc` and `~/.box64rc`, both formatted as `.ini` files. If you don’t want to use the default `/etc/box64.box64rc` file, copy it to `~/.box64rc` to ensure compatibility.

Settings priority: `~/.box64rc` > `/etc/box64.box64rc` > Command line.

For more information, check [Usage Documentation](docs/USAGE.md).

---

## Additional Platform-Specific Notes

### Unity Game Emulation

- Many Unity games require OpenGL 3+, which may be challenging on ARM/RISC-V SBCs.
- **Tip for Pi4 and Pi5 Users**: Set `MESA_GL_VERSION_OVERRIDE=3.2` with `BOX64_DYNAREC_STRONGMEM=1` to prevent freezes and enable strong memory mode.
- **Using Panfrost**: For better compatibility on ARM, enable `PAN_MESA_DEBUG=gl3` to force higher OpenGL profiles. This can help if a game starts but quits unexpectedly before showing any content.

### Steam

See [Steam Documentation](docs/STEAM.md).

#### Steam Overlay on NVIDIA GB10

On our GB10 setup, CS2 still loaded `gameoverlayrenderer.so` with the Steam Overlay switch turned off in the game's settings. Its input-event queue filled up and caused repeated waits and a sustained FPS drop. The launch helpers in this fork remove only `gameoverlayrenderer.so` from `LD_PRELOAD` and `BOX64_LD_PRELOAD` before starting the game, preserving other preloaded libraries and game arguments.

**`install_steam.sh` does not install these helpers or configure game launch options.** After installing Steam and this fork of Box64, configure each game below in **Properties > General > Launch Options**. Keep Steam Overlay disabled in the game's settings as well.

The examples assume this repository is at `$HOME/box64`. Adjust the helper paths if you put it elsewhere, and keep the checkout at that location while these launch options refer to it. Steam client updates do not overwrite these scripts in the Box64 checkout.

**Counter-Strike 2:**

```bash
BOX64_DYNAREC_STRONGMEM=4 BOX64_DYNAREC_NOHOSTEXT=uscat GAME_DEBUGGER="$HOME/box64/tests/cs2_core_launch.sh" %command%
```

[`tests/cs2_core_launch.sh`](tests/cs2_core_launch.sh) launches the installed `/usr/local/bin/box64`. It keeps its historical filename so existing launch options continue to work. It does not raise core-dump limits, enable JIT profiling, create diagnostic files, or select an old diagnostic build. The old `build/cs2-profile/capture-jit-next` marker is no longer used. Normal Steam logging and any externally configured diagnostics retain their own settings.

**Counter-Strike 1.6:**

```bash
BOX64_DYNAREC_STRONGMEM=3 BOX64_DYNAREC_NOHOSTEXT=uscat DEBUGGER="$HOME/box64/tests/steam_no_overlay.sh" %command%
```

[`tests/steam_no_overlay.sh`](tests/steam_no_overlay.sh) filters the overlay preload and executes the game's original command. GoldSrc uses `DEBUGGER`; CS2 uses `GAME_DEBUGGER`. This preserves the existing CS 1.6 launch path through binfmt and the installed Box64.

These are the launch options tested on our GB10 system. Keep the memory-ordering options scoped to these games. Updating the helper scripts does not require rebuilding or reinstalling Box64. They filter the game's environment without modifying Steam's installed libraries.

### Wine

Box64 supports Wine64 and Proton. For 32-bit components, Box86 is required. Systems with both Box64 and Box86 can run 32- and 64-bit Windows programs.

**Note**: You can use Wine WOW64 build to run x86 Windows programs in Box64-only environments, this is still experimental, but it works in most cases.

For more information, check [Wine Documentation](docs/WINE.md).

----
Final word
----

I want to thank everyone who has contributed to box64 development.
There are many ways to contribute: code contribution, financial, hardware and advertisement!
So, in no particular order, I want to thank:
 * For their major code contribution: rajdakin, mogery, ksco, xctan
 * For their major financial contribution: [Playtron](https://playtron.one), tohodakilla, FlyingFathead, stormchaser3000, dennis1248, sll00, [libre-computer-project](https://libre.computer/), [CubeCoders Limited](http://cubecoders.com/)
 * For hardware contribution and LoongArch migration: [xiaoji](https://www.linuxgame.cn/), Deepin Beijing Develop Team
 * For their hardware contribution: [ADLINK](https://www.adlinktech.com/Products/Computer_on_Modules/COM-HPC-Server-Carrier-and-Starter-Kit/Ampere_Altra_Developer_Platform?lang=en) with [Ampere](https://amperecomputing.com/home/edge), [SpacemiT](https://www.spacemit.com/), [SOPHGO](https://www.sophon.ai/), [Radxa](https://rockpi.org/), [StarFive](https://rvspace.org/), [Pine64](https://www.pine64.org/), [AYN](https://www.ayntec.com/), [AYANEO](https://ayaneo.com/), [jiangcuo](https://github.com/jiangcuo)
 * For their continuous advertisements for the box64 project: salva ([microLinux](https://www.youtube.com/channel/UCwFQAEj1lp3out4n7BeBatQ)), [PILab](https://www.youtube.com/channel/UCgfQjdc5RceRlTGfuthBs7g)/[TwisterOS](https://twisteros.com/) team, [The Byteman](https://www.youtube.com/channel/UCEr8lpIJ3B5Ctc5BvcOHSnA), [NicoD](https://www.youtube.com/channel/UCpv7NFr0-9AB5xoklh3Snhg), ekianjo ([Boilingsteam](https://boilingsteam.com/))

And I also thank the many other people who participated even once in this project.

(If you use Box64 in your project, please don't forget to mention it!)

