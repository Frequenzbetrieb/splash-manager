# Splash Manager

Custom Engine QML startup splash manager for EngineX OS.

Upload a custom PNG splash screen via a drag-and-drop web interface at `http://<deck-ip>:8081`.

## Features

- Drag-and-drop PNG upload via web browser
- Supports both 16:10 (1280×800) and 16:9 (1366×768) screen models
- Writes to all three language packs (en, zh-Hant, zh-Hans)
- Backs up original splash files before first modification
- "Restore Default" button to revert to stock splash
- Originals automatically restored on mod stop/uninstall
- Security: Host validation (blocks DNS rebinding), Origin checking, Content-Type enforcement
- PNG validation (IHDR check, max 4096×4096)
- Safe file writes (write to temp + fsync + rename)

## Install

1. Web console `http://<deck IP>:8080` → **Mods** → drop the `.tar.gz`
2. Or extract into `/mods/` on a USB stick (`/mods/splash-manager/mod.json`)

## Build from source

Requires a musl cross-compiler toolchain.

```sh
# armhf (32-bit, 14 models)
arm-linux-musleabihf-gcc -O2 -static -o splash-server-armhf src/splash-server.c

# aarch64 (64-bit, PRIME 4 G2 / Rane SYSTEM ONE)
aarch64-linux-musl-gcc -O2 -static -o splash-server-aarch64 src/splash-server.c
```

## Note

This mod customizes the **Engine QML startup splash** (shown while the Engine UI initializes), not the hardware bootloader splash stored in the eMMC splash partition.

## License

MIT
