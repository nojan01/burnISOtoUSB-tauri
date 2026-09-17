# Bundled F3 tools

F3 10.0: https://github.com/AltraMayor/f3/tree/v10.0 (GPL-3.0).
argp-standalone 1.5.0: https://github.com/argp-standalone/argp-standalone/tree/1.5.0
(LGPL-2.1-or-later, with LGPL-2.0-or-later and public-domain source files).
Copyright notices are retained in the original source files.

The upstream code is unmodified; COPYING.LESSER was added to argp's source tree
to supply the full LGPL 2.1 license text. Downloaded source archive SHA-256:

- f3 v10.0: `ce54275b7793f97391583ede33c1d87590901d8da20cce604b1f07a029aefc67`
- argp 1.5.0: `c29eae929dfebd575c38174f2c8c315766092cec99a8f987569d0cad3c6d64f6`

The app invokes f3write and f3read as
separate programs. argp is compiled into those programs, not the Rust application.
The MIT license of the application does not replace these component licenses.

To rebuild on macOS, install Apple's Command Line Tools and run:

    bash scripts/build-f3.sh aarch64-apple-darwin
    # or: bash scripts/build-f3.sh x86_64-apple-darwin

The script uses clang and system libc; no Homebrew, meson or network is needed.
The explicit macOS configuration is scripts/f3-argp-config.h.
Executables are written to src-tauri/binaries; they may be run independently.
Every app bundle includes this source tree and build scripts in
Contents/Resources/f3-sources.tar.gz, plus license texts in Contents/Resources/licenses.
The archive can be extracted and rebuilt with the commands above without Rust
when an explicit target is supplied. F3 is provided without warranty.
