# Known gaps in this offline bundle

## Summary

The bundle in `debs/` is **incomplete for amd64**. It contains 244 `i386`
packages but only 77 `amd64` ones, because it was collected on a machine that
already had the 64-bit X11/OpenGL/audio stack installed — `apt-get download`
only fetched what was missing *there*.

On a slim host (such as a headless Debian container) this means:

| Component | Installs? | Runs? | Blocker |
|---|---|---|---|
| **Qiling** | yes | partly | `gevent` wheel is cp313-only |
| rootfs | yes | **yes** | — |
| **wine64** | yes | no | `libunwind.so.8` |
| **Xvfb** | yes | no | `libGL.so.1`, `libXfont2.so.2`, `libpixman-1.so.0`, `libunwind.so.8` |
| **xauth** | **no** | no | not present in `debs/` at all |

Nothing here can be resolved offline: the required files are not in the
repository, and the installer is required not to contact a mirror.

## 1. `xauth` is not bundled

All 336 `.deb` files were scanned; none ships a `xauth` (or `mcookie`) binary.
`xvfb-run` hard-exits when it is absent:

```sh
# /usr/bin/xvfb-run, line 137
if ! command -v xauth >/dev/null; then
    error "xauth command not found"
```

**Workaround (no xauth needed).** `Xvfb` itself has no such dependency, so
start it directly instead of through `xvfb-run`:

```sh
source ./xvfb-env.sh        # starts Xvfb on :99 and exports DISPLAY
wine64 sample.exe
```

To fix it properly, add `xauth_1%3a1.1.2-1build1_amd64.deb` to `debs/`.

## 2. amd64 runtime libraries shipped only as i386

Each package below is present in `debs/` as `_i386.deb` but has **no `_amd64.deb`
counterpart**, so 64-bit Wine and Xvfb cannot resolve their libraries:

| Package (version in bundle) | Provides |
|---|---|
| `libunwind8` 1.6.2-3build1.1 | `libunwind.so.8` — **blocks wine64** |
| `libgl1` 1.7.0-1build1 | `libGL.so.1` |
| `libpixman-1-0` 0.42.2-1build1 | `libpixman-1.so.0` |
| `libasound2t64` 1.2.11-1ubuntu0.3 | `libasound.so.2` |
| `libdbus-1-3` 1.14.10-4ubuntu4.1 | `libdbus-1.so.3` |
| `libgstreamer1.0-0` 1.24.2-1ubuntu0.1 | `libgstreamer-1.0.so.0`, `libgstbase-1.0.so.0` |
| `libicu74` 74.2-1ubuntu3.1 | `libicuuc.so.74` |
| `libldap2` 2.6.10+dfsg-0ubuntu0.24.04.1 | `libldap.so.2`, `liblber.so.2` |
| `libpcsclite1` 2.0.3-1build1 | `libpcsclite.so.1` |
| `libpulse0` 1:16.1+dfsg1-2ubuntu10.1 | `libpulse.so.0` |
| `libssh-4` 0.10.6-2ubuntu0.5 | `libssh.so.4` |
| `libusb-1.0-0` 2:1.0.27-1 | `libusb-1.0.so.0` |
| `libwayland-client0` 1.22.0-2.1build1 | `libwayland-client.so.0` |
| `libxkbcommon0` 1.6.0-1build1 | `libxkbcommon.so.0` |
| `ocl-icd-libopencl1` 2.3.2-1build1 | `libOpenCL.so.1` |

Not bundled for **either** architecture:

| Package | Provides |
|---|---|
| `libxfont2` | `libXfont2.so.2` — **blocks Xvfb** |
| `libibverbs1` | `libibverbs.so.1` |

### Regenerating the bundle

On an Ubuntu 24.04 amd64 machine:

```sh
sudo dpkg --add-architecture i386 && sudo apt-get update
apt-get download $(apt-cache depends --recurse --no-recommends --no-suggests \
  --no-conflicts --no-breaks --no-replaces --no-enhances \
  wine64 wine32 xvfb xauth | grep '^\w' | sort -u)
```

The key point is to resolve the dependency closure **inside a clean container**
rather than on a workstation, so that already-satisfied dependencies are still
downloaded.

## 3. glibc skew (handled automatically)

The debs are noble builds referencing `GLIBC_2.38`/`2.39`; an older host
(Debian 12 = glibc 2.36) refuses to load them, which breaks anything linked
against them — including `python3`, via `libexpat.so.1`.

`install.sh` repairs this automatically with `tools/elfcompat.c`, which
rewrites the affected ELF references in place:

* undefined `__isoc23_*` symbols are re-pointed at their classic equivalents
  (`__isoc23_strtoul` → `strtoul`); the C23 variants differ only in accepting
  binary literals;
* symbols bound to a too-new glibc version node are made unversioned, and the
  matching `Verneed` entry is unlinked, so e.g. `fmod` resolves from `libm`.

Originals are backed up to `/var/tmp/glibc-compat-backup` (override with
`ELFCOMPAT_BACKUP`). To restore:

```sh
sudo cp -a /var/tmp/glibc-compat-backup/. / && sudo ldconfig
```

## 4. Python wheels are built for CPython 3.13 only

`wheels/` contains **cp313** binary wheels. On any other interpreter pip
cannot use them:

```
ERROR: Could not find a version that satisfies the requirement gevent>=20.9.0
```

| Wheel | Kind | Usable on cp311? |
|---|---|---|
| `gevent-26.9.0-cp313-...` | C extension | no |
| `greenlet-3.5.6-cp313-...` | C extension | no |
| `pillow-10.4.0-cp313-...` | C extension | no |
| `pyyaml-6.0.3-cp313-...` | C extension | no |
| `zope_interface-8.6-cp313-...` | C extension | no |
| `multiprocess-0.70.19-py313-none-any` | pure python | yes, after retagging |

`install.sh` falls back to installing Qiling plus the architecture-independent
dependencies (`capstone`, `unicorn`, `pefile`, `python-registry`,
`keystone-engine`, `pyelftools`, `termcolor`), and retags the pure-python
`multiprocess` wheel so it can be used.

### Consequence: the Linux and Windows backends do not load

`gevent` is imported by `qiling/os/thread.py`, `qiling/os/linux/{thread,futex}.py`,
`qiling/os/posix/syscall/{sched,time}.py` and `qiling/extensions/multitask.py`.
Because `qiling.os.windows.windows` pulls in `qiling.os.thread`, **both** the
Linux and Windows backends fail to import without it:

```
usable backends:   macos freebsd uefi dos blob
UNUSABLE backends: linux (missing gevent), windows (missing gevent)
```

Note that `import qiling` still succeeds, so an import check alone is not a
valid verification — `install.sh` probes each backend instead.

### Fixes (pick one)

1. **Ship matching wheels** — add cp311 (or your host's ABI) builds of
   `gevent`, `greenlet`, `pyyaml`, `zope.interface` and `pillow` to `wheels/`.
   On a host with the same Python version:
   `pip download gevent greenlet pyyaml zope.interface pillow -d wheels/`
2. **Ship the interpreter the wheels were built for** — add `python3.13` debs
   to `debs/`; `install.sh` will then resolve the full dependency set.
3. **Allow a one-off online install** (breaks the offline requirement):
   `.venv/bin/pip install gevent`

## 5. libcurl's optional transports (handled automatically)

The bundle installs Ubuntu's `libcurl3t64-gnutls` / `libcurl4t64`, whose
`DT_NEEDED` list includes `libssh.so.4`, `libldap.so.2` and `liblber.so.2`.
Those are **not shipped for amd64**, and the dynamic loader refuses to start
*any* libcurl consumer when they are missing — which silently breaks
`git` over HTTPS and `curl`:

```
git-remote-https: error while loading shared libraries: libssh.so.4
```

Note the Ubuntu `t64` package renames (`libcurl3-gnutls` →
`libcurl3t64-gnutls`, `libasound2` → `libasound2t64`, ...) mean these do not
look like replacements of host packages, so they are installed even in the
default "don't replace host packages" mode.

`install.sh` runs `tools/stub-missing-libs.sh`, which compiles inert
stand-ins exporting exactly the symbols and symbol *versions* the consumer
imports (e.g. `sftp_init@LIBSSH_4_5_0`). They are written to
`/usr/local/lib/offline-bundle-stubs` and registered via `ld.so.conf.d`;
nothing is overwritten.

HTTPS, FTP and the rest of curl work normally. The `scp://`, `sftp://` and
`ldap://` URL schemes do not. Shipping the real amd64 `libssh-4` and
`libldap2` packages removes the need for the stubs — delete the directory and
run `ldconfig` to drop them.
