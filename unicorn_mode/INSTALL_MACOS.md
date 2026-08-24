# Installing afl-unicorn fuzzing on macOS (AFL++ / unicornafl)

This guide sets up **coverage-guided fuzzing of Unicorn harnesses on macOS**,
including Apple Silicon, using AFL++ and unicornafl (Unicorn 2.x + AFL
instrumentation). Once it is done you can fuzz the samples and record drcov
coverage for the [ghidra-aflcov](https://github.com/sengi12/ghidra-aflcov)
plugin.

## Read this first

- **This is for the Unicorn workflow only.** AFL's `qemu_mode` (whole-binary
  fuzzing) relies on a patched Linux-user QEMU and the Linux fork server; it does
  **not** run on macOS. Keep that on Linux.
- **macOS fuzzing is slower than Linux** — Darwin's `fork()`/`execve()` overhead
  makes it a fraction of Linux throughput (tens to low hundreds of exec/s on the
  samples). It is great for development, triage and coverage visualization; use
  Linux for long campaigns.
- The steps below are the exact sequence verified on Apple Silicon with AFL++
  4.05c. The version pins matter — see [Troubleshooting](#troubleshooting).

## Prerequisites

- macOS with [Homebrew](https://brew.sh).
- **Python 3.11 or 3.12** — *not* 3.13+ (unicornafl's Python glue uses modules
  removed from newer stdlib). Install one:
  ```sh
  brew install python@3.12
  ```
- Xcode command-line tools (`xcode-select --install`).

## Part 1 — AFL++

Install AFL++ (this gives you `afl-fuzz`, `afl-showmap`, and the `unicorn_mode`
tree):

```sh
brew install afl++
```

Or build from source into `~/Applications/AFLplusplus` (what this guide assumes
as `$AFL`):

```sh
git clone https://github.com/AFLplusplus/AFLplusplus ~/Applications/AFLplusplus
cd ~/Applications/AFLplusplus
make
```

Set a path variable for the rest of this guide:

```sh
export AFL="$HOME/Applications/AFLplusplus"   # or "$(brew --prefix)/opt/afl++/share/afl++"
"$AFL/afl-fuzz" 2>&1 | head -1                 # should print the afl-fuzz++ banner
```

## Part 2 — build unicornafl

`unicornafl` is not usable from PyPI (its package is not self-contained). Build
it from AFL++'s own tree. It needs `automake`, which macOS does not ship:

```sh
brew install automake
cd "$AFL/unicorn_mode"
./build_unicorn_support.sh
```

This clones and compiles unicornafl (a few minutes). Its final self-test may
print an error about a sample harness — that is fine; the Python bindings we
need are installed in the next step regardless. The important result is a built
tree at `$AFL/unicorn_mode/unicornafl`.

```sh
export UCAFL="$AFL/unicorn_mode/unicornafl"
ls "$UCAFL/unicorn/bindings/python/setup.py" "$UCAFL/bindings/python/setup.py"
```

## Part 3 — a Python environment

Create a dedicated virtualenv on **Python 3.12** and install the *matching pair*:
the instrumented Unicorn that unicornafl was built against, then unicornafl
itself with `--no-deps` so pip does not replace that Unicorn with the stock one.

```sh
python3.12 -m venv "$HOME/aflpp-venv"
source "$HOME/aflpp-venv/bin/activate"

pip install --upgrade pip 'setuptools<81' wheel                    # setuptools<81 provides pkg_resources
pip install --force-reinstall "$UCAFL/unicorn/bindings/python"     # instrumented unicorn 2.0.1
pip install --no-deps --force-reinstall "$UCAFL/bindings/python"   # unicornafl 2.0.2
```

## Part 4 — verify

```sh
python -c "import unicornafl; unicornafl.monkeypatch(); \
  from unicorn import Uc,UC_ARCH_MIPS,UC_MODE_MIPS32,UC_MODE_BIG_ENDIAN; \
  print('afl_fuzz ready:', hasattr(Uc(UC_ARCH_MIPS,UC_MODE_MIPS32+UC_MODE_BIG_ENDIAN),'afl_fuzz'))"
```

Expected: `afl_fuzz ready: True`.

Then confirm the instrumentation feeds AFL's bitmap on a real sample:

```sh
cd /path/to/afl-unicorn/unicorn_mode/samples/simple
AFL_MAP_SIZE=65536 "$AFL/afl-showmap" -U -m none -t 5000 -o /tmp/map \
  -- python simple_test_harness_aflpp.py ./sample_inputs/sample1.bin
```

Expected: a `Captured N tuples` line. You are ready — see
[EXAMPLE_WALKTHROUGH.md](EXAMPLE_WALKTHROUGH.md) to fuzz and visualize coverage.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `error: externally-managed-environment` on `pip install` | PEP 668. Always install into a virtualenv (Part 3), not the system Python. |
| `ModuleNotFoundError: No module named 'pkg_resources'` | setuptools ≥ 81 removed it. `pip install 'setuptools<81'` in the venv. |
| `AttributeError: module 'distutils' has no attribute 'sysconfig'` | You are on Python 3.13+. Recreate the venv with **Python 3.12**. |
| `afl-showmap` prints `Unicorn mode doesn't seem to work` / no tuples | Stock Unicorn 2.1.x clobbered the instrumented 2.0.1. Reinstall per Part 3, using `--no-deps` for unicornafl. |
| `Error: 'automake' not found` from the build script | `brew install automake` (Part 2). |
| `afl-fuzz` complains about the crash reporter | `sudo launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist` (reload with `load` afterwards). |
| Very low exec/s | Expected on macOS. Try persistent mode (`-p N`) on loop-amenable targets, or fuzz on Linux for throughput. |

## Reusing the environment

The venv at `~/aflpp-venv` is what you activate for every fuzzing or coverage
session:

```sh
source "$HOME/aflpp-venv/bin/activate"
```

The built `unicornafl` tree under `$AFL` persists, so you only rebuild it if you
update AFL++.
