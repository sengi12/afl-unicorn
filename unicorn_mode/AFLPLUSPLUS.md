# Fuzzing with AFL++ (unicornafl)

The classic afl-unicorn workflow (this repo's `AflUnicornEngine`, patched
Unicorn v1) still exists and is unchanged. This document covers the modern
port: running the same targets under **AFL++** using **unicornafl** (Unicorn
2.x + AFL instrumentation), which is where upstream afl-unicorn now lives.

The ported sample harness is
[`samples/simple/simple_test_harness_aflpp.py`](samples/simple/simple_test_harness_aflpp.py).
It drives fuzzing through `uc.afl_fuzz()` (no manual fork-server bootstrap) and
still supports `--coverage` to write a drcov file for the ghidra-aflcov plugin.

## What runs where

- **Linux (recommended for throughput):** AFL++ unicorn_mode is first-class here.
  This is the fast fuzzing host — keep using it.
- **macOS, including Apple Silicon:** it works (verified below), but fork/exec
  overhead makes it slower. Good for convenience and for the coverage-replay
  mode; not the place for long campaigns.

## Setup

You need AFL++ and its `unicornafl` bindings. **Build `unicornafl` from AFL++'s
source tree — do not `pip install unicornafl` from PyPI.** The PyPI package
imports fine but its bundled native library does not implement the fork-server
handshake that current AFL++ expects: under `afl-showmap -U` / `afl-fuzz -U` the
child segfaults and captures **0 coverage tuples**. The source build produces a
`unicornafl` whose ABI matches your AFL++ and captures coverage correctly.

Modern `unicornafl` (2.1+) is a Rust/`maturin` build, so the setup differs from
the old v1 flow. The steps below are verified on both Linux (Kali rolling,
AFL++ 5.02c, Python 3.14) and macOS (Apple Silicon, AFL++ 4.05c).

1. **Install build prerequisites.** The build compiles Unicorn (CMake + Ninja)
   and the Rust bindings (cargo):

   ```sh
   # Debian / Kali / Ubuntu
   sudo apt-get install -y afl++ build-essential cargo rustc cmake ninja-build \
       python3-dev python3-venv git

   # macOS (Homebrew)
   brew install afl++ rust cmake ninja automake
   ```

2. **Build unicornafl** with AFL++'s own script. Note the name: it is now a
   Python script (`build_unicorn_support.py`), not the old `.sh`. AFL++ must be
   compiled first (the script checks for it):

   ```sh
   cd /path/to/AFLplusplus
   make            # or use the distro afl++ package's prebuilt binaries
   cd unicorn_mode
   python3 build_unicorn_support.py    # builds Unicorn + unicornafl (~a few minutes)
   ```

   The script installs `unicornafl` into a virtualenv it creates at
   `unicorn_mode/.venv`. Use that interpreter to run the harnesses, e.g.
   `/path/to/AFLplusplus/unicorn_mode/.venv/bin/python`.

3. **If you use your own virtualenv, pin `setuptools<81`.** unicornafl's Python
   glue still imports `pkg_resources`, which setuptools removed in 81. Python
   3.13/3.14 venvs ship no `pkg_resources` at all, so add it back:

   ```sh
   pip install 'setuptools<81'    # provides pkg_resources
   ```

   Verify the bindings load and match your Unicorn:

   ```sh
   python -c "import unicornafl; unicornafl.monkeypatch(); \
              from unicorn import Uc, UC_ARCH_MIPS, UC_MODE_MIPS32, UC_MODE_BIG_ENDIAN; \
              print('afl_fuzz:', hasattr(Uc(UC_ARCH_MIPS, UC_MODE_MIPS32+UC_MODE_BIG_ENDIAN),'afl_fuzz'))"
   ```

   Then confirm instrumentation actually feeds the bitmap (this is the check the
   PyPI package fails):

   ```sh
   afl-showmap -U -m none -o /tmp/map -- python simple_test_harness_aflpp.py ./sample_inputs/sample1.bin
   # Expect "Captured N tuples" with N > 0. "Captured 0 tuples" + a signal-11
   # abort means a mismatched/PyPI unicornafl - rebuild from source.
   ```

## Fuzzing

```sh
cd samples/simple
afl-fuzz -U -m none -i ./sample_inputs -o ./output -- \
    python simple_test_harness_aflpp.py @@
```

AFL++ replaces `@@` with each testcase path; the harness feeds it to the
emulator through its `place_input_callback` and reports coverage automatically.

Quick instrumentation check without a full run:

```sh
afl-showmap -U -m none -o /tmp/map -- python simple_test_harness_aflpp.py ./sample_inputs/sample1.bin
# "Captured N tuples" means instrumentation is feeding the AFL bitmap.
```

## Verified results

- **Linux (Kali rolling, AFL++ 5.02c, Python 3.14):** source-built unicornafl,
  `afl-showmap -U` captured 5 tuples from the MIPS sample and a short `afl-fuzz -U`
  session brought up the fork server, found a new corpus item and saved a crash.
  The PyPI `unicornafl` on the same host captured 0 tuples and segfaulted — hence
  the build-from-source requirement above.
- **macOS (Apple Silicon, AFL++ 4.05c):** `afl-showmap -U` captured 6 tuples, and
  a short `afl-fuzz -U` session brought up the fork server ("Using SHARED MEMORY
  FUZZING", `target_mode: unicornshmem_testcase`), fuzzed the seeds, found new
  corpus items and saved a crash. Throughput was ~150 exec/s — the expected macOS
  fork/exec penalty; Linux is considerably faster.

## Persistent mode

`-p N` enables AFL++ persistent mode: unicornafl runs N inputs per fork,
snapshotting the emulator state before the first and restoring it before each
subsequent one. It is a large throughput win (it amortizes the fork/exec cost
that hurts most on macOS):

```sh
afl-fuzz -U -m none -i ./sample_inputs -o ./output -- \
    python simple_test_harness_aflpp.py -p 1000 @@
```

Persistent mode suits targets with a re-entrant loop point. The trivial
single-shot `simple_target` is not a natural fit (AFL++ warns that the loop
address is not consistently reached); the default `-p 1` is the reliable path
for it. Use persistent mode on targets whose harness re-enters a request loop.

## Coverage visualization (works anywhere)

Record one input's path and load it in ghidra-aflcov:

```sh
python simple_test_harness_aflpp.py --coverage run.drcov ./sample_inputs/sample1.bin
```

## Crash triage with a coverage diff

To see what a crash did that the corpus never did, build a baseline from the
queue and diff a crash against it. `--coverage-dir` replays a whole directory
and writes per-input drcov plus a merged `_baseline.drcov`:

```sh
# after an afl-fuzz run into ./output
python simple_test_harness_aflpp.py --coverage-dir output/default/queue   --coverage-out cov/queue
python simple_test_harness_aflpp.py --coverage-dir output/default/crashes --coverage-out cov/crashes
```

Then in Ghidra (ghidra-aflcov):

1. **Baseline…** → `cov/queue/_baseline.drcov` (the corpus, painted green).
2. **Diff…** → a crash file, e.g. `cov/crashes/id:000000….drcov`.

Blocks the crash reached that the corpus did not are painted orange-red, and the
diff table ranks functions by those "crash-only" blocks - the code path unique
to the crash. See [COVERAGE.md](COVERAGE.md) for the drcov format details.
