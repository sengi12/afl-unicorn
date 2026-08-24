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

You need AFL++ and its `unicornafl` bindings. On Linux the AFL++ package or its
`unicorn_mode/build_unicorn_support.sh` sets this up. On macOS the steps below
are what actually worked (Apple Silicon, AFL++ 4.05c):

1. **Build unicornafl** with AFL++'s own script (PyPI's `unicornafl` is not
   self-contained and fails to build):

   ```sh
   # one-time build dependency on macOS
   brew install automake

   cd /path/to/AFLplusplus/unicorn_mode
   ./build_unicorn_support.sh     # clones + builds unicornafl (~a few minutes)
   ```

2. **Use Python 3.11 or 3.12 — not 3.13/3.14.** unicornafl 2.0.x's Python glue
   imports `pkg_resources` and `distutils.sysconfig`, both removed from the
   modern stdlib. A 3.12 virtualenv avoids the problem:

   ```sh
   python3.12 -m venv aflpp-venv
   . aflpp-venv/bin/activate
   pip install 'setuptools<81'    # provides pkg_resources
   ```

3. **Install the matching pair** (the instrumented Unicorn that unicornafl was
   built against, then unicornafl without letting pip pull stock Unicorn):

   ```sh
   UCAFL=/path/to/AFLplusplus/unicorn_mode/unicornafl
   pip install --force-reinstall "$UCAFL/unicorn/bindings/python"      # unicorn 2.0.1 (instrumented)
   pip install --no-deps --force-reinstall "$UCAFL/bindings/python"    # unicornafl
   ```

   Verify:

   ```sh
   python -c "import unicornafl; unicornafl.monkeypatch(); \
              from unicorn import Uc, UC_ARCH_MIPS, UC_MODE_MIPS32, UC_MODE_BIG_ENDIAN; \
              print('afl_fuzz:', hasattr(Uc(UC_ARCH_MIPS, UC_MODE_MIPS32+UC_MODE_BIG_ENDIAN),'afl_fuzz'))"
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

## Verified result (macOS ARM, AFL++ 4.05c)

`afl-showmap -U` captured 6 coverage tuples from the MIPS sample, and a short
`afl-fuzz -U` session brought up the fork server ("Using SHARED MEMORY FUZZING",
`target_mode: unicornshmem_testcase`), fuzzed the seeds, found new corpus items
and saved a crash. Throughput was ~150 exec/s — the expected macOS penalty;
Linux is considerably faster.

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
