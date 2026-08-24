# End-to-end walkthrough: fuzz a MIPS target on macOS and see the crash path in Ghidra

This tutorial runs the whole pipeline on a Mac (Apple Silicon included):

1. Fuzz a **MIPS 32-bit big-endian** test binary with **AFL++ + unicornafl** —
   a different architecture from your host, emulated by Unicorn.
2. Turn the results into **drcov** coverage files.
3. Load them into **[ghidra-aflcov](https://github.com/sengi12/ghidra-aflcov)**
   and diff a crash against the corpus, so the code path unique to the crash is
   highlighted in the Listing and Function Graph.

It should take about 15 minutes the first time (most of it the one-time setup).

## What you need

- **AFL++** installed (`afl-fuzz`, and its `unicorn_mode/unicornafl` tree built).
- **Python 3.11 or 3.12** (not 3.13+ — unicornafl's Python glue uses modules
  removed from newer stdlib). Homebrew's `python3.12` is fine.
- **Ghidra 10.2 or higher**, and a clone of `ghidra-aflcov`.
- This repository (the afl-unicorn fork with the AFL++ harness).

The example target is `unicorn_mode/samples/simple/simple_target.bin`: raw MIPS
code, loaded at address `0x100000`, that reads its input from `0x300000` and
crashes in a few different ways. We use the crash that fires when byte 20 of the
input is non-zero.

## Set your paths

Adjust these to your machine, then paste into the terminal you'll use:

```sh
export REPO="$HOME/path/to/afl-unicorn"          # this repository
export AFL="$HOME/Applications/AFLplusplus"       # your AFL++ checkout
export UCAFL="$AFL/unicorn_mode/unicornafl"
export PLUGIN="$HOME/path/to/ghidra-aflcov"       # the Ghidra plugin repo
cd "$REPO/unicorn_mode/samples/simple"
```

---

## Step 1 — one-time: a Python environment with unicornafl

unicornafl must be paired with the *instrumented* Unicorn it was built against.
Installing `unicornafl` from PyPI does not work (its package is not
self-contained); build it from AFL++'s tree instead. If you have not already:

```sh
brew install automake                 # AFL++'s build script needs it on macOS
cd "$AFL/unicorn_mode"
./build_unicorn_support.sh            # clones + builds unicornafl (a few minutes)
```

Then create a virtualenv and install the matching pair into it:

```sh
python3.12 -m venv "$HOME/aflpp-venv"
source "$HOME/aflpp-venv/bin/activate"
pip install --upgrade pip 'setuptools<81' wheel     # setuptools<81 keeps pkg_resources
pip install --force-reinstall "$UCAFL/unicorn/bindings/python"     # instrumented unicorn
pip install --no-deps --force-reinstall "$UCAFL/bindings/python"   # unicornafl (no-deps: keep the instrumented unicorn)
```

Verify it imports and `afl_fuzz` is available:

```sh
python -c "import unicornafl; unicornafl.monkeypatch(); \
  from unicorn import Uc,UC_ARCH_MIPS,UC_MODE_MIPS32,UC_MODE_BIG_ENDIAN; \
  print('afl_fuzz ready:', hasattr(Uc(UC_ARCH_MIPS,UC_MODE_MIPS32+UC_MODE_BIG_ENDIAN),'afl_fuzz'))"
```

Expected: `afl_fuzz ready: True`. Keep this venv activated for the rest.

## Step 2 — sanity check the instrumentation

```sh
cd "$REPO/unicorn_mode/samples/simple"
AFL_MAP_SIZE=65536 "$AFL/afl-showmap" -U -m none -t 5000 -o /tmp/map \
  -- python simple_test_harness_aflpp.py ./sample_inputs/sample1.bin
```

Expected: a line like **`Captured 6 tuples`**. (A `No AFL, no need to fork`
message just above it is normal — afl-showmap does a single instrumented run.)

## Step 3 — fuzz the MIPS target

```sh
export AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1
"$AFL/afl-fuzz" -U -m none -t 5000 -i ./sample_inputs -o ./output \
  -- python simple_test_harness_aflpp.py @@
```

`afl-fuzz` brings up the fork server ("Using SHARED MEMORY FUZZING") and begins
mutating inputs through the emulated MIPS target. Watch the **`saved crashes`**
counter; once it reaches 1 or more, press **Ctrl-C**. Results are in
`output/default/queue/` (the corpus it built) and `output/default/crashes/`.

> Throughput on macOS is modest (~150 exec/s) because of Darwin's fork/exec
> overhead — this is expected; Linux is much faster. It is fine for this demo.
>
> If macOS intercepts crashes, unload the crash reporter once:
> `sudo launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist`
> (reload later with `load`).

## Step 4 — generate drcov coverage

Replay the corpus and the crashes to produce coverage files. `--coverage-dir`
writes one `.drcov` per input plus a merged `_baseline.drcov`:

```sh
python simple_test_harness_aflpp.py --coverage-dir output/default/queue   --coverage-out cov/queue
python simple_test_harness_aflpp.py --coverage-dir output/default/crashes --coverage-out cov/crashes
```

### Prefer a guaranteed crash?

If the fuzzer was slow to find one, craft the deterministic crash directly (byte
20 non-zero) alongside a benign input, and skip fuzzing:

```sh
mkdir -p demo/queue demo/crashes
python3 -c "open('demo/queue/benign','wb').write(b'AAAA')"
python3 -c "open('demo/crashes/crash','wb').write(b'A'*20+b'\xff')"
python simple_test_harness_aflpp.py --coverage-dir demo/queue   --coverage-out demo/cov_queue
python simple_test_harness_aflpp.py --coverage-dir demo/crashes --coverage-out demo/cov_crashes
```

This gives `demo/cov_queue/_baseline.drcov` and `demo/cov_crashes/crash.drcov`,
used below.

## Step 5 — load the binary into Ghidra

The coverage stores block offsets relative to the module base `0x100000`, and
the plugin adds them to the program's image base — so the program **must** be
based at `0x100000` or nothing will line up.

1. **File ▸ Import File** → `unicorn_mode/samples/simple/simple_target.bin`.
2. **Format:** `Raw Binary`.
3. **Language:** click `…`, filter **MIPS**, choose **`MIPS:BE:32:default`**
   (MIPS, 32-bit, big-endian).
4. **Options… ▸ Base Address:** `00100000`.
5. Import and open it in the CodeBrowser (you can decline auto-analysis).

Give Ghidra some basic blocks to color:

6. Press **G**, type `100000`, Enter.
7. Press **D** to disassemble, then **F** to create a function at the entry.
   (Ghidra follows the branches and builds the basic blocks from here.)

## Step 6 — run the plugin and diff the crash

1. Open the **Script Manager** (green ▶ in the toolbar).
2. **Manage Script Directories** → **+** → add your `ghidra-aflcov` folder →
   refresh.
3. Filter for **`AflCoverage.java`**, select it, run (or press **Alt-A**). The
   **AFL Coverage** window docks.
4. Click **Baseline…** → `demo/cov_queue/_baseline.drcov`
   (or `cov/queue/_baseline.drcov`). The corpus blocks paint green.
5. Click **Diff…** → `demo/cov_crashes/crash.drcov`
   (or one file from `cov/crashes/`).

## What you should see

The diff recolors by which set reached each block:

| Colour | Meaning | In this example |
|---|---|---|
| **orange-red** | reached only by the crash | `0x00100028` — the `data[20] != 0` crash branch |
| **green** | reached by both | `0x00100000` — the shared entry block |
| **blue** | reached only by the baseline | the normal return path the crash skipped (`0x10003c`, `0x100050`, …) |

The **diff table** ranks functions by their **Crash-only** count, so the
function containing `0x100028` is at the top with `Crash-only = 1`. Double-click
that row to jump there. Open **Window ▸ Function Graph** to see the same
colouring on the block diagram — the orange-red node is exactly where the crash
diverged from every corpus input.

## Troubleshooting

- **Nothing paints / blocks land in the wrong place.** The program's base
  address is almost certainly not `0x00100000`. Re-import with the correct base,
  or use **Memory Map** to rebase.
- **Blocks paint as raw byte ranges, not whole basic blocks.** The code at those
  addresses is not disassembled — repeat step 5's disassemble/create-function,
  or run auto-analysis, then reload the coverage.
- **`afl_fuzz` missing / import errors.** You are on Python 3.13+ or stock
  Unicorn 2.1.x clobbered the instrumented one. Rebuild the venv per step 1 on
  Python 3.12 with `setuptools<81` and the `--no-deps` unicornafl install.
- **"No ColorizingService available."** Run the plugin from Ghidra's CodeBrowser
  tool (it has the Colorizer); a stripped tool will not.
