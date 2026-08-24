# Coverage visualization

afl-unicorn can record which basic blocks an input drove through during
emulation and write them to a [drcov](https://dynamorio.org/page_drcov.html)
file. drcov is the format used by DynamoRIO, Lighthouse and Dragondance, and by
the companion [ghidra-aflcov](https://github.com/sengi12/ghidra-aflcov) plugin,
which paints the executed blocks onto Ghidra's Listing and Function Graph.

Coverage is meant for **replaying a single input outside the fuzzing loop** - a
crashing testcase, or an interesting corpus entry - so you can see the path it
took. Do not enable it while fuzzing under AFL; it writes a file per run and
slows emulation.

## The format module

[`helper_scripts/drcov.py`](helper_scripts/drcov.py) is a dependency-free writer:

- `DrcovWriter` — serializes modules + basic blocks to drcov v2.
- `BlockCoverage` — a `UC_HOOK_BLOCK` callback that records executed blocks for
  one module, then writes them out.

Block offsets are stored relative to the module base, so the output is
independent of where the code was mapped and lines up with the binary's RVAs in
a disassembler.

## From a harness that uses AflUnicornEngine

The engine collects coverage when constructed with `enable_coverage=True`, and
writes it with `dump_coverage()`:

```python
from unicorn_loader import AflUnicornEngine

uc = AflUnicornEngine(context_dir, enable_coverage=True)
# ... uc.emu_start(...) ...
uc.dump_coverage("run.drcov")   # base/end default to the loaded executable span
```

Pass `base=`, `end=` and `module_name=` to `dump_coverage()` to pin the module
range explicitly - recommended when the context is a whole-process dump with
several mapped objects and you only care about one.

## From a harness that uses raw Unicorn

Use `BlockCoverage` directly, as the simple sample does
([`samples/simple/simple_test_harness.py`](samples/simple/simple_test_harness.py)):

```python
from drcov import BlockCoverage

cov = BlockCoverage(base=CODE_ADDRESS, end=CODE_ADDRESS + CODE_SIZE_MAX,
                    path="simple_target.bin")
uc.hook_add(UC_HOOK_BLOCK, cov.hook)
# ... uc.emu_start(...) ...
cov.save("run.drcov")
```

The sample exposes this behind a flag:

```sh
python simple_test_harness.py --coverage run.drcov ./sample_inputs/sample1.bin
```

## Viewing it in Ghidra

1. Open the same binary you emulated and let auto-analysis finish.
2. Add the `ghidra-aflcov` directory to Ghidra's script directories.
3. Run `AflCoverage.java` (Alt-A), then **Load drcov…** and pick your file.

The covered blocks turn green and the panel lists per-function coverage. If the
blocks land in the wrong place, set Ghidra's image base to the module base you
used when recording (for the simple sample, that is `CODE_ADDRESS`, `0x100000`).
