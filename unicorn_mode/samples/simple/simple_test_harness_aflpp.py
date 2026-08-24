"""
   AFL++ (unicornafl) test harness for AFL's Unicorn Mode.

   This is the modernized port of simple_test_harness.py onto AFL++'s
   unicornafl (Unicorn 2.x + AFL instrumentation). It does the same job - load
   simple_target.bin (MIPS), place the input at 0x300000, and run main() - but
   drives fuzzing through unicornafl's uc.afl_fuzz() instead of the old manual
   fork-server bootstrap and emu_start loop. afl_fuzz() owns the fork server,
   feeds each input through a callback, reports coverage to AFL, and detects
   crashes for us.

   Two modes, so no functionality is lost relative to the classic workflow:

     * Fuzzing (needs AFL++ / unicornafl):
         afl-fuzz -U -i ./sample_inputs -o ./output -- python3 \
             simple_test_harness_aflpp.py @@
       (AFL++'s afl-fuzz replaces the @@ with each testcase path.)

     * Coverage replay (stock Unicorn 2.x, works anywhere incl. macOS):
         python3 simple_test_harness_aflpp.py --coverage run.drcov \
             ./sample_inputs/sample1.bin
       Writes a drcov file for ghidra-aflcov / Lighthouse / Dragondance.

   Fuzzing throughput is best on Linux; the coverage-replay mode is what you use
   on macOS to visualize a path.
"""

import argparse
import os
import signal
import sys

# unicornafl monkeypatches the stock `unicorn` module so a normal Uc gains
# .afl_fuzz(). It is only needed to fuzz; coverage replay runs on stock Unicorn.
try:
    import unicornafl
    unicornafl.monkeypatch()
    from unicornafl import UcAflError
    HAVE_AFLPP = True
except ImportError:
    HAVE_AFLPP = False
    class UcAflError(Exception):  # placeholder so run_fuzz's except clause resolves
        pass

from unicorn import *
from unicorn.mips_const import *

# drcov coverage helper (for --coverage replay).
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'helper_scripts'))
try:
    from drcov import BlockCoverage
except ImportError:
    BlockCoverage = None

# Path to the binary to emulate
BINARY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'simple_target.bin')

# Memory map (identical to the classic harness so the same target lines up)
CODE_ADDRESS  = 0x00100000
CODE_SIZE_MAX = 0x00010000
STACK_ADDRESS = 0x00200000
STACK_SIZE    = 0x00010000
DATA_ADDRESS  = 0x00300000
DATA_SIZE_MAX = 0x00010000

# main() entry and the address just past its last instruction
START_ADDRESS = CODE_ADDRESS
END_ADDRESS   = CODE_ADDRESS + 0xf4


def force_crash(uc_error):
    """Signal AFL that a crash occurred (used in coverage-replay mode)."""
    mem_errors = [
        UC_ERR_READ_UNMAPPED, UC_ERR_READ_PROT, UC_ERR_READ_UNALIGNED,
        UC_ERR_WRITE_UNMAPPED, UC_ERR_WRITE_PROT, UC_ERR_WRITE_UNALIGNED,
        UC_ERR_FETCH_UNMAPPED, UC_ERR_FETCH_PROT, UC_ERR_FETCH_UNALIGNED,
    ]
    if uc_error.errno in mem_errors:
        os.kill(os.getpid(), signal.SIGSEGV)
    elif uc_error.errno == UC_ERR_INSN_INVALID:
        os.kill(os.getpid(), signal.SIGILL)
    else:
        os.kill(os.getpid(), signal.SIGABRT)


def build_engine():
    """Create the Unicorn engine with the target and stack mapped in."""
    uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)

    with open(BINARY_FILE, 'rb') as f:
        binary_code = f.read()
    if len(binary_code) > CODE_SIZE_MAX:
        raise RuntimeError("Binary code is too large (> {} bytes)".format(CODE_SIZE_MAX))

    uc.mem_map(CODE_ADDRESS, CODE_SIZE_MAX)
    uc.mem_write(CODE_ADDRESS, binary_code)
    uc.reg_write(UC_MIPS_REG_PC, START_ADDRESS)

    uc.mem_map(STACK_ADDRESS, STACK_SIZE)
    uc.reg_write(UC_MIPS_REG_SP, STACK_ADDRESS + STACK_SIZE)

    uc.mem_map(DATA_ADDRESS, DATA_SIZE_MAX)
    return uc


def run_fuzz(uc, input_file):
    """Hand control to AFL++ via unicornafl. Returns only when fuzzing ends."""
    def place_input_callback(uc, input, persistent_round, data):
        # Reject over-long inputs so AFL treats them as uninteresting.
        if len(input) > DATA_SIZE_MAX:
            return False
        uc.mem_write(DATA_ADDRESS, input)

    # afl_fuzz starts the fork server, replays each input through the callback,
    # and stops emulation at any address in `exits`.
    try:
        uc.afl_fuzz(input_file=input_file,
                    place_input_callback=place_input_callback,
                    exits=[END_ADDRESS])
    except UcAflError as e:
        # Raised when there is no AFL fork server around (e.g. run directly, or
        # under afl-showmap): unicornafl did one emulation and has nothing to
        # fork to. That is not a failure of the harness.
        if "No AFL" in str(e) or "no need to fork" in str(e):
            print("[*] Ran once without an AFL fork server (not fuzzing). "
                  "Launch under afl-fuzz to fuzz, or use --coverage to record a path.")
            return
        raise


def run_coverage(uc, input_file, coverage_file):
    """Run one input on stock Unicorn and write drcov coverage for a disassembler."""
    if BlockCoverage is None:
        print("ERROR: drcov.py not found; cannot record coverage")
        return 1

    cov = BlockCoverage(base=CODE_ADDRESS, end=CODE_ADDRESS + CODE_SIZE_MAX,
                        path="simple_target.bin")
    uc.hook_add(UC_HOOK_BLOCK, cov.hook)

    with open(input_file, 'rb') as f:
        data = f.read()
    if len(data) > DATA_SIZE_MAX:
        print("Test input is too long (> {} bytes)".format(DATA_SIZE_MAX))
        return 1
    uc.mem_write(DATA_ADDRESS, data)

    try:
        uc.emu_start(START_ADDRESS, END_ADDRESS, timeout=0, count=0)
    except UcError as e:
        print("Execution failed with error: {}".format(e))

    cov.save(coverage_file)
    print("Wrote {} basic blocks of coverage to {}".format(len(cov.blocks), coverage_file))
    return 0


def main():
    parser = argparse.ArgumentParser(description="AFL++ unicornafl harness for simple_target.bin")
    parser.add_argument('input_file', type=str, help="Path to the input testcase")
    parser.add_argument('-c', '--coverage', type=str, default=None, metavar="FILE",
                        help="Replay one input on stock Unicorn and write drcov coverage to FILE "
                             "(for ghidra-aflcov). Does not fuzz.")
    args = parser.parse_args()

    uc = build_engine()

    if args.coverage:
        return run_coverage(uc, args.input_file, args.coverage)

    if not HAVE_AFLPP:
        print("ERROR: unicornafl is not installed, so fuzzing is unavailable on this host.")
        print("       Install AFL++ unicorn_mode (build_unicorn_support.sh), or use")
        print("       --coverage to replay a single input for visualization.")
        return 1

    run_fuzz(uc, args.input_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
