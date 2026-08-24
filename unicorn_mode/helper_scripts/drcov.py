"""
    drcov.py

    Writes DynamoRIO drcov coverage files from a Unicorn emulation run.

    The drcov format is the lingua franca of coverage tooling: DynamoRIO's own
    drcov client, Lighthouse, Dragondance and the companion ghidra-aflcov plugin
    all read it. Emitting it here means an afl-unicorn harness can hand its
    coverage straight to any of them, and the code paths a fuzzing input took can
    be painted onto the disassembly.

    Two pieces:
      - DrcovWriter: the pure file format. No Unicorn dependency, so it is easy
        to test on its own.
      - BlockCoverage: a UC_HOOK_BLOCK callback that records which basic blocks
        executed, keyed to one module, then writes them out via DrcovWriter.

    Usage from a harness:

        from drcov import BlockCoverage
        cov = BlockCoverage(base=0x400000, end=0x452000, path="target.bin")
        uc.hook_add(UC_HOOK_BLOCK, cov.hook)
        # ... run emu_start ...
        cov.save("run.drcov")

    Block offsets are stored relative to the module base, exactly as drcov
    expects, so the result is independent of where the module was mapped and
    lines up with the binary's RVAs in a disassembler.
"""

import struct

# One drcov basic-block table entry: u32 start (offset from module base),
# u16 size, u16 module id. Little-endian.
_BB_STRUCT = struct.Struct("<IHH")


class DrcovModule(object):
    __slots__ = ("id", "base", "end", "path")

    def __init__(self, module_id, base, end, path):
        self.id = module_id
        self.base = base
        self.end = end
        self.path = path


class DrcovWriter(object):
    """Accumulates modules and basic blocks and serializes them as drcov v2."""

    def __init__(self):
        self._modules = []
        # set of (module_id, start_offset, size); a set so repeated hits of the
        # same block collapse to one coverage entry
        self._blocks = set()

    def add_module(self, path, base, end, module_id=None):
        """Register a module and return its id."""
        if module_id is None:
            module_id = len(self._modules)
        self._modules.append(DrcovModule(module_id, base, end, path))
        return module_id

    def add_block(self, module_id, start_offset, size):
        """Record one executed basic block as an offset from its module base."""
        self._blocks.add((module_id, start_offset & 0xFFFFFFFF,
                          size & 0xFFFF, ))

    def block_count(self):
        return len(self._blocks)

    def to_bytes(self):
        header = []
        header.append("DRCOV VERSION: 2")
        header.append("DRCOV FLAVOR: drcov")
        header.append("Module Table: version 2, count %d" % len(self._modules))
        header.append("Columns: id, base, end, entry, checksum, timestamp, path")
        for m in self._modules:
            header.append("  %d, 0x%016x, 0x%016x, 0x%016x, 0x0, 0x0, %s"
                          % (m.id, m.base, m.end, m.base, m.path))
        header.append("BB Table: %d bbs" % len(self._blocks))
        text = ("\n".join(header) + "\n").encode("utf-8")

        # Sort for deterministic output; the format itself is order-independent.
        body = bytearray()
        for module_id, start, size in sorted(self._blocks):
            body += _BB_STRUCT.pack(start, size, module_id)
        return bytes(text) + bytes(body)

    def save(self, path):
        with open(path, "wb") as f:
            f.write(self.to_bytes())


class BlockCoverage(object):
    """
    Collects basic-block coverage for a single module during emulation.

    Register hook() as a UC_HOOK_BLOCK callback. Blocks outside [base, end) are
    ignored, so hits in loader stubs or the emulator's own scratch memory do not
    pollute the module's coverage.
    """

    def __init__(self, base, end, path, module_id=0):
        if end <= base:
            raise ValueError("module end (0x%x) must be above base (0x%x)" % (end, base))
        self.base = base
        self.end = end
        self.path = path
        self.module_id = module_id
        # (start_offset, size) pairs, deduplicated
        self.blocks = set()

    def hook(self, uc, address, size, user_data):
        """UC_HOOK_BLOCK callback: (uc, address, size, user_data)."""
        if self.base <= address < self.end:
            self.blocks.add((address - self.base, size))

    def to_writer(self):
        w = DrcovWriter()
        w.add_module(self.path, self.base, self.end, self.module_id)
        for start, size in self.blocks:
            w.add_block(self.module_id, start, size)
        return w

    def save(self, path):
        self.to_writer().save(path)


if __name__ == "__main__":
    # Self-test: fabricate a few block hits and write a demo file.
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "demo.drcov"
    cov = BlockCoverage(base=0x400000, end=0x452000, path="target.bin")
    for addr, size in [(0x401000, 0x20), (0x401020, 0x10), (0x401234, 0x08),
                       (0x401000, 0x20)]:   # repeat is deduped
        cov.hook(None, addr, size, None)
    cov.save(out)
    print("wrote %s: %d unique blocks" % (out, len(cov.blocks)))
