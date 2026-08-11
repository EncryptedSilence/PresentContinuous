"""tools/tests/test_m4_layout.py -- guard on the M4 .timed section address.

The Cortex-M4 build found up to 7.5% variation in measured cycle counts
depending on where the timed kernel happened to land relative to the
STM32F407's 128-bit flash fetch boundary (see fw/m4/link/product.ld and the
Makefile comment above -falign-functions=16). fw/m4/link/product.ld pins a
`.timed` output section at a fixed flash address ahead of `.text` so that
address no longer depends on whatever else is in the image; this test is the
guard that the pin actually holds, in the built ELF rather than only in the
linker script's text.

EXPECTED_TIMED_IMAGES is the cross-task contract: fw/m4/ctr_layout_probe.c's
`ctr_timed_kernel` is a permanent fixture (not the CTR kernel itself, which
lands in a later task) so this check stays meaningful even when no CTR image
has been built. A later task's per-cipher CTR images are additional entries
here, each carrying their own `.timed`-tagged entry point at the same address
in their own image; they do not replace ctr_layout_probe.

Deliberately NOT a glob over every file under build/m4/: this repository has a
documented history (Makefile, around the `test:` target) of a test that ran
nowhere for twelve tasks and no one noticed. A glob that silently skips any
image lacking the symbol is the same failure shape one level down -- it would
pass while checking nothing if, say, the Makefile rule that is supposed to tag
a new image's kernel were simply never wired up. So the set of images expected
to carry the symbol is explicit and is asserted non-empty; anything not in the
set (kat.elf, hello.elf, ...) is simply not checked. `make test` builds
build/m4/ctr_layout_probe.elf automatically when the cross toolchain is on
PATH (see M4_NM_PRESENT in the Makefile); running this module directly first
needs `make m4-ctr-layout-probe`.
"""
import os
import shutil
import subprocess
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
BUILD_M4 = os.path.join(ROOT, "build", "m4")

NM = shutil.which("arm-none-eabi-nm")

# The cross-task contract. Two kinds of image carry the pinned kernel:
#
#   ctr_layout_probe  the permanent standalone fixture (fw/m4/ctr_layout_probe.c), which
#                     depends on nothing else in the firmware and keeps this check
#                     meaningful even with no CTR image built.
#   ctr_fixture       the real counter-mode harness (fw/m4/ctr_m4_main.c) built for one
#                     cipher with a fixed winner, so the check covers the ACTUAL harness
#                     the published winner images are built from -- the pin is a property
#                     of the linker script and the section attribute, identical whichever
#                     backend the freeze selects, so this one image proves it for all of
#                     them. `make test` builds both automatically once arm-none-eabi-nm is
#                     on PATH (see M4_NM_PRESENT in the Makefile).
#
# The published ctr_<slug>_product winner images carry the same pin by the same
# mechanism; they are measured by tools/campaign.py m4 --measure and are not rebuilt here
# because their winners come from the committed freeze rather than from this test.
EXPECTED_TIMED_IMAGES = ["ctr_layout_probe", "ctr_fixture"]

TIMED_SYMBOL = "ctr_timed_kernel"
TIMED_ADDRESS = 0x08010000


def _nm_symbols(elf_path):
    """name -> address for every symbol `arm-none-eabi-nm -n` reports with one.

    Undefined symbols (type U) print with a blank address field instead of a
    hex address and are skipped; every other line is `<addr> <type> <name>`.
    """
    out = subprocess.run(
        [NM, "-n", elf_path], capture_output=True, text=True, check=True
    ).stdout
    symbols = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        addr_str, _sym_type, name = parts
        try:
            symbols[name] = int(addr_str, 16)
        except ValueError:
            continue
    return symbols


class TestExpectedImageSet(unittest.TestCase):
    """Runs unconditionally, independent of the cross toolchain.

    An empty EXPECTED_TIMED_IMAGES must fail the suite outright rather than
    let TestM4Layout below iterate zero images and report success -- that is
    the "checked nothing but passed" failure mode this file exists to avoid,
    and it must be visible even on a machine with no cross compiler at all.
    """

    def test_expected_image_set_is_not_empty(self):
        self.assertTrue(
            EXPECTED_TIMED_IMAGES,
            "EXPECTED_TIMED_IMAGES is empty -- no image is registered to "
            "carry " + TIMED_SYMBOL + ", so a run over it would pass having "
            "checked nothing",
        )


class TestM4Layout(unittest.TestCase):
    """Requires arm-none-eabi-nm; skips the whole class (visibly) without it.

    This is a genuine environment skip -- there is nothing to inspect a Cortex-M4
    ELF's symbol table with -- and is not the same condition as
    TestExpectedImageSet failing above; `-v` output shows the two apart by name.
    """

    @classmethod
    def setUpClass(cls):
        if NM is None:
            raise unittest.SkipTest(
                "arm-none-eabi-nm not found on PATH -- cannot inspect M4 ELF "
                "symbol tables on this machine; install the arm-none-eabi "
                "cross toolchain to run this check"
            )

    def test_timed_kernel_is_pinned_in_every_expected_image(self):
        for name in EXPECTED_TIMED_IMAGES:
            elf_path = os.path.join(BUILD_M4, name + ".elf")
            with self.subTest(image=name):
                self.assertTrue(
                    os.path.isfile(elf_path),
                    "%s not built -- run `make m4-ctr-layout-probe` (or "
                    "`make test`, which builds it automatically once "
                    "arm-none-eabi-nm is on PATH) before running this test"
                    % elf_path,
                )
                symbols = _nm_symbols(elf_path)
                self.assertIn(
                    TIMED_SYMBOL,
                    symbols,
                    "%s: %s is missing from the symbol table entirely"
                    % (elf_path, TIMED_SYMBOL),
                )
                addr = symbols[TIMED_SYMBOL]
                self.assertEqual(
                    addr,
                    TIMED_ADDRESS,
                    "%s: %s linked at 0x%08x, expected the fixed address "
                    "0x%08x -- the .timed section in fw/m4/link/product.ld "
                    "did not pin it"
                    % (elf_path, TIMED_SYMBOL, addr, TIMED_ADDRESS),
                )


if __name__ == "__main__":
    unittest.main()
