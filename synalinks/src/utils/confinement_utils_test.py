# License Apache 2.0: (c) 2025-2026 Yoan Sallami (Synalinks Team)

import sys
import types
import unittest
from unittest import mock

from synalinks.src import testing
from synalinks.src.utils import confinement_utils


@unittest.skipIf(sys.platform == "win32", "the probe forks: Linux and macOS only")
class ConfinementProbeTest(testing.TestCase):
    """The user-namespace probe of `confinement_available`, its child faked."""

    def probe(self, *exit_codes):
        """Run `confinement_available` once per exit code of the probe's child."""
        statuses = iter(code << 8 for code in exit_codes)

        def no_userns_switch(path, *args, **kwargs):
            raise OSError(path)  # as on distros without the switch

        with (
            mock.patch.object(confinement_utils, "confine_smoke_cache", None),
            mock.patch.object(confinement_utils.platform, "system", return_value="Linux"),
            mock.patch.object(confinement_utils.os.path, "exists", return_value=True),
            mock.patch.object(confinement_utils.os, "unshare", create=True),
            mock.patch.dict(sys.modules, {"mfusepy": types.ModuleType("mfusepy")}),
            mock.patch.object(confinement_utils, "open", no_userns_switch, create=True),
            mock.patch.object(confinement_utils.os, "fork", return_value=4242),
            mock.patch.object(
                confinement_utils.os,
                "waitpid",
                side_effect=lambda pid, flags: (pid, next(statuses)),
            ),
        ):
            return [confinement_utils.confinement_available() for _ in exit_codes]

    def test_a_refusal_is_probed_again_and_a_later_pass_counts(self):
        refused, passed, cached = self.probe(92, 0, 92)
        self.assertFalse(refused[0])
        self.assertIn("writing /proc/self/uid_map was refused", refused[1])
        self.assertEqual(passed, (True, ""))
        # Once confinement worked it is not probed again.
        self.assertEqual(cached, (True, ""))

    def test_the_refused_step_is_named(self):
        for code, step in confinement_utils.PROBE_STEPS.items():
            [(ok, reason)] = self.probe(code)
            self.assertFalse(ok)
            self.assertIn(step, reason)

    def test_a_child_killed_by_a_signal_is_a_refusal(self):
        with mock.patch.object(confinement_utils.os, "WIFEXITED", return_value=False):
            [(ok, reason)] = self.probe(0)
        self.assertFalse(ok)
        self.assertIn("the probe child was refused", reason)
