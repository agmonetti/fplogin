#!/usr/bin/env python3
"""Consumer-visible evidence boundaries for the SDDM lab collector."""
import unittest

from collect_sddm_lab import Capture

BOOT = "a" * 32
REQUEST = "12345678-1234-4234-8234-123456789abc"
OTHER_REQUEST = "87654321-4321-4321-8321-cba987654321"


def entry(message, pid="100", boot=BOOT, unit="sddm-lab.service"):
    return {
        "MESSAGE": message, "_PID": pid, "_BOOT_ID": boot,
        "__MONOTONIC_TIMESTAMP": "1000", "_SYSTEMD_UNIT": unit,
    }


class CaptureTest(unittest.TestCase):
    def test_quoted_logind_sessions_strip_user_and_keep_unknown_binding(self):
        capture = Capture()
        opened = capture.normalize(entry(
            "New session 'c1' of user 'private-user' with class 'greeter' and type 'x11'.",
            unit="systemd-logind.service",
        ))
        self.assertEqual(opened["session"], "c1")
        self.assertEqual(opened["event"], "session-new")
        self.assertIsNone(opened["request"])
        self.assertNotIn("private-user", str(opened))
        closed = capture.normalize(entry(
            "Session 'c1' logged out. Waiting for processes to exit.",
            unit="systemd-logind.service",
        ))
        self.assertEqual(closed["session"], "c1")
        self.assertEqual(closed["event"], "session-ended")

    def test_helper_pid_reuse_and_boot_change_cannot_reuse_old_request(self):
        capture = Capture()
        capture.normalize(entry(
            f"FPLOGIN_TRACE event=helper-start request={REQUEST} helper_pid=200 generation=2 method=1 role=fingerprint"
        ))
        pam = capture.normalize(entry("FPLOGIN_PAM phase=authenticate edge=return rc=0", pid="200"))
        self.assertEqual(pam["request"], REQUEST)
        self.assertEqual(pam["generation"], "2")
        unknown = capture.normalize(entry("FPLOGIN_PAM phase=end edge=return rc=0", pid="200", boot="b" * 32))
        self.assertIsNone(unknown["request"])
        capture.normalize(entry(
            f"FPLOGIN_TRACE event=helper-startup request={OTHER_REQUEST} helper_pid=200 method=0 role=password",
            pid="200",
        ))
        retried = capture.normalize(entry("FPLOGIN_PAM phase=authenticate edge=return rc=0", pid="200"))
        self.assertEqual(retried["request"], OTHER_REQUEST)
        self.assertEqual(retried["role"], "password")
        self.assertIsNone(retried["generation"])

    def test_unrecognized_messages_and_secret_shaped_fields_are_discarded(self):
        capture = Capture()
        for message in (
            "PAM response: private-password",
            "FPLOGIN_TRACE event=private-password",
            "FPLOGIN_TRACE event=helper-start request=private-password helper_pid=200",
            f"FPLOGIN_TRACE event=helper-start request={REQUEST} helper_pid=200 password=private-password",
            "FPLOGIN_PAM phase=authenticate edge=return rc=private-password",
        ):
            with self.subTest(message=message):
                self.assertIsNone(capture.normalize(entry(message)))


if __name__ == "__main__":
    unittest.main()
