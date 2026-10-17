"""定时任务出错时要先发失败通知再照常失败（离线，不连 SMTP、不调 nmap）。"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import ipm  # noqa: E402


class TestFailureMail(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.env = self.tmp / ".env"
        self.env.write_text("SMTP_SERVER=s\nSENDER_EMAIL=a@x\nSENDER_PASSWORD=p\n"
                            "RECIPIENT_EMAILS=b@x\n", encoding="utf-8")
        self.sent = []

    def _send(self, cfg, subject, body, attachments=()):
        self.sent.append((subject, body))
        return cfg.recipients

    def test_rov_exception_sends_failure_mail_and_reraises(self):
        with mock.patch.object(ipm.mailer, "send", self._send):
            with self.assertRaises(FileNotFoundError):
                ipm.main(["rov", "--email", "--env", str(self.env),
                          "--list", str(self.tmp / "missing.list")])
        self.assertEqual(len(self.sent), 1)
        subject, body = self.sent[0]
        self.assertIn("[ipm] ROA/IRR 校验 ✗ 运行失败", subject)
        self.assertIn("FileNotFoundError", subject)
        self.assertIn("Traceback", body)

    def test_scan_systemexit_sends_failure_mail(self):
        empty = self.tmp / "prefix.list"
        empty.write_text("# no prefixes\n", encoding="utf-8")
        with mock.patch.object(ipm.mailer, "send", self._send), \
                mock.patch.object(ipm.scan_mod, "nmap_available", lambda: True):
            with self.assertRaises(SystemExit) as cm:
                ipm.main(["scan", "--email", "--env", str(self.env),
                          "--prefix-list", str(empty)])
        self.assertIn("没有 IPv4 前缀", str(cm.exception.code))
        self.assertIn("IPv4 在用地址扫描 ✗ 运行失败", self.sent[0][0])

    def test_no_failure_mail_without_email_flag(self):
        with mock.patch.object(ipm.mailer, "send", self._send):
            with self.assertRaises(FileNotFoundError):
                ipm.main(["rov", "--list", str(self.tmp / "missing.list")])
        self.assertEqual(self.sent, [])

    def test_mail_failure_does_not_hide_original_error(self):
        def broken(*a, **k):
            raise OSError("smtp down")
        with mock.patch.object(ipm.mailer, "send", broken):
            with self.assertRaises(FileNotFoundError):
                ipm.main(["rov", "--email", "--env", str(self.env),
                          "--list", str(self.tmp / "missing.list")])


if __name__ == "__main__":
    unittest.main()
