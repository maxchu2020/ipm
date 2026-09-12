"""邮件推送的单元测试（不连 SMTP，只验证配置解析与信件构造）。"""

import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from ipmlib.mailer import MailConfig, build_message, load_env, send

SAMPLE = """# === Email Configuration (Gmail) ===
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=a@example.com
SENDER_PASSWORD=abcd efgh ijkl mnop

# === Recipients ===
RECIPIENT_EMAILS=to1@example.com, to2@example.com

# === BCC Recipients ===
BCC_EMAILS=bcc@example.com
"""


class TestLoadEnv(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.path = Path(self._dir.name) / ".env"
        self.path.write_text(SAMPLE, encoding="utf-8")

    def tearDown(self):
        self._dir.cleanup()

    def test_parses_keys_and_skips_comments(self):
        env = load_env(self.path)
        self.assertEqual(env["SMTP_SERVER"], "smtp.gmail.com")
        self.assertEqual(env["SENDER_EMAIL"], "a@example.com")
        self.assertNotIn("#", "".join(env))

    def test_password_with_spaces_preserved(self):
        # Gmail 应用专用密码自带空格，不能被截断
        self.assertEqual(load_env(self.path)["SENDER_PASSWORD"],
                         "abcd efgh ijkl mnop")

    def test_missing_file_is_empty(self):
        self.assertEqual(load_env(Path(self._dir.name) / "nope"), {})


class TestMailConfig(unittest.TestCase):
    def cfg(self, **over):
        env = dict(SMTP_SERVER="s", SMTP_PORT="587", SENDER_EMAIL="a@x.com",
                   SENDER_PASSWORD="p", RECIPIENT_EMAILS="t@x.com",
                   BCC_EMAILS="b@x.com")
        env.update(over)
        return MailConfig(env)

    def test_recipients_include_bcc(self):
        self.assertEqual(self.cfg().recipients, ["t@x.com", "b@x.com"])

    def test_recipients_deduplicated_case_insensitively(self):
        c = self.cfg(RECIPIENT_EMAILS="t@x.com", BCC_EMAILS="T@X.com,b@x.com")
        self.assertEqual(c.recipients, ["t@x.com", "b@x.com"])

    def test_multiple_recipients_split_and_trimmed(self):
        c = self.cfg(RECIPIENT_EMAILS="a@x.com , b@x.com", BCC_EMAILS="")
        self.assertEqual(c.to, ["a@x.com", "b@x.com"])

    def test_missing_reports_each_gap(self):
        self.assertEqual(self.cfg(SENDER_PASSWORD="").missing(),
                         ["SENDER_PASSWORD"])
        self.assertIn("RECIPIENT_EMAILS/BCC_EMAILS",
                      self.cfg(RECIPIENT_EMAILS="", BCC_EMAILS="").missing())
        self.assertEqual(self.cfg().missing(), [])

    def test_send_refuses_incomplete_config(self):
        with self.assertRaises(ValueError):
            send(self.cfg(SMTP_SERVER=""), "s", "body")


class TestBuildMessage(unittest.TestCase):
    def setUp(self):
        self.cfg = MailConfig(dict(
            SMTP_SERVER="s", SENDER_EMAIL="a@x.com", SENDER_PASSWORD="p",
            RECIPIENT_EMAILS="t@x.com", BCC_EMAILS="b@x.com"))

    def test_bcc_not_in_headers(self):
        """密送地址只能出现在投递地址里，写进信头就不是密送了。"""
        msg = build_message(self.cfg, "主题", "正文")
        self.assertNotIn("Bcc", msg)
        self.assertNotIn("b@x.com", str(msg))
        self.assertIn("b@x.com", self.cfg.recipients)

    def test_has_plain_and_html_parts(self):
        msg = build_message(self.cfg, "主题", "正文")
        types = {p.get_content_type() for p in msg.walk()}
        self.assertIn("text/plain", types)
        self.assertIn("text/html", types)

    def test_html_escapes_and_preserves_alignment(self):
        msg = build_message(self.cfg, "s", "a < b & c")
        html = msg.get_body(preferencelist=("html",)).get_content()
        self.assertIn("&lt;", html)
        self.assertIn("&amp;", html)
        self.assertIn("<pre", html)          # 等宽，报表对齐才不会散

    def test_attachments_added_with_filenames(self):
        with tempfile.TemporaryDirectory() as d:
            csv = Path(d) / "rov.csv"
            csv.write_text("a,b\n1,2\n", encoding="utf-8")
            msg = build_message(self.cfg, "s", "body", [csv])
            names = [p.get_filename() for p in msg.iter_attachments()]
            self.assertEqual(names, ["rov.csv"])

    def test_missing_attachment_skipped_silently(self):
        msg = build_message(self.cfg, "s", "body", [Path("/nonexistent.csv")])
        self.assertEqual(list(msg.iter_attachments()), [])


class TestSubjectLine(unittest.TestCase):
    def test_subjects(self):
        import datetime
        import ipaddress
        from ipmlib.roa import Vrp
        from ipmlib.rov import evaluate
        from ipmlib.rov_report import subject_line

        n = ipaddress.ip_network
        far = Vrp(n("10.0.0.0/24"), 65000, 24, 0, "t", 9999999999)
        soon = Vrp(n("10.0.0.0/24"), 65000, 24, 0, "t", int(
            datetime.datetime.now(datetime.timezone.utc).timestamp() + 5 * 86400))

        ok = subject_line(evaluate([(n("10.0.0.0/24"), 65000)], [far], {}, {}))
        self.assertIn("正常", ok)
        self.assertNotIn("⚠", ok)

        bad = subject_line(evaluate([(n("10.0.0.0/24"), 65001)], [far], {}, {}))
        self.assertIn("⚠", bad)
        self.assertIn("无授权", bad)

        exp = subject_line(evaluate([(n("10.0.0.0/24"), 65000)], [soon], {}, {}))
        self.assertIn("将到期", exp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
