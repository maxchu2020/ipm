"""把校验报表通过 SMTP 推送出去。

凭证从 .env 读（该文件 600 权限且不入库），不硬编码在代码里。
只用标准库，无第三方依赖。
"""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, formatdate
from pathlib import Path


def load_env(path) -> dict:
    """极简 .env 解析：KEY=VALUE，# 开头为注释，值里的 = 保留。"""
    env = {}
    path = Path(path)
    if not path.is_file():
        return env
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def _addrs(value: str) -> list:
    return [x.strip() for x in (value or "").split(",") if x.strip()]


class MailConfig:
    def __init__(self, env: dict):
        self.server = env.get("SMTP_SERVER", "")
        self.port = int(env.get("SMTP_PORT", "587") or 587)
        self.sender = env.get("SENDER_EMAIL", "")
        self.password = env.get("SENDER_PASSWORD", "")
        self.to = _addrs(env.get("RECIPIENT_EMAILS", ""))
        self.bcc = _addrs(env.get("BCC_EMAILS", ""))

    @property
    def recipients(self) -> list:
        """实际投递地址 = 收件人 + 密送，去重但保持顺序。"""
        seen, out = set(), []
        for a in self.to + self.bcc:
            if a.lower() not in seen:
                seen.add(a.lower())
                out.append(a)
        return out

    def missing(self) -> list:
        lack = [name for name, val in
                (("SMTP_SERVER", self.server), ("SENDER_EMAIL", self.sender),
                 ("SENDER_PASSWORD", self.password)) if not val]
        if not self.recipients:
            lack.append("RECIPIENT_EMAILS/BCC_EMAILS")
        return lack


def build_message(cfg: MailConfig, subject: str, text_body: str,
                  attachments=()) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr(("ipm ROA/IRR 校验", cfg.sender))
    msg["To"] = ", ".join(cfg.to) or cfg.sender
    msg["Date"] = formatdate(localtime=True)
    # Bcc 只放进投递地址，不写进信头，否则密送就失去意义

    msg.set_content(text_body)
    msg.add_alternative(_html(text_body), subtype="html")

    for path in attachments:
        path = Path(path)
        if not path.is_file():
            continue
        data = path.read_bytes()
        maintype, subtype = _mime_for(path)
        msg.add_attachment(data, maintype=maintype, subtype=subtype,
                           filename=path.name)
    return msg


def _mime_for(path: Path):
    return {".csv": ("text", "csv"), ".json": ("application", "json"),
            ".txt": ("text", "plain")}.get(path.suffix, ("application", "octet-stream"))


def _html(text: str) -> str:
    """报表是等宽对齐的，HTML 里必须用 <pre> + 等宽字体才不会散架。"""
    escaped = (text.replace("&", "&amp;").replace("<", "&lt;")
               .replace(">", "&gt;"))
    return ("<html><body style=\"margin:0;padding:12px;background:#fff\">"
            "<pre style=\"font-family:'DejaVu Sans Mono',Menlo,Consolas,"
            "monospace;font-size:12px;line-height:1.4;white-space:pre;"
            "overflow-x:auto\">" + escaped + "</pre></body></html>")


def send(cfg: MailConfig, subject: str, text_body: str, attachments=(),
         timeout: int = 30) -> list:
    """发送并返回实际投递地址；配置不全或发送失败时抛异常。"""
    lack = cfg.missing()
    if lack:
        raise ValueError("邮件配置缺少：" + "、".join(lack))

    msg = build_message(cfg, subject, text_body, attachments)
    with smtplib.SMTP(cfg.server, cfg.port, timeout=timeout) as smtp:
        smtp.ehlo()
        smtp.starttls(context=ssl.create_default_context())
        smtp.ehlo()
        smtp.login(cfg.sender, cfg.password)
        smtp.send_message(msg, from_addr=cfg.sender, to_addrs=cfg.recipients)
    return cfg.recipients
