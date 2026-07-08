# modules/alerting/email.py
from __future__ import annotations
from typing import Any, Dict, List, Optional
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

logger = logging.getLogger('uvicorn.error')
logger.setLevel(logging.DEBUG)


class Module:
    """Send alert e-mails through an SMTP relay host."""

    def __init__(self, config: Dict[str, Any]) -> None:
        self.cfg = config or {}
        self.host = self.cfg.get("smtp_host", "localhost")
        self.port = int(self.cfg.get("smtp_port", 25))
        self.use_tls = bool(self.cfg.get("smtp_tls", False))
        self.use_starttls = bool(self.cfg.get("smtp_starttls", False))
        self.username = self.cfg.get("smtp_username", "")
        self.password = self.cfg.get("smtp_password", "")
        self.sender = self.cfg.get("sender", "draugnet@localhost")
        self.recipients: List[str] = self.cfg.get("recipients", [])
        self.subject_prefix = self.cfg.get("subject_prefix", "[Draugnet]")

    def _connect(self) -> smtplib.SMTP:
        """Create and return an authenticated SMTP connection."""
        if self.use_tls:
            server = smtplib.SMTP_SSL(self.host, self.port, timeout=30)
        else:
            server = smtplib.SMTP(self.host, self.port, timeout=30)
        if self.use_starttls and not self.use_tls:
            server.starttls()
        if self.username and self.password:
            server.login(self.username, self.password)
        return server

    def send(
        self,
        subject: str,
        body: str,
        *,
        recipients: Optional[List[str]] = None,
        html: bool = False,
    ) -> bool:
        """Send an alert e-mail.

        Args:
            subject:    E-mail subject (the configured prefix is prepended).
            body:       Plain-text (or HTML) body.
            recipients: Override the default recipient list for this message.
            html:       If True, send the body as text/html instead of text/plain.

        Returns:
            True on success, False on failure (errors are logged, not raised).
        """
        to_addrs = recipients or self.recipients
        if not to_addrs:
            logger.warning("Email alerting: no recipients configured, skipping send")
            return False

        msg = MIMEMultipart("alternative")
        msg["From"] = self.sender
        msg["To"] = ", ".join(to_addrs)
        msg["Subject"] = f"{self.subject_prefix} {subject}"

        content_type = "html" if html else "plain"
        msg.attach(MIMEText(body, content_type, "utf-8"))

        try:
            server = self._connect()
            server.sendmail(self.sender, to_addrs, msg.as_string())
            server.quit()
            logger.info("Alert e-mail sent: %s -> %s", subject, to_addrs)
            return True
        except Exception as e:
            logger.error("Failed to send alert e-mail: %s", e)
            return False
