#!/usr/bin/env python3
"""
Production SSL Certificate Monitoring Script (Excel Version)
Zoho SMTP + Environment Variables + SSL Context Safe
"""

import os
import sys
import ssl
import subprocess
import smtplib
import logging
import argparse
import time
import schedule
import pandas as pd
from pathlib import Path
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# ============================================================
# CONFIGURATION FROM ENVIRONMENT VARIABLES
# ============================================================

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
FROM_EMAIL = os.getenv("FROM_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

ABOUT_TO_EXPIRE_EMAIL = os.getenv("ABOUT_TO_EXPIRE_EMAIL")
ABOUT_TO_EXPIRE_CC = os.getenv("ABOUT_TO_EXPIRE_CC")
EXPIRED_EMAIL = os.getenv("EXPIRED_EMAIL")

EXCEL_FILE_PATH = "./domains.xlsx"
EXCEL_SHEET_NAME = "Sheet1"

SCHEDULE_HOUR = 18  # default 5 PM


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("ssl_monitor.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)


# ============================================================
# VALIDATION
# ============================================================

def validate_config():
    required = [SMTP_SERVER, FROM_EMAIL, SMTP_PASSWORD]
    if not all(required):
        logger.error("SMTP configuration missing in environment variables.")
        sys.exit(1)


# ============================================================
# EXCEL READER
# ============================================================

class ExcelAPI:

    def __init__(self, file_path, sheet_name):
        self.file_path = Path(file_path)
        self.sheet_name = sheet_name

    def get_domains(self):
        if not self.file_path.exists():
            logger.error(f"Excel file not found: {self.file_path}")
            return []

        df = pd.read_excel(self.file_path, sheet_name=self.sheet_name)

        domains = []
        for _, row in df.iterrows():
            domain = str(row.get("Domain", "")).strip()
            port = str(row.get("Port", "443")).strip()

            if domain:
                domains.append({"domain": domain, "port": port})

        return domains


# ============================================================
# SSL CHECKER
# ============================================================

class SSLChecker:

    @staticmethod
    def check(domain, port):
        try:
            cmd = f"echo | openssl s_client -servername {domain} -connect {domain}:{port} 2>/dev/null | openssl x509 -noout -enddate"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                return None

            import re
            match = re.search(r'notAfter=(.+)', result.stdout)
            if not match:
                return None

            expiry_str = match.group(1).strip()
            expiry_date = datetime.strptime(expiry_str.replace(" GMT", ""), "%b %d %H:%M:%S %Y")

            days_left = (expiry_date - datetime.utcnow()).days

            return {
                "domain": domain,
                "port": port,
                "expiry": expiry_date,
                "days_left": days_left
            }

        except Exception as e:
            logger.error(f"SSL check failed for {domain}:{port} - {e}")
            return None


# ============================================================
# EMAIL SENDER
# ============================================================

class EmailNotifier:

    def __init__(self):
        self.context = ssl.create_default_context()

    def send(self, to_email, subject, html_body, cc_email=None):
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = FROM_EMAIL
            msg["To"] = to_email

            if cc_email:
                msg["Cc"] = cc_email

            msg.attach(MIMEText(html_body, "html"))

            recipients = [to_email]
            if cc_email:
                recipients.append(cc_email)

            with smtplib.SMTP_SSL(
                SMTP_SERVER,
                SMTP_PORT,
                context=self.context,
                timeout=20
            ) as server:
                server.login(FROM_EMAIL, SMTP_PASSWORD)
                server.sendmail(FROM_EMAIL, recipients, msg.as_string())

            logger.info(f"Email sent to {to_email}")
            return True

        except Exception as e:
            logger.error(f"Email sending failed: {e}")
            return False


# ============================================================
# MAIN MONITOR
# ============================================================

class SSLMonitor:

    def __init__(self):
        self.excel = ExcelAPI(EXCEL_FILE_PATH, EXCEL_SHEET_NAME)
        self.checker = SSLChecker()
        self.mailer = EmailNotifier()

    def run_check(self):
        logger.info("Starting SSL certificate check")

        domains = self.excel.get_domains()

        for entry in domains:
            result = self.checker.check(entry["domain"], entry["port"])

            if not result:
                continue

            days = result["days_left"]

            if days <= 0:
                subject = "❌ SSL Certificate Expired - Immediate Action Required"
                body = f"""
                <h3>SSL Certificate Expired</h3>
                <p><b>Domain:</b> {result['domain']}</p>
                <p><b>Port:</b> {result['port']}</p>
                <p><b>Expired On:</b> {result['expiry']}</p>
                """
                self.mailer.send(EXPIRED_EMAIL, subject, body)

            elif days < 50:
                subject = f"⚠ SSL Expiry Alert - {days} Days Remaining"
                body = f"""
                <h3>SSL Certificate Expiry Warning</h3>
                <p><b>Domain:</b> {result['domain']}</p>
                <p><b>Port:</b> {result['port']}</p>
                <p><b>Expiry Date:</b> {result['expiry']}</p>
                <p><b>Days Remaining:</b> {days}</p>
                """
                self.mailer.send(ABOUT_TO_EXPIRE_EMAIL, subject, body, ABOUT_TO_EXPIRE_CC)

            else:
                logger.info(f"{result['domain']} OK ({days} days left)")

        logger.info("SSL check completed")

    def schedule(self, hour):
        schedule.every().day.at(f"{hour:02d}:00").do(self.run_check)
        logger.info(f"Scheduled daily at {hour:02d}:00")

        while True:
            schedule.run_pending()
            time.sleep(60)


# ============================================================
# ENTRY POINT
# ============================================================

def main():
    validate_config()

    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["once", "schedule"], default="once")
    parser.add_argument("--hour", type=int, default=SCHEDULE_HOUR)

    args = parser.parse_args()

    monitor = SSLMonitor()

    if args.mode == "once":
        monitor.run_check()
    else:
        monitor.schedule(args.hour)


if __name__ == "__main__":
    main()
