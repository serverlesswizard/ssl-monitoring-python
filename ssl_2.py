#!/usr/bin/env python3
"""
Production SSL Certificate Monitoring Script (Excel Version)
Zoho SMTP + Hardcoded Email Addresses + SSL Context Safe
Optimized for Cron Job Automation
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
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# IST timezone (UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))


# ============================================================
# CONFIGURATION - HARDCODED (NO ENVIRONMENT VARIABLES NEEDED)
# ============================================================

# SMTP Server Configuration - HARDCODED
SMTP_SERVER = "smtp.zoho.com"                            # Zoho SMTP server
SMTP_PORT = 465                                           # SSL port for Zoho
FROM_EMAIL = "vishal.anand@wyzmindz.com"                       # Your Zoho email address
SMTP_PASSWORD = "xxxxxx"                      # Your Zoho app password

# Email Recipients - HARDCODED
ABOUT_TO_EXPIRE_EMAIL = "itsupport@wyzmindz.com"           # Primary recipient for expiry warnings
ABOUT_TO_EXPIRE_CC = "nalien.a@wyzmindz.com, bhavith.km@wyzmindz.com"          # CC for expiry warnings
EXPIRED_EMAIL = "itsupport@wyzmindz.com"         # For expired certificates
EXPIRED_CC = "nalien.a@wyzmindz.com, bhavith.km@wyzmindz.com"

# Excel Configuration
EXCEL_FILE_PATH = "./domains.xlsx"
EXCEL_SHEET_NAME = "Sheet1"

# Scheduled Check Time
SCHEDULE_HOUR = 18  # Default 5 PM (18:00)

# Certificate Expiry Thresholds
EXPIRY_WARNING_DAYS = 7  # Alert when certificate expires within N days


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
    """Validate hardcoded configuration"""
    # Validate SMTP settings
    if FROM_EMAIL == "your-email@zoho.com":
        logger.error("❌ Configuration Error!")
        logger.error("   Please edit the script and set:")
        logger.error("   - FROM_EMAIL: Your actual Zoho email address")
        logger.error("   - SMTP_PASSWORD: Your Zoho app password")
        sys.exit(1)
    
    if not SMTP_PASSWORD or SMTP_PASSWORD == "your-app-password":
        logger.error("❌ Configuration Error!")
        logger.error("   SMTP_PASSWORD not set. Please edit the script.")
        sys.exit(1)
    
    # Validate hardcoded email addresses
    if not ABOUT_TO_EXPIRE_EMAIL or "@" not in ABOUT_TO_EXPIRE_EMAIL:
        logger.error(f"❌ Invalid ABOUT_TO_EXPIRE_EMAIL: {ABOUT_TO_EXPIRE_EMAIL}")
        sys.exit(1)
    
    if not EXPIRED_EMAIL or "@" not in EXPIRED_EMAIL:
        logger.error(f"❌ Invalid EXPIRED_EMAIL: {EXPIRED_EMAIL}")
        sys.exit(1)
    
    logger.info("✓ Configuration validated successfully")
    logger.info(f"  From: {FROM_EMAIL}")
    logger.info(f"  Warning Recipient: {ABOUT_TO_EXPIRE_EMAIL}")
    logger.info(f"  Critical Recipient: {EXPIRED_EMAIL}")


# ============================================================
# EXCEL READER
# ============================================================

class ExcelAPI:
    """Read domain list from Excel file"""

    def __init__(self, file_path, sheet_name):
        self.file_path = Path(file_path)
        self.sheet_name = sheet_name

    def get_domains(self):
        """
        Read domains and ports from Excel file
        
        Expected columns: Domain, Port (optional, defaults to 443)
        """
        if not self.file_path.exists():
            logger.error(f"Excel file not found: {self.file_path}")
            return []

        try:
            df = pd.read_excel(self.file_path, sheet_name=self.sheet_name)
        except Exception as e:
            logger.error(f"Failed to read Excel file: {e}")
            return []

        domains = []
        for idx, row in df.iterrows():
            domain = str(row.get("Domain", "")).strip()
            port = str(row.get("Port", "443")).strip()

            if domain and domain.lower() != "nan":
                domains.append({
                    "domain": domain,
                    "port": port if port else "443"
                })
            else:
                logger.warning(f"Row {idx + 2}: Skipping invalid domain")

        logger.info(f"Loaded {len(domains)} domain(s) from Excel")
        return domains


# ============================================================
# SSL CHECKER
# ============================================================

class SSLChecker:
    """Check SSL certificate expiry dates"""

    @staticmethod
    def check(domain, port):
        """
        Check SSL certificate expiry for a domain:port combination
        
        Returns:
            dict: Certificate info {domain, port, expiry, days_left}
            None: If check fails
        """
        try:
            # Use openssl to retrieve certificate expiry date
            cmd = (
                f"echo | openssl s_client -servername {domain} "
                f"-connect {domain}:{port} 2>/dev/null | "
                f"openssl x509 -noout -enddate"
            )
            
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                logger.warning(f"SSL check failed for {domain}:{port} (openssl error)")
                return None

            # Parse expiry date from openssl output
            import re
            match = re.search(r'notAfter=(.+)', result.stdout)
            
            if not match:
                logger.warning(f"Could not parse expiry date for {domain}:{port}")
                return None

            expiry_str = match.group(1).strip().replace(" GMT", "")
            expiry_date_utc = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y")
            
            # Convert UTC to IST (UTC+5:30)
            expiry_date_utc = expiry_date_utc.replace(tzinfo=timezone.utc)
            expiry_date_ist = expiry_date_utc.astimezone(IST)

            # Calculate days left from IST time
            now_ist = datetime.now(IST)
            days_left = (expiry_date_ist.replace(tzinfo=None) - now_ist.replace(tzinfo=None)).days

            return {
                "domain": domain,
                "port": port,
                "expiry": expiry_date_ist,
                "days_left": days_left
            }

        except subprocess.TimeoutExpired:
            logger.error(f"SSL check timeout for {domain}:{port}")
            return None
        except Exception as e:
            logger.error(f"SSL check failed for {domain}:{port} - {e}")
            return None


# ============================================================
# EMAIL SENDER
# ============================================================

class EmailNotifier:
    """Send email notifications using Zoho SMTP"""

    def __init__(self):
        """Initialize SSL context for secure connection"""
        self.context = ssl.create_default_context()

    def send(self, to_email, subject, html_body, cc_email=None):
        """
        Send HTML email notification
        
        Args:
            to_email: Primary recipient
            subject: Email subject line
            html_body: HTML formatted message body
            cc_email: Optional CC recipient
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = FROM_EMAIL
            msg["To"] = to_email

            if cc_email:
                msg["Cc"] = cc_email

            # Attach HTML body
            msg.attach(MIMEText(html_body, "html"))

            # Build recipient list
            recipients = [to_email]
            if cc_email:
                recipients.append(cc_email)

            # Send via Zoho SMTP with SSL
            with smtplib.SMTP_SSL(
                SMTP_SERVER,
                SMTP_PORT,
                context=self.context,
                timeout=20
            ) as server:
                server.login(FROM_EMAIL, SMTP_PASSWORD)
                server.sendmail(FROM_EMAIL, recipients, msg.as_string())

            logger.info(f"Email sent to {to_email}" + 
                       (f" (CC: {cc_email})" if cc_email else ""))
            return True

        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"❌ SMTP Authentication Failed!")
            logger.error(f"   Check your FROM_EMAIL and SMTP_PASSWORD in the script")
            logger.error(f"   Error: {e}")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
            return False
        except Exception as e:
            logger.error(f"Email sending failed: {e}")
            return False


# ============================================================
# MAIN MONITOR
# ============================================================

class SSLMonitor:
    """Main SSL certificate monitoring orchestrator"""

    def __init__(self):
        self.excel = ExcelAPI(EXCEL_FILE_PATH, EXCEL_SHEET_NAME)
        self.checker = SSLChecker()
        self.mailer = EmailNotifier()

    def run_check(self):
        """Run SSL certificate check for all domains"""
        logger.info("=" * 60)
        logger.info("Starting SSL certificate check")
        logger.info("=" * 60)

        domains = self.excel.get_domains()

        if not domains:
            logger.warning("No domains to check. Exiting.")
            return

        checked = 0
        expired = 0
        expiring_soon = 0
        ok = 0

        for entry in domains:
            result = self.checker.check(entry["domain"], entry["port"])

            if not result:
                logger.error(f"Skipping {entry['domain']}:{entry['port']} - check failed")
                continue

            checked += 1
            days = result["days_left"]

            if days <= 0:
                # Certificate is expired
                expired += 1
                subject = f"❌ SSL Certificate Expired - {result['domain']}"
                body = self._format_expired_email(result)
                self.mailer.send(EXPIRED_EMAIL, subject, body)
                logger.error(f"{result['domain']} EXPIRED (expired {abs(days)} days ago)")

            elif days < EXPIRY_WARNING_DAYS:
                # Certificate expiring soon
                expiring_soon += 1
                subject = f"⚠️  SSL Expiry Alert - {result['domain']} ({days} days)"
                body = self._format_warning_email(result)
                self.mailer.send(
                    ABOUT_TO_EXPIRE_EMAIL,
                    subject,
                    body,
                    ABOUT_TO_EXPIRE_CC
                )
                logger.warning(f"{result['domain']} expiring in {days} days")

            else:
                # Certificate is OK
                ok += 1
                logger.info(f"{result['domain']} OK ({days} days remaining)")

        logger.info("=" * 60)
        logger.info(f"SSL check completed - Checked: {checked}, Expired: {expired}, "
                   f"Expiring: {expiring_soon}, OK: {ok}")
        logger.info("=" * 60)

    def _format_warning_email(self, result):
        """Format expiry warning email body"""
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2 style="color: #ff9800;">⚠️ SSL Certificate Expiry Warning</h2>
            
            <p>An SSL certificate is expiring soon and requires attention.</p>
            
            <table style="border-collapse: collapse; width: 100%; max-width: 600px;">
                <tr style="background-color: #f5f5f5;">
                    <td style="padding: 10px; border: 1px solid #ddd; font-weight: bold;">Domain:</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{result['domain']}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #ddd; font-weight: bold;">Port:</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{result['port']}</td>
                </tr>
                <tr style="background-color: #f5f5f5;">
                    <td style="padding: 10px; border: 1px solid #ddd; font-weight: bold;">Expiry Date:</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{result['expiry'].strftime('%Y-%m-%d %H:%M:%S IST')}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #ddd; font-weight: bold;">Days Remaining:</td>
                    <td style="padding: 10px; border: 1px solid #ddd; color: #ff9800; font-weight: bold;">{result['days_left']} days</td>
                </tr>
            </table>
            
            <p style="margin-top: 20px; color: #d32f2f;"><strong>Action Required:</strong> 
            Please renew this SSL certificate before the expiry date.</p>
            
            <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
            <p style="font-size: 12px; color: #999;">
                This is an automated message from SSL Certificate Monitor.
                Sent at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
            </p>
        </body>
        </html>
        """

    def _format_expired_email(self, result):
        """Format expired certificate email body"""
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2 style="color: #d32f2f;">❌ SSL Certificate EXPIRED - Immediate Action Required</h2>
            
            <p style="color: #d32f2f; font-weight: bold;">
                A critical SSL certificate has expired. This requires immediate remediation.
            </p>
            
            <table style="border-collapse: collapse; width: 100%; max-width: 600px; border: 2px solid #d32f2f;">
                <tr style="background-color: #ffebee;">
                    <td style="padding: 10px; border: 1px solid #ddd; font-weight: bold;">Domain:</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{result['domain']}</td>
                </tr>
                <tr style="background-color: #ffebee;">
                    <td style="padding: 10px; border: 1px solid #ddd; font-weight: bold;">Port:</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{result['port']}</td>
                </tr>
                <tr style="background-color: #ffebee;">
                    <td style="padding: 10px; border: 1px solid #ddd; font-weight: bold;">Expired On:</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{result['expiry'].strftime('%Y-%m-%d %H:%M:%S IST')}</td>
                </tr>
                <tr style="background-color: #ffebee;">
                    <td style="padding: 10px; border: 1px solid #ddd; font-weight: bold;">Status:</td>
                    <td style="padding: 10px; border: 1px solid #ddd; color: #d32f2f; font-weight: bold;">
                        EXPIRED {abs(result['days_left'])} days ago
                    </td>
                </tr>
            </table>
            
            <p style="margin-top: 20px; color: #d32f2f; font-weight: bold;">
                URGENT: Renew this certificate immediately to restore service availability.
            </p>
            
            <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
            <p style="font-size: 12px; color: #999;">
                This is an automated message from SSL Certificate Monitor.
                Sent at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
            </p>
        </body>
        </html>
        """

    def schedule(self, hour):
        """Schedule daily check at specified hour"""
        schedule.every().day.at(f"{hour:02d}:00").do(self.run_check)
        logger.info(f"Scheduled daily check at {hour:02d}:00")

        while True:
            schedule.run_pending()
            time.sleep(60)


# ============================================================
# ENTRY POINT
# ============================================================

def main():
    """Main entry point"""
    # Validate configuration
    validate_config()

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="SSL Certificate Monitoring Script",
        epilog="Examples:\n"
               "  python ssl_monitor.py --mode once\n"
               "  python ssl_monitor.py --mode schedule --hour 18"
    )
    parser.add_argument(
        "--mode",
        choices=["once", "schedule"],
        default="once",
        help="Run mode: 'once' for single check, 'schedule' for daily scheduling"
    )
    parser.add_argument(
        "--hour",
        type=int,
        default=SCHEDULE_HOUR,
        help=f"Hour to schedule daily check (0-23, default: {SCHEDULE_HOUR})"
    )

    args = parser.parse_args()

    # Validate hour argument
    if not 0 <= args.hour <= 23:
        logger.error(f"Invalid hour: {args.hour}. Must be between 0 and 23.")
        sys.exit(1)

    # Initialize and run monitor
    monitor = SSLMonitor()

    if args.mode == "once":
        logger.info("Running SSL check once...")
        monitor.run_check()
    else:
        logger.info("Starting scheduled SSL checks...")
        monitor.schedule(args.hour)


if __name__ == "__main__":
    main()