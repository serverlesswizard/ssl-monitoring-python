#!/usr/bin/env python3
"""
Test script to validate SSL Monitoring (Excel Version) configuration
Checks all dependencies and settings before running the main system
"""

import subprocess
import sys
import os
import json
from pathlib import Path

class ConfigTester:
    """Tests SSL Monitoring configuration"""
    
    def __init__(self):
        self.issues = []
        self.warnings = []
        self.success_count = 0
    
    def test_python_version(self):
        """Check Python version"""
        print("Testing Python version...", end=" ")
        if sys.version_info >= (3, 8):
            print("✓")
            self.success_count += 1
        else:
            self.issues.append(f"Python 3.8+ required (you have {sys.version_info.major}.{sys.version_info.minor})")
            print("✗")
    
    def test_openssl(self):
        """Check OpenSSL installation"""
        print("Testing OpenSSL...", end=" ")
        try:
            result = subprocess.run(['openssl', 'version'], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✓ ({result.stdout.strip()})")
                self.success_count += 1
            else:
                self.issues.append("OpenSSL command failed")
                print("✗")
        except FileNotFoundError:
            self.issues.append("OpenSSL not found. Install with: sudo apt-get install openssl")
            print("✗")
    
    def test_python_packages(self):
        """Check required Python packages"""
        print("Testing Python packages...", end=" ")
        packages = ['pandas', 'openpyxl', 'schedule']
        missing = []
        for package in packages:
            try:
                __import__(package)
            except ImportError:
                missing.append(package)
        
        if not missing:
            print("✓")
            self.success_count += 1
        else:
            self.issues.append(f"Missing packages: {', '.join(missing)}. Run: pip install -r requirements_excel.txt")
            print("✗")
    
    def test_excel_file(self):
        """Check Excel file"""
        print("Testing Excel file...", end=" ")
        excel_path = os.getenv('EXCEL_FILE_PATH', './domains.xlsx')
        
        excel_file = Path(excel_path)
        if not excel_file.exists():
            self.issues.append(f"Excel file not found: {excel_path}")
            print("✗")
            return
        
        try:
            import pandas as pd
            df = pd.read_excel(excel_path, sheet_name=os.getenv('EXCEL_SHEET_NAME', 'Sheet1'))
            
            if df.empty:
                self.warnings.append(f"Excel file exists but is empty: {excel_path}")
                print("⚠")
            else:
                # Check for required columns
                columns = [col.strip() for col in df.columns]
                has_domain = any(col.lower() == 'domain' for col in columns)
                has_port = any(col.lower() == 'port' for col in columns)
                
                if has_domain and has_port:
                    print(f"✓ ({len(df)} domains)")
                    self.success_count += 1
                else:
                    missing_cols = []
                    if not has_domain:
                        missing_cols.append('Domain')
                    if not has_port:
                        missing_cols.append('Port')
                    self.issues.append(f"Missing columns in Excel: {', '.join(missing_cols)}")
                    print("✗")
        except Exception as e:
            self.issues.append(f"Error reading Excel file: {str(e)}")
            print("✗")
    
    def test_smtp_config(self):
        """Check SMTP configuration"""
        print("Testing SMTP configuration...", end=" ")
        smtp_server = os.getenv('SMTP_SERVER')
        from_email = os.getenv('FROM_EMAIL')
        smtp_password = os.getenv('SMTP_PASSWORD')
        
        missing = []
        if not smtp_server:
            missing.append('SMTP_SERVER')
        if not from_email:
            missing.append('FROM_EMAIL')
        if not smtp_password:
            missing.append('SMTP_PASSWORD')
        
        if missing:
            self.warnings.append(f"SMTP config incomplete: missing {', '.join(missing)}")
            print("⚠")
        else:
            print("✓")
            self.success_count += 1
    
    def test_smtp_connection(self):
        """Test SMTP connection"""
        print("Testing SMTP connection...", end=" ")
        smtp_server = os.getenv('SMTP_SERVER')
        smtp_port = int(os.getenv('SMTP_PORT', '587'))
        from_email = os.getenv('FROM_EMAIL')
        smtp_password = os.getenv('SMTP_PASSWORD')
        
        if not all([smtp_server, from_email, smtp_password]):
            print("⊘ (skipped - no config)")
            return
        
        try:
            import smtplib
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=5)
            server.starttls()
            server.login(from_email, smtp_password)
            server.quit()
            print("✓")
            self.success_count += 1
        except smtplib.SMTPAuthenticationError:
            self.issues.append(f"SMTP authentication failed. Check email/password.")
            print("✗")
        except smtplib.SMTPException as e:
            self.warnings.append(f"SMTP connection warning: {str(e)}")
            print("⚠")
        except Exception as e:
            self.warnings.append(f"SMTP test failed: {str(e)}")
            print("⚠")
    
    def test_dns_resolution(self):
        """Test basic DNS resolution"""
        print("Testing DNS resolution...", end=" ")
        try:
            import socket
            socket.gethostbyname('google.com')
            print("✓")
            self.success_count += 1
        except socket.gaierror:
            self.issues.append("DNS resolution failed. Check internet connection.")
            print("✗")
    
    def test_ssl_check(self):
        """Test SSL certificate check functionality"""
        print("Testing SSL certificate check...", end=" ")
        try:
            cmd = "echo | openssl s_client -servername google.com -connect google.com:443 2>/dev/null | openssl x509 -noout -enddate"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0 and 'notAfter' in result.stdout:
                print("✓")
                self.success_count += 1
            else:
                self.issues.append("SSL certificate check failed")
                print("✗")
        except Exception as e:
            self.issues.append(f"SSL check error: {str(e)}")
            print("✗")
    
    def test_alert_recipients(self):
        """Check alert recipient configuration"""
        print("Testing alert recipients...", end=" ")
        about_to_expire = os.getenv('ABOUT_TO_EXPIRE_EMAIL')
        expired = os.getenv('EXPIRED_EMAIL')
        
        if not about_to_expire or not expired:
            self.warnings.append("Alert recipients not fully configured")
            print("⚠")
        else:
            print("✓")
            self.success_count += 1
    
    def run_all_tests(self):
        """Run all tests"""
        print("\n" + "=" * 60)
        print("SSL MONITORING (EXCEL) CONFIGURATION TESTS")
        print("=" * 60 + "\n")
        
        self.test_python_version()
        self.test_openssl()
        self.test_python_packages()
        self.test_excel_file()
        self.test_dns_resolution()
        self.test_ssl_check()
        self.test_smtp_config()
        self.test_smtp_connection()
        self.test_alert_recipients()
        
        print("\n" + "=" * 60)
        print(f"Results: {self.success_count} passed", end="")
        if self.warnings:
            print(f", {len(self.warnings)} warnings", end="")
        if self.issues:
            print(f", {len(self.issues)} issues", end="")
        print("\n" + "=" * 60 + "\n")
        
        if self.warnings:
            print("⚠ WARNINGS:")
            for warning in self.warnings:
                print(f"  - {warning}")
            print()
        
        if self.issues:
            print("✗ ISSUES TO FIX:")
            for issue in self.issues:
                print(f"  - {issue}")
            print()
            return False
        else:
            print("✓ All checks passed! Ready to deploy.\n")
            return True

if __name__ == '__main__':
    tester = ConfigTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)
