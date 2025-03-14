#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced YouTube Security Scanner with Advanced Vulnerability Detection (Modular Version)

DISCLAIMER: Alat ini dirancang untuk pengujian keamanan pada lingkungan yang telah diotorisasi.
Penggunaan pada situs tanpa izin merupakan pelanggaran hukum.
"""

import os
import time
import smtplib
import hashlib
import logging
import sqlite3
import threading
import json
import requests
import schedule
import re
from email.mime.text import MIMEText
from datetime import datetime
from urllib.parse import urljoin, urlparse

# Selenium dan Flask imports
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
from flask import Flask, render_template_string

# ===============================
# Konfigurasi Logging
# ===============================
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# ===============================
# Konfigurasi Umum (Sebaiknya simpan di file konfigurasi terpisah)
# ===============================
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'm.argareksapati21@gmail.com',
    'sender_password': 'argareksapati21',  # Gunakan App Password
    'recipient_email': 'm.areksa21@gmail.com'
}

YOUTUBE_CONFIG = {
    'base_url': 'https://www.youtube.com',
    'contact_form': 'https://support.google.com/youtube/contact/ytm_form',
    'security_report_endpoint': 'https://support.google.com/youtube/contact/security',
    'api_endpoint': 'https://www.googleapis.com/youtube/v3/'
}

REPORTED_BUGS_FILE = "reported_bugs.txt"
DB_FILE = "bug_history.db"

# ========================================
# Utilitas Penyimpanan & Database
# ========================================
class StorageUtil:
    @staticmethod
    def load_reported_bugs(filename: str = REPORTED_BUGS_FILE) -> set:
        if os.path.exists(filename):
            with open(filename, "r", encoding="utf-8") as f:
                lines = f.read().splitlines()
            return set(lines)
        return set()

    @staticmethod
    def save_reported_bugs(bug_hashes: set, filename: str = REPORTED_BUGS_FILE) -> None:
        with open(filename, "w", encoding="utf-8") as f:
            for h in bug_hashes:
                f.write(h + "\n")

    @staticmethod
    def hash_report(report: str) -> str:
        return hashlib.md5(report.encode("utf-8")).hexdigest()

    @staticmethod
    def setup_db() -> None:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS bug_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bug_hash TEXT UNIQUE,
                    report TEXT,
                    timestamp TEXT
                )
            ''')
            conn.commit()

    @staticmethod
    def store_bug_report_in_db(report: str, bug_hash: str) -> None:
        timestamp = datetime.utcnow().isoformat()
        try:
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO bug_history (bug_hash, report, timestamp)
                    VALUES (?, ?, ?)
                ''', (bug_hash, report, timestamp))
                conn.commit()
        except sqlite3.IntegrityError:
            logging.info("Bug report sudah tersimpan di database.")

    @staticmethod
    def load_reported_bugs_from_db() -> set:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT bug_hash FROM bug_history')
            rows = cursor.fetchall()
        return set(row[0] for row in rows)


# ========================================
# Notifikasi Email
# ========================================
class EmailNotifier:
    @staticmethod
    def send_notification(subject: str, body: str) -> bool:
        try:
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = EMAIL_CONFIG['sender_email']
            msg['To'] = EMAIL_CONFIG['recipient_email']

            with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
                server.starttls()
                server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
                server.send_message(msg)

            logging.info("Email notifikasi berhasil dikirim")
            return True
        except Exception as e:
            logging.error(f"Gagal mengirim email: {e}")
            return False


# ========================================
# Modul Pemindaian Keamanan
# ========================================
class SecurityScanner:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.results = {}

    def init_driver(self) -> webdriver.Chrome:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--enable-logging")
        chrome_options.add_argument("--v=1")
        # Untuk mengaktifkan logging performa (opsional)
        chrome_options.add_experimental_option('perfLoggingPrefs', {
            'enableNetwork': True,
            'enablePage': True
        })
        chrome_options.set_capability('goog:loggingPrefs', {'browser': 'ALL', 'performance': 'ALL'})
        return webdriver.Chrome(options=chrome_options)

    def perform_scan(self) -> dict:
        driver = self.init_driver()
        try:
            driver.get(self.base_url)
            time.sleep(3)
            # Interaksi dinamis: Scroll halaman
            ActionChains(driver).send_keys(Keys.END).perform()
            time.sleep(1)
            ActionChains(driver).send_keys(Keys.HOME).perform()
            time.sleep(1)

            basic_results = self.basic_scan(driver)
            security_results = self.advanced_security_scan(driver)
            self.results = {'basic': basic_results, 'security': security_results}
            return self.results
        finally:
            driver.quit()

    def basic_scan(self, driver: webdriver.Chrome) -> dict:
        """Pemindaian dasar (broken links, JS errors, performa, dll.)"""
        results = {
            'broken_links': self.check_broken_links(driver),
            'js_errors': self.get_console_errors(driver),
            'api_errors': self.analyze_network_requests(driver),
            'performance_issues': self.analyze_performance(driver),
            'layout_issues': self.check_layout_issues(driver),
            'accessibility_issues': self.run_accessibility_checks(driver),
            'user_agent': driver.execute_script("return navigator.userAgent"),
            'platform': driver.execute_script("return navigator.platform")
        }
        return results

    def advanced_security_scan(self, driver: webdriver.Chrome) -> dict:
        """Pemindaian keamanan tingkat lanjut"""
        results = {
            'xss_vulnerabilities': self.check_xss_vulnerabilities(driver),
            'csrf_vulnerabilities': self.check_csrf_vulnerabilities(driver),
            'missing_security_headers': self.check_security_headers(driver),
            'sensitive_data_exposure': self.check_sensitive_data(driver),
            'cors_misconfiguration': self.check_cors_misconfig(driver),
            'authentication_flaws': self.check_auth_flaws(driver)
        }
        return results

    # ---------- Basic Scanning Methods ----------
    def check_broken_links(self, driver: webdriver.Chrome) -> list:
        links = driver.find_elements(By.TAG_NAME, "a")
        broken = []
        for link in links:
            url = link.get_attribute("href")
            if url:
                try:
                    response = requests.head(url, timeout=5)
                    if response.status_code >= 400:
                        broken.append(url)
                except Exception as e:
                    logging.error(f"Error checking link {url}: {e}")
                    broken.append(url)
        return broken

    def get_console_errors(self, driver: webdriver.Chrome) -> list:
        errors = []
        try:
            logs = driver.get_log('browser')
            for log in logs:
                if log.get('level') == 'SEVERE':
                    errors.append(log.get('message'))
        except Exception as e:
            logging.error(f"Error getting console logs: {e}")
        return errors

    def analyze_network_requests(self, driver: webdriver.Chrome) -> list:
        api_errors = []
        try:
            logs = driver.get_log('performance')
            for log_entry in logs:
                message = json.loads(log_entry['message'])['message']
                if 'Network.response' in message.get('method', ''):
                    response = message.get('params', {}).get('response', {})
                    if response.get('status', 200) >= 400:
                        url = response.get('url', 'N/A')
                        status = response.get('status')
                        api_errors.append(f"{url} - Status: {status}")
        except Exception as e:
            logging.error(f"Error dalam analisis network: {e}")
        return api_errors

    def analyze_performance(self, driver: webdriver.Chrome) -> list:
        try:
            metrics = driver.execute_script("return window.performance.getEntriesByType('navigation')[0];")
            issues = []
            if metrics.get('domInteractive', 0) > 3000:
                issues.append(f"DOM Interactive terlalu lama: {metrics['domInteractive']}ms")
            if metrics.get('loadEventEnd', 0) > 5000:
                issues.append(f"Waktu load terlalu lama: {metrics['loadEventEnd']}ms")
            return issues
        except Exception as e:
            logging.error(f"Error analisis performa: {e}")
            return []

    def check_layout_issues(self, driver: webdriver.Chrome) -> list:
        try:
            issues = driver.execute_script("""
                const issues = [];
                document.querySelectorAll('img').forEach(img => {
                    if (!img.complete || img.naturalWidth === 0) {
                        issues.push(`Gambar rusak: ${img.src}`);
                    }
                    if (!img.alt) {
                        issues.push(`Gambar tanpa alt text: ${img.src}`);
                    }
                });
                document.querySelectorAll('*').forEach(el => {
                    const style = window.getComputedStyle(el);
                    if (el.scrollWidth > el.clientWidth || el.scrollHeight > el.clientHeight) {
                        issues.push(`Konten terpotong: ${el.tagName} - ${el.innerText.slice(0,30)}`);
                    }
                });
                return issues;
            """)
            return issues
        except Exception as e:
            logging.error(f"Error dalam pengecekan layout: {e}")
            return []

    def run_accessibility_checks(self, driver: webdriver.Chrome) -> list:
        try:
            if not os.path.exists('axe.min.js'):
                logging.error("File axe.min.js tidak ditemukan.")
                return []
            with open('axe.min.js', 'r') as f:
                axe_script = f.read()
            driver.execute_script(axe_script)
            results = driver.execute_async_script("""
                var callback = arguments[arguments.length - 1];
                axe.run().then(results => callback(results));
            """)
            violations = results.get('violations', [])
            return [f"{item['id']}: {item['help']}" for item in violations]
        except Exception as e:
            logging.error(f"Error dalam pemeriksaan aksesibilitas: {e}")
            return []

    # ---------- Advanced Security Scanning Methods ----------
    def check_xss_vulnerabilities(self, driver: webdriver.Chrome) -> list:
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)'
        ]
        vulnerabilities = []
        try:
            fields = driver.find_elements(By.TAG_NAME, 'input') + driver.find_elements(By.TAG_NAME, 'textarea')
            for field in fields:
                original_value = field.get_attribute('value') or ""
                for payload in xss_payloads:
                    field.clear()
                    field.send_keys(payload + Keys.RETURN)
                    time.sleep(1)
                    try:
                        alert = driver.switch_to.alert
                        if 'XSS' in alert.text or '1' in alert.text:
                            vulnerabilities.append(f"XSS terdeteksi di field {field.get_attribute('id')} dengan payload: {payload}")
                        alert.dismiss()
                    except Exception:
                        pass
                    if payload in driver.page_source:
                        vulnerabilities.append(f"Input tidak difilter di field {field.get_attribute('id')} - payload: {payload}")
                    field.clear()
                    field.send_keys(original_value)
            # Uji parameter URL
            current_url = driver.current_url
            for payload in xss_payloads:
                test_url = f"{current_url}?q={payload}"
                driver.get(test_url)
                time.sleep(2)
                if payload in driver.page_source:
                    vulnerabilities.append(f"Reflected XSS terdeteksi di parameter URL dengan payload: {payload}")
            return list(set(vulnerabilities))
        except Exception as e:
            logging.error(f"XSS check error: {e}")
            return []

    def check_csrf_vulnerabilities(self, driver: webdriver.Chrome) -> list:
        vulnerabilities = []
        try:
            forms = driver.find_elements(By.TAG_NAME, 'form')
            for form in forms:
                anti_csrf = False
                for inp in form.find_elements(By.TAG_NAME, 'input'):
                    name = (inp.get_attribute('name') or "").lower()
                    if 'csrf' in name or 'token' in name:
                        anti_csrf = True
                        break
                if not anti_csrf:
                    action = form.get_attribute('action') or ''
                    action = urljoin(driver.current_url, action)
                    vulnerabilities.append(f"Form tanpa CSRF token: {action}")
            return vulnerabilities
        except Exception as e:
            logging.error(f"CSRF check error: {e}")
            return []

    def check_security_headers(self, driver: webdriver.Chrome) -> list:
        missing_headers = []
        try:
            url = driver.current_url
            response = requests.head(url, timeout=5)
            headers = response.headers
            security_headers = {
                'Content-Security-Policy': "Mencegah XSS dan injection attacks",
                'X-Frame-Options': "Mencegah clickjacking",
                'X-Content-Type-Options': "Mencegah MIME sniffing",
                'Strict-Transport-Security': "Enforce HTTPS",
                'Referrer-Policy': "Kontrol referrer information"
            }
            for header, desc in security_headers.items():
                if header not in headers:
                    missing_headers.append(f"{header} ({desc})")
            return missing_headers
        except Exception as e:
            logging.error(f"Security header check error: {e}")
            return []

    def check_sensitive_data(self, driver: webdriver.Chrome) -> list:
        sensitive_patterns = {
            'api_key': r'AIza[0-9A-Za-z-_]{35}',
            'oauth_token': r'ya29\.[0-9A-Za-z\-_]+',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'jwt': r'eyJhbGciOiJ[^\s"]+'
        }
        found_data = []
        try:
            scripts = driver.find_elements(By.TAG_NAME, 'script')
            for script in scripts:
                content = script.get_attribute('innerHTML')
                for data_type, pattern in sensitive_patterns.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        found_data.append(f"{data_type} terdeteksi: {matches[0][:10]}... (dari {len(scripts)} scripts)")
            return list(set(found_data))
        except Exception as e:
            logging.error(f"Sensitive data check error: {e}")
            return []

    def check_cors_misconfig(self, driver: webdriver.Chrome) -> list:
        vulnerabilities = []
        try:
            cors_test_origin = "https://malicious.example.com"
            test_url = driver.current_url
            headers = {'Origin': cors_test_origin}
            response = requests.get(test_url, headers=headers)
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            if cors_test_origin in acao and acac.lower() == 'true':
                vulnerabilities.append("CORS misconfiguration: Mengizinkan origin arbitrer dengan kredensial")
            return vulnerabilities
        except Exception as e:
            logging.error(f"CORS check error: {e}")
            return []

    def check_auth_flaws(self, driver: webdriver.Chrome) -> list:
        flaws = []
        try:
            login_forms = driver.find_elements(By.CSS_SELECTOR, 'form[action*="login"]')
            for form in login_forms:
                password_fields = form.find_elements(By.CSS_SELECTOR, 'input[type="password"]')
                for field in password_fields:
                    autocomplete = field.get_attribute('autocomplete') or ''
                    if 'current-password' not in autocomplete:
                        flaws.append("Password field tanpa autocomplete='current-password'")
                action = form.get_attribute('action') or ''
                if action.startswith('http://'):
                    flaws.append("Login form menggunakan HTTP, bukan HTTPS")
            cookies = driver.get_cookies()
            for cookie in cookies:
                if cookie.get('secure') != True and urlparse(driver.current_url).scheme == 'https':
                    flaws.append(f"Cookie {cookie['name']} tanpa flag Secure")
                if cookie.get('httpOnly') != True:
                    flaws.append(f"Cookie {cookie['name']} tanpa flag HttpOnly")
            return flaws
        except Exception as e:
            logging.error(f"Auth check error: {e}")
            return []

# ========================================
# Reporting dan Dashboard
# ========================================
class Reporter:
    @staticmethod
    def format_bug_report(bug_details: dict) -> str:
        report = f"""
**Bug Report**
- Waktu Deteksi: {datetime.now().isoformat()}
- URL: {bug_details.get('basic', {}).get('url', 'N/A')}

**Detail Bug (Basic):**
- Broken Links: {len(bug_details.get('basic', {}).get('broken_links', []))} ditemukan
- JavaScript Errors: {len(bug_details.get('basic', {}).get('js_errors', []))} error
- API Errors: {len(bug_details.get('basic', {}).get('api_errors', []))} error
- Layout Issues: {len(bug_details.get('basic', {}).get('layout_issues', []))} masalah
- Accessibility Issues: {len(bug_details.get('basic', {}).get('accessibility_issues', []))} pelanggaran

**Detail Keamanan:**
- XSS Vulnerabilities: {len(bug_details.get('security', {}).get('xss_vulnerabilities', []))} ditemukan
- CSRF Vulnerabilities: {len(bug_details.get('security', {}).get('csrf_vulnerabilities', []))} ditemukan
- Missing Security Headers: {len(bug_details.get('security', {}).get('missing_security_headers', []))} belum diterapkan
- Sensitive Data Exposure: {len(bug_details.get('security', {}).get('sensitive_data_exposure', []))} terdeteksi
- CORS Misconfiguration: {len(bug_details.get('security', {}).get('cors_misconfiguration', []))} ditemukan
- Authentication Flaws: {len(bug_details.get('security', {}).get('authentication_flaws', []))} ditemukan

**Lingkungan:**
- User Agent: {bug_details.get('basic', {}).get('user_agent', 'N/A')}
- Platform: {bug_details.get('basic', {}).get('platform', 'N/A')}

**Logs Detail:**
{json.dumps(bug_details, indent=2)}
"""
        return report

    @staticmethod
    def generate_exploit_poc(bug_details: dict) -> str:
        poc_lines = []
        if bug_details.get('security', {}).get('xss_vulnerabilities'):
            poc_lines.append("XSS Exploit:")
            poc_lines.append("1. Masukkan payload berikut di kolom pencarian:")
            poc_lines.append('<script>alert(document.cookie)</script>')
            poc_lines.append("2. Verifikasi apakah alert muncul.")
        if bug_details.get('security', {}).get('csrf_vulnerabilities'):
            poc_lines.append("\nCSRF Exploit:")
            poc_lines.append("1. Buat halaman HTML dengan form:")
            poc_lines.append('<form action="YOUTUBE_ENDPOINT" method="POST">')
            poc_lines.append('<input type="hidden" name="action" value="delete">')
            poc_lines.append('</form>')
            poc_lines.append("2. Bujuk korban untuk membuka halaman tersebut.")
        return "\n".join(poc_lines)

    @staticmethod
    def critical_vulnerability_check(bug_details: dict) -> list:
        critical = []
        sec = bug_details.get('security', {})
        if sec.get('xss_vulnerabilities'):
            critical.append("Critical XSS Vulnerability Detected")
        if sec.get('sensitive_data_exposure'):
            critical.append("Sensitive Data Exposure Detected")
        if sec.get('cors_misconfiguration'):
            critical.append("Dangerous CORS Configuration Detected")
        return critical

# Dashboard dengan Flask
def create_dashboard_app() -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def index():
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT bug_hash, report, timestamp FROM bug_history ORDER BY id DESC")
            rows = cursor.fetchall()
        template = """
        <html>
        <head>
            <title>Bug History Dashboard</title>
            <style>
                table, th, td { border: 1px solid black; border-collapse: collapse; padding: 8px; }
            </style>
        </head>
        <body>
            <h1>Bug History Dashboard</h1>
            <table>
                <tr>
                    <th>Timestamp</th>
                    <th>Bug Hash</th>
                    <th>Report</th>
                </tr>
                {% for bug in bugs %}
                <tr>
                    <td>{{ bug[2] }}</td>
                    <td>{{ bug[0] }}</td>
                    <td><pre>{{ bug[1] }}</pre></td>
                </tr>
                {% endfor %}
            </table>
        </body>
        </html>
        """
        return render_template_string(template, bugs=rows)

    return app

def run_dashboard() -> None:
    app = create_dashboard_app()
    logging.info("Dashboard berjalan di http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000)

# ========================================
# Scheduler & Main Entry Point
# ========================================
def main():
    try:
        StorageUtil.setup_db()
        # Jalankan dashboard di thread terpisah
        dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
        dashboard_thread.start()

        scanner = SecurityScanner(YOUTUBE_CONFIG['base_url'])
        results = scanner.perform_scan()

        # Buat laporan dan periksa kerentanan kritis
        report = Reporter.format_bug_report(results)
        critical = Reporter.critical_vulnerability_check(results)
        if critical:
            poc = Reporter.generate_exploit_poc(results)
            EmailNotifier.send_notification("CRITICAL VULNERABILITIES FOUND", 
                                            f"Issues:\n{chr(10).join(critical)}\n\nPoC:\n{poc}")
        else:
            EmailNotifier.send_notification("Bug Detection Report", report)

        # Simpan laporan ke database dan file
        bug_hash = StorageUtil.hash_report(report)
        reported_bug_hashes = StorageUtil.load_reported_bugs().union(StorageUtil.load_reported_bugs_from_db())
        if bug_hash not in reported_bug_hashes:
            StorageUtil.store_bug_report_in_db(report, bug_hash)
            reported_bug_hashes.add(bug_hash)
            StorageUtil.save_reported_bugs(reported_bug_hashes)

        # Scheduler untuk pemindaian berkala setiap 5 menit
        schedule.every(5).minutes.do(lambda: scanner.perform_scan())
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Aplikasi dihentikan oleh pengguna")
    except Exception as e:
        logging.error(f"Error utama: {e}")
        EmailNotifier.send_notification("Critical System Error", f"Aplikasi mengalami error: {str(e)}")

if __name__ == "__main__":
    main()