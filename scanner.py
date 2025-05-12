import requests
from bs4 import BeautifulSoup
import nmap
import socket
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
import subprocess
import os

# Constants
REPORT_FILE = "vulnerability_report.pdf"
SCREENSHOT_FILE = "screenshot.png"

def scan_website(url):
    """Main scanning function with comprehensive checks"""
    print(f"\n🔍 Scanning {url}...")
    
    # Initialize report data
    findings = {
        'target': url,
        'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'open_ports': [],
        'vulnerabilities': [],
        'screenshot': False
    }

    # Run security checks
    findings.update(scan_ports(url))
    findings.update(check_xss(url))
    findings.update(check_sql_injection(url))
    findings.update(check_directory_listing(url))
    
    # Take screenshot (if GUI available)
    if take_screenshot(url):
        findings['screenshot'] = True
    
    # Generate professional report
    generate_report(findings)
    
    print(f"\n✅ Scan completed! Report saved to {REPORT_FILE}")

def scan_ports(target):
    """Comprehensive port scanning with service detection"""
    try:
        host = socket.gethostbyname(target.split('//')[1].split('/')[0])
        scanner = nmap.PortScanner()
        
        # Scan common web ports with service detection
        scanner.scan(hosts=host, arguments='-p 21,22,80,443,8080,8443 -sV -T4')
        
        open_ports = []
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                service = scanner[host][proto][port]
                open_ports.append({
                    'port': port,
                    'state': service['state'],
                    'service': service['name'],
                    'version': service.get('version', 'unknown')
                })
        
        return {'open_ports': open_ports}
    except Exception as e:
        print(f"⚠️ Port scan failed: {e}")
        return {'open_ports': []}

def check_xss(url):
    """Advanced XSS detection with multiple payloads"""
    payloads = [
        "<script>alert('XSS1')</script>",
        "<img src=x onerror=alert('XSS2')>",
        "'\"><svg/onload=alert('XSS3')>"
    ]
    
    vulnerabilities = []
    for payload in payloads:
        try:
            test_url = f"{url}?q={payload}" if '?' not in url else f"{url}&q={payload}"
            response = requests.get(test_url, timeout=10)
            
            if payload in response.text:
                vulnerabilities.append({
                    'type': 'XSS',
                    'severity': 'High',
                    'payload': payload,
                    'location': 'URL parameter'
                })
        except:
            continue
    
    return {'vulnerabilities': vulnerabilities}

def check_sql_injection(url):
    """Basic SQL injection detection"""
    payloads = [
        "' OR '1'='1",
        "' OR 1=1 --",
        "admin' --"
    ]
    
    vulnerabilities = []
    for payload in payloads:
        try:
            test_url = f"{url}?id={payload}" if '?' not in url else f"{url}&id={payload}"
            response = requests.get(test_url, timeout=10)
            
            if "error in your SQL syntax" in response.text.lower():
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'severity': 'Critical',
                    'payload': payload,
                    'location': 'URL parameter'
                })
        except:
            continue
    
    return {'vulnerabilities': vulnerabilities}

def check_directory_listing(url):
    """Check for directory listing vulnerabilities"""
    directories = [
        "images/",
        "uploads/",
        "admin/",
        "backup/"
    ]
    
    vulnerabilities = []
    for directory in directories:
        try:
            response = requests.get(f"{url}/{directory}", timeout=10)
            if "Index of /" in response.text:
                vulnerabilities.append({
                    'type': 'Directory Listing',
                    'severity': 'Medium',
                    'exposed_directory': directory
                })
        except:
            continue
    
    return {'vulnerabilities': vulnerabilities}

def take_screenshot(url):
    """Capture website screenshot using wkhtmltopdf"""
    try:
        if not os.path.exists('screenshots'):
            os.makedirs('screenshots')
        
        output_file = f"screenshots/{url.split('//')[1].replace('/', '_')}.png"
        subprocess.run([
            'wkhtmltoimage',
            '--quality', '50',
            '--disable-javascript',
            url,
            output_file
        ], check=True)
        return output_file
    except:
        return None

def generate_report(data):
    """Generate professional PDF report"""
    doc = SimpleDocTemplate(REPORT_FILE, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    story.append(Paragraph(f"<b>Vulnerability Assessment Report</b>", styles['Title']))
    story.append(Spacer(1, 12))
    
    # Metadata
    story.append(Paragraph(f"<b>Target URL:</b> {data['target']}", styles['Normal']))
    story.append(Paragraph(f"<b>Scan Date:</b> {data['date']}", styles['Normal']))
    story.append(Spacer(1, 24))
    
    # Open Ports
    story.append(Paragraph("<b>Open Ports:</b>", styles['Heading2']))
    for port in data['open_ports']:
        story.append(Paragraph(
            f"Port {port['port']} ({port['service']} {port['version']}): {port['state']}", 
            styles['Normal']
        ))
    story.append(Spacer(1, 12))
    
    # Vulnerabilities
    story.append(Paragraph("<b>Vulnerabilities Found:</b>", styles['Heading2']))
    if not data['vulnerabilities']:
        story.append(Paragraph("No critical vulnerabilities detected", styles['Normal']))
    else:
        for vuln in data['vulnerabilities']:
            story.append(Paragraph(
                f"<font color='red'><b>{vuln['type']}</b></font> ({vuln['severity']}): "
                f"Detected at {vuln.get('location', 'unknown')}",
                styles['Normal']
            ))
            if 'payload' in vuln:
                story.append(Paragraph(f"Payload: {vuln['payload']}", styles['Code']))
    story.append(Spacer(1, 24))
    
    # Screenshot
    if data.get('screenshot'):
        try:
            img = Image(data['screenshot'], width=400, height=300)
            story.append(Paragraph("<b>Screenshot:</b>", styles['Heading2']))
            story.append(img)
        except:
            pass
    
    doc.build(story)

if __name__ == "__main__":
    target = input("Enter target URL (e.g., http://testphp.vulnweb.com): ")
    scan_website(target)
