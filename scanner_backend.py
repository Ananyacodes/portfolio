from datetime import datetime, timezone
import json
import os
import platform
import re
import smtplib
import socket
import ssl
import subprocess
from email.message import EmailMessage
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlparse

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS


BASE_DIR = Path(__file__).resolve().parent


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return

    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key == "SMTP_PASSWORD":
                value = "".join(value.split())
            elif key == "SMTP_USERNAME":
                value = value.strip()
            if key:
                os.environ[key] = value


load_dotenv(BASE_DIR / ".env")
app = Flask(__name__)
CORS(app)

THM_PROFILE_URL = "https://tryhackme.com/p/ananyakar2007"
SITE_GITHUB_URL = os.getenv("SITE_GITHUB_URL", "https://github.com/Ananyacodes")
SITE_LINKEDIN_URL = os.getenv("SITE_LINKEDIN_URL", "https://www.linkedin.com/in/ananya-kar-6378291b4/")
THM_PUBLIC_PROFILE_API = "https://tryhackme.com/api/v2/public-profile?username={username}"

RATE_LIMIT_WINDOW = 60 * 15
RATE_LIMIT_MAX = 6
RATE_LIMIT_MEMORY: dict[str, list[float]] = {}


def is_rate_limited(ip: str) -> bool:
    now = datetime.now(timezone.utc).timestamp()
    history = RATE_LIMIT_MEMORY.setdefault(ip, [])
    history[:] = [ts for ts in history if now - ts < RATE_LIMIT_WINDOW]
    if len(history) >= RATE_LIMIT_MAX:
        return True
    history.append(now)
    return False
RESUME_THM_STATS = {
    "rank": "194,052",
    "rooms": "86",
    "badges": "10",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def fetch_json(url: str, timeout: int = 20) -> dict:
    request_obj = Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
    with urlopen(request_obj, timeout=timeout) as response:
        payload = response.read().decode("utf-8", "ignore")
    return json.loads(payload)


def run_ping(target: str) -> dict:
    ping_count_arg = "-n" if platform.system().lower() == "windows" else "-c"
    ping_command = ["ping", ping_count_arg, "3", target]

    try:
        ping = subprocess.run(
            ping_command,
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = ping.stdout if ping.returncode == 0 else ping.stderr
        packets_received = 0
        packets_transmitted = 0
        loss_percent = 100
        avg_ms = None

        sent_match = re.search(r"Sent = (\d+), Received = (\d+), Lost = (\d+)", output, re.I)
        if sent_match:
            packets_transmitted = int(sent_match.group(1))
            packets_received = int(sent_match.group(2))
            lost = int(sent_match.group(3))
            if packets_transmitted:
                loss_percent = round((lost / packets_transmitted) * 100)
        else:
            unix_match = re.search(r"(\d+) packets transmitted, (\d+) received", output, re.I)
            if unix_match:
                packets_transmitted = int(unix_match.group(1))
                packets_received = int(unix_match.group(2))
                if packets_transmitted:
                    loss_percent = round(((packets_transmitted - packets_received) / packets_transmitted) * 100)

        avg_match = re.search(r"min/avg/max(?:/\w+)? = [\d.]+/([\d.]+)/", output)
        if avg_match:
            avg_ms = float(avg_match.group(1))

        return {
            "reachable": packets_received > 0,
            "transmitted": packets_transmitted,
            "received": packets_received,
            "loss_percent": loss_percent,
            "avg_ms": avg_ms,
            "raw": output,
        }
    except Exception as exc:
        return {
            "reachable": False,
            "transmitted": 0,
            "received": 0,
            "loss_percent": 100,
            "avg_ms": None,
            "raw": f"Ping error: {exc}",
        }


# Service Risk Mapping - Common ports with threat levels and vulnerabilities
SERVICE_INTELLIGENCE = {
    21: {"name": "FTP", "risk": "high", "protocol": "tcp", "category": "file-transfer", "cves": ["CVE-2015-1193", "CVE-2019-15846"]},
    22: {"name": "SSH", "risk": "low", "protocol": "tcp", "category": "remote-access", "cves": []},
    23: {"name": "Telnet", "risk": "critical", "protocol": "tcp", "category": "remote-access", "cves": ["CVE-1999-0514", "CVE-2011-4862"]},
    25: {"name": "SMTP", "risk": "medium", "protocol": "tcp", "category": "mail", "cves": ["CVE-2016-10521"]},
    53: {"name": "DNS", "risk": "low", "protocol": "tcp/udp", "category": "infrastructure", "cves": []},
    80: {"name": "HTTP", "risk": "medium", "protocol": "tcp", "category": "web", "cves": []},
    110: {"name": "POP3", "risk": "high", "protocol": "tcp", "category": "mail", "cves": ["CVE-2011-4862"]},
    143: {"name": "IMAP", "risk": "high", "protocol": "tcp", "category": "mail", "cves": ["CVE-2016-2124"]},
    443: {"name": "HTTPS", "risk": "low", "protocol": "tcp", "category": "web", "cves": []},
    445: {"name": "SMB", "risk": "critical", "protocol": "tcp", "category": "file-sharing", "cves": ["CVE-2017-0143", "CVE-2020-1472"]},
    3306: {"name": "MySQL", "risk": "high", "protocol": "tcp", "category": "database", "cves": ["CVE-2019-2725"]},
    3389: {"name": "RDP", "risk": "high", "protocol": "tcp", "category": "remote-access", "cves": ["CVE-2019-0708", "CVE-2022-21889"]},
    5432: {"name": "PostgreSQL", "risk": "high", "protocol": "tcp", "category": "database", "cves": ["CVE-2013-0255"]},
    5900: {"name": "VNC", "risk": "high", "protocol": "tcp", "category": "remote-access", "cves": ["CVE-2019-15690"]},
    6379: {"name": "Redis", "risk": "critical", "protocol": "tcp", "category": "database", "cves": ["CVE-2020-14144", "CVE-2022-0543"]},
    27017: {"name": "MongoDB", "risk": "critical", "protocol": "tcp", "category": "database", "cves": ["CVE-2019-2725"]},
}


def get_dns_info(target: str) -> dict:
    """Perform DNS enumeration and reverse DNS lookup."""
    dns_data = {
        "forward_lookup": None,
        "reverse_lookup": None,
        "mx_records": [],
        "ns_records": [],
        "errors": []
    }
    
    try:
        # Forward DNS lookup
        try:
            dns_data["forward_lookup"] = socket.gethostbyname(target)
        except socket.gaierror as e:
            dns_data["errors"].append(f"Forward lookup failed: {str(e)}")
        
        # Reverse DNS lookup
        if dns_data["forward_lookup"]:
            try:
                reverse_host = socket.gethostbyaddr(dns_data["forward_lookup"])
                dns_data["reverse_lookup"] = reverse_host[0]
            except socket.herror:
                dns_data["reverse_lookup"] = None
    except Exception as e:
        dns_data["errors"].append(f"DNS enumeration error: {str(e)}")
    
    return dns_data


def analyze_ssl_certificate(target: str, port: int = 443) -> dict:
    """Extract and analyze SSL/TLS certificate information."""
    cert_data = {
        "has_ssl": False,
        "certificate": None,
        "subject": None,
        "issuer": None,
        "validity": {"not_before": None, "not_after": None, "valid": False},
        "cipher_suite": None,
        "protocol_version": None,
        "errors": []
    }
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((target, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert_data["has_ssl"] = True
                cert_data["protocol_version"] = ssock.version
                cert_data["cipher_suite"] = ssock.cipher()[0]
                
                cert_der = ssock.getpeercert(binary_form=True)
                cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                
                cert_dict = ssock.getpeercert()
                if cert_dict:
                    cert_data["subject"] = dict(x[0] for x in cert_dict.get('subject', []))
                    cert_data["issuer"] = dict(x[0] for x in cert_dict.get('issuer', []))
                    cert_data["validity"]["not_before"] = cert_dict.get('notBefore')
                    cert_data["validity"]["not_after"] = cert_dict.get('notAfter')
                    cert_data["validity"]["valid"] = True
                    cert_data["certificate"] = cert_pem[:200] + "..." if len(cert_pem) > 200 else cert_pem
    except ssl.SSLError as e:
        cert_data["errors"].append(f"SSL/TLS error: {str(e)}")
    except socket.timeout:
        cert_data["errors"].append("SSL certificate check timeout")
    except Exception as e:
        cert_data["errors"].append(f"Certificate analysis error: {str(e)}")
    
    return cert_data


def get_http_headers(target: str, port: int = 80, use_https: bool = False) -> dict:
    """Analyze HTTP security headers."""
    headers_data = {
        "server": None,
        "security_headers": {},
        "missing_headers": [],
        "errors": []
    }
    
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{target}:{port}" if port not in [80, 443] else f"{scheme}://{target}"
    
    security_headers_to_check = [
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
        "X-XSS-Protection",
        "Referrer-Policy"
    ]
    
    try:
        req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(req, timeout=5) as response:
            headers_data["server"] = response.headers.get("Server")
            
            for header in security_headers_to_check:
                value = response.headers.get(header)
                if value:
                    headers_data["security_headers"][header] = value
                else:
                    headers_data["missing_headers"].append(header)
    except Exception as e:
        headers_data["errors"].append(f"HTTP header analysis error: {str(e)}")
    
    return headers_data


def categorize_port_risk(port_num: int, service_name: str) -> dict:
    """Categorize ports by risk level and provide intelligence."""
    if port_num in SERVICE_INTELLIGENCE:
        intel = SERVICE_INTELLIGENCE[port_num]
        return {
            "port": port_num,
            "service": intel["name"],
            "risk_level": intel["risk"],
            "category": intel["category"],
            "protocol": intel["protocol"],
            "known_cves": intel["cves"],
            "recommendations": get_remediation(intel["risk"], intel["name"])
        }
    
    # Common port ranges for unknown services
    if 1 <= port_num <= 1024:
        risk = "medium"
    elif 1024 < port_num <= 49151:
        risk = "low"
    else:
        risk = "low"
    
    return {
        "port": port_num,
        "service": service_name or "Unknown",
        "risk_level": risk,
        "category": "custom",
        "protocol": "tcp",
        "known_cves": [],
        "recommendations": []
    }


def get_remediation(risk_level: str, service_name: str) -> list:
    """Generate remediation recommendations based on risk."""
    recommendations = {
        "critical": [
            f"URGENT: {service_name} is running with critical risk exposure",
            "Consider disabling this service if not essential",
            "Apply all available security patches immediately",
            "Implement network-level access controls (firewall rules)"
        ],
        "high": [
            f"{service_name} represents significant security risk",
            "Ensure service is updated to latest version",
            "Implement strong authentication mechanisms",
            "Restrict access to authorized IPs only"
        ],
        "medium": [
            f"Monitor {service_name} for suspicious activity",
            "Keep service updated with security patches",
            "Implement proper authentication and encryption",
            "Use non-standard ports if possible"
        ],
        "low": [
            f"{service_name} poses low risk if properly configured",
            "Apply standard security best practices",
            "Keep service updated and monitored"
        ]
    }
    return recommendations.get(risk_level, [])



def parse_nmap_output(output: str) -> list[dict]:
    """Parse Nmap output and extract port information."""
    ports: list[dict] = []

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("Nmap"):
            continue

        match = re.match(r"^(\d+)/(tcp|udp)\s+(open|closed|filtered)\s*(.*)$", stripped, re.I)
        if not match:
            continue

        remainder = match.group(4).strip()
        service = "unknown"
        version = ""
        if remainder:
            parts = remainder.split(None, 1)
            service = parts[0]
            version = parts[1] if len(parts) > 1 else ""

        ports.append(
            {
                "port": int(match.group(1)),
                "protocol": match.group(2).lower(),
                "state": match.group(3).lower(),
                "service": service,
                "version": version,
            }
        )

    return ports


def build_nmap_command(target: str, scan_type: str) -> list[str]:
    if scan_type == "quick":
        return ["nmap", "-F", target]
    return ["nmap", "-sV", "-sC", target]


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_site(path: str):
    if path and (BASE_DIR / path).exists():
        return send_from_directory(BASE_DIR, path)
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "message": "Scanner backend is running"})


@app.route("/contact", methods=["POST"])
def contact():
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    email = (payload.get("email") or "").strip()
    message = (payload.get("message") or "").strip()

    if not name or not email or not message:
        return jsonify({"ok": False, "message": "Please complete every field before sending."}), 400

    if "@" not in email or "." not in email.split("@", 1)[1]:
        return jsonify({"ok": False, "message": "Please provide a valid email address."}), 400

    load_dotenv(BASE_DIR / ".env")
    contact_recipient = os.getenv("CONTACT_EMAIL", "ananyakar2007@gmail.com")
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "465"))
    smtp_username = os.getenv("SMTP_USERNAME", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")

    if is_rate_limited(request.remote_addr or request.headers.get("X-Forwarded-For", "unknown")):
        return jsonify({"ok": False, "message": "Too many contact attempts. Please try again later."}), 429

    if contact_recipient and smtp_host and smtp_username and smtp_password:
        try:
            mail = EmailMessage()
            mail["Subject"] = f"Portfolio contact from {name}"
            mail["From"] = smtp_username
            mail["To"] = contact_recipient
            mail["Reply-To"] = email
            mail.set_content(
                f"Name: {name}\nEmail: {email}\n\n{message}"
            )

            use_ssl = os.getenv("SMTP_USE_SSL", "true").lower() in ["1", "true", "yes"]
            smtp_timeout = int(os.getenv("SMTP_TIMEOUT", "20"))

            if use_ssl:
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=smtp_timeout) as server:
                    if smtp_username and smtp_password:
                        server.login(smtp_username, smtp_password)
                    server.send_message(mail)
            else:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=smtp_timeout) as server:
                    server.ehlo()
                    if smtp_port == 587:
                        server.starttls()
                        server.ehlo()
                    if smtp_username and smtp_password:
                        server.login(smtp_username, smtp_password)
                    server.send_message(mail)

            return jsonify({"ok": True, "message": "Thanks — your message was sent successfully."})
        except Exception as exc:
            return jsonify({"ok": False, "message": "Email delivery failed. Check SMTP settings and logs.", "error": str(exc)}), 500

    return jsonify({"ok": False, "message": "SMTP is not configured. Please set SMTP_HOST, SMTP_USERNAME, and SMTP_PASSWORD."}), 500


@app.route("/thm-stats", methods=["GET"])
def thm_stats():
    result = {
        **RESUME_THM_STATS,
        "profile_url": THM_PROFILE_URL,
        "source": "verified-resume",
        "live": False,
        "updated_at": utc_now_iso(),
        "message": "Using verified resume data because the public profile cannot be queried reliably.",
    }

    try:
        profile_data = fetch_json(THM_PUBLIC_PROFILE_API.format(username="ananyakar2007"))
        live_data = profile_data.get("data", {}) if isinstance(profile_data, dict) else {}

        rank = live_data.get("rank")
        badges = live_data.get("badgesNumber")
        rooms = live_data.get("completedRoomsNumber")

        if rank and badges is not None and rooms is not None:
            result.update(
                {
                    "rank": f"{rank:,}",
                    "badges": str(badges),
                    "rooms": str(rooms),
                    "level": live_data.get("level"),
                    "top_percentage": live_data.get("topPercentage"),
                    "top_ten_percent": live_data.get("isInTopTenPercent"),
                    "league_tier": live_data.get("leagueTier"),
                    "country": live_data.get("country"),
                    "capability_score": (live_data.get("capabilityScore") or {}).get("value"),
                }
            )
            result["profile_url"] = THM_PROFILE_URL
            result["source"] = "tryhackme-public-api"
            result["live"] = True
            result["message"] = "Live profile snapshot pulled from TryHackMe public API."
    except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        result["error"] = str(exc)
    except Exception as exc:
        result["error"] = str(exc)

    return jsonify(result)


@app.route("/scan", methods=["POST"])
def scan():
    data = request.json or {}
    target = data.get("target", "localhost")
    scan_type = data.get("scan_type", "quick")

    report = {
        "target": target,
        "scan_type": scan_type,
        "timestamp": utc_now_iso(),
        "ping": run_ping(target),
        "dns_intelligence": {},
        "ports": [],
        "vulnerability_assessment": {
            "critical_ports": [],
            "high_risk_ports": [],
            "overall_risk": "low"
        },
        "http_analysis": {},
        "ssl_analysis": {},
        "counts": {
            "open": 0,
            "closed": 0,
            "filtered": 0,
            "total": 0,
        },
        "threat_summary": {
            "score": 0,  # 0-100
            "findings": [],
            "remediation": []
        },
        "notes": [],
        "warnings": [],
        "raw": {"nmap": ""},
    }

    # Step 1: DNS Enumeration
    if report["ping"]["reachable"]:
        report["dns_intelligence"] = get_dns_info(target)

    # Step 2: Run Nmap Scan
    nmap_command = build_nmap_command(target, scan_type)

    try:
        nmap = subprocess.run(nmap_command, capture_output=True, text=True, timeout=90)
        raw_output = nmap.stdout if nmap.returncode == 0 else nmap.stderr
        report["raw"]["nmap"] = raw_output
        report["ports"] = parse_nmap_output(raw_output)

        # Step 3: Enhance ports with intelligence and risk assessment
        enhanced_ports = []
        critical_count = 0
        high_count = 0
        
        for port in report["ports"]:
            # Only analyze open ports for additional intelligence
            if port["state"] == "open":
                port_intel = categorize_port_risk(port["port"], port["service"])
                port.update(port_intel)
                
                # Collect vulnerability findings
                if port_intel["risk_level"] == "critical":
                    report["vulnerability_assessment"]["critical_ports"].append({
                        "port": port["port"],
                        "service": port_intel["service"],
                        "cves": port_intel["known_cves"]
                    })
                    critical_count += 1
                elif port_intel["risk_level"] == "high":
                    report["vulnerability_assessment"]["high_risk_ports"].append({
                        "port": port["port"],
                        "service": port_intel["service"],
                        "cves": port_intel["known_cves"]
                    })
                    high_count += 1
            
            enhanced_ports.append(port)

        report["ports"] = enhanced_ports

        # Step 4: SSL/TLS Analysis for HTTPS ports
        if report["ping"]["reachable"] and any(p["port"] == 443 and p["state"] == "open" for p in report["ports"]):
            report["ssl_analysis"] = analyze_ssl_certificate(target, 443)

        # Step 5: HTTP Security Headers Analysis
        http_port = next((p for p in report["ports"] if p["port"] == 80 and p["state"] == "open"), None)
        https_port = next((p for p in report["ports"] if p["port"] == 443 and p["state"] == "open"), None)
        
        if http_port:
            report["http_analysis"] = get_http_headers(target, 80, False)
        if https_port:
            report["ssl_analysis"].update(get_http_headers(target, 443, True))

        # Step 6: Calculate counts and risk assessment
        for port in report["ports"]:
            state = port["state"]
            report["counts"][state] = report["counts"].get(state, 0) + 1

        report["counts"]["total"] = len(report["ports"])

        # Step 7: Set overall risk level
        if critical_count > 0:
            report["vulnerability_assessment"]["overall_risk"] = "critical"
            report["threat_summary"]["score"] = 90 + min(critical_count * 3, 10)
        elif high_count > 0:
            report["vulnerability_assessment"]["overall_risk"] = "high"
            report["threat_summary"]["score"] = 65 + (high_count * 5)
        elif report["counts"]["open"] > 0:
            report["vulnerability_assessment"]["overall_risk"] = "medium"
            report["threat_summary"]["score"] = 40 + (report["counts"]["open"] * 3)
        else:
            report["vulnerability_assessment"]["overall_risk"] = "low"
            report["threat_summary"]["score"] = 10

        # Step 8: Generate findings and remediation
        open_count = report["counts"]["open"]
        
        if critical_count > 0:
            report["threat_summary"]["findings"].append(
                f"⚠️ CRITICAL: {critical_count} critical-risk service(s) detected requiring immediate attention"
            )
        
        if high_count > 0:
            report["threat_summary"]["findings"].append(
                f"🔴 HIGH RISK: {high_count} high-risk service(s) found"
            )
        
        if open_count > 0:
            report["threat_summary"]["findings"].append(
                f"📊 Total exposed service(s): {open_count}"
            )
        
        if report["ssl_analysis"].get("has_ssl") and not report["ssl_analysis"].get("validity", {}).get("valid"):
            report["threat_summary"]["findings"].append("🔒 SSL certificate issues detected")
        
        if report["http_analysis"].get("missing_headers"):
            report["threat_summary"]["findings"].append(
                f"🛡️ Missing {len(report['http_analysis']['missing_headers'])} security headers"
            )

        # Generate remediation steps
        for critical_port in report["vulnerability_assessment"]["critical_ports"]:
            service_risk = "critical"
            for rec in get_remediation(service_risk, critical_port["service"]):
                if rec not in report["threat_summary"]["remediation"]:
                    report["threat_summary"]["remediation"].append(rec)

        # Step 9: Generate notes
        if open_count == 0:
            report["notes"].append("✅ No open services detected - good baseline.")
        else:
            report["notes"].append(f"🔍 Scan identified {open_count} open port(s) requiring review.")

        if scan_type == "quick":
            report["notes"].append("⚡ Quick mode scanned top 100 ports (fastest attack surface analysis).")
        else:
            report["notes"].append("🔬 Full mode ran extended version detection and script scanning.")

        report["notes"].append(f"🌐 Threat score: {report['threat_summary']['score']}/100 ({report['vulnerability_assessment']['overall_risk'].upper()})")

    except subprocess.TimeoutExpired:
        report["warnings"].append("⏱️ Nmap scan timed out after 90 seconds. Results may be incomplete.")
    except FileNotFoundError:
        report["warnings"].append("❌ Nmap not found. Install nmap to enable live scans: https://nmap.org/download")
    except Exception as exc:
        report["warnings"].append(f"⚠️ Nmap error: {exc}")

    return jsonify(report)



if __name__ == "__main__":
    print("=" * 70)
    print(" " * 15 + "🔐 ADVANCED SECURITY SCANNER BACKEND")
    print("=" * 70)
    print("\n📡 CAPABILITIES:")
    print("  ✓ Ping & Network Reachability Analysis")
    print("  ✓ DNS Enumeration (Forward & Reverse Lookups)")
    print("  ✓ Nmap Port Scanning with Version Detection")
    print("  ✓ Service Intelligence & Risk Categorization")
    print("  ✓ SSL/TLS Certificate Analysis")
    print("  ✓ HTTP Security Headers Assessment")
    print("  ✓ Known CVE Mapping for Services")
    print("  ✓ Threat Scoring & Risk Assessment")
    print("  ✓ Automated Remediation Recommendations")
    print("\n🚀 ENDPOINTS:")
    print(f"  POST /scan          - Run comprehensive security scan")
    print(f"  GET  /health        - Service health check")
    print(f"  GET  /thm-stats     - TryHackMe profile statistics")
    print("\n🌐 Running on: http://localhost:5000")
    print("⚠️  Only scan systems you own or have explicit permission to test!")
    print("=" * 70)
    app.run(debug=True, host="0.0.0.0", port=5000)
