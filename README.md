# Ananya Kar - Cybersecurity Portfolio

Welcome to my professional portfolio website! This is a comprehensive showcase of my expertise in cybersecurity, threat detection, and incident response.

🔗 **Live Portfolio**: Open `index.html` in your browser to view the portfolio.

---

## 📋 Portfolio Sections

### 1. **Portfolio & Credentials Tab**
- **Hero Section**: Key introduction and TryHackMe achievements
- **GitHub Projects**: 6+ security research projects
- **Experience**: Current roles and internships
- **Technical Skills**: Categorized by domain
- **Achievements**: TryHackMe Top 9%, Published Researcher, SIH Top 50
- **Education**: B.Tech CSE, SRMIST with 8.95/10.0 CGPA

### 2. **Real Security Scanner Tab**
- **Network Scanner**: Performs real Nmap scans, ping tests, and service detection
- **Authorization Modal**: Requires confirmation before scanning
- **Live Results**: Displays ICMP and Nmap output
- **Setup Instructions**: Easy 2-minute backend setup

---

## 🚀 Getting Started

### View Portfolio (No Setup Required)
1. Open `index.html` in any web browser
2. Browse through the Portfolio tab to see projects and credentials
3. The Security Scanner tab will show "Backend not running" until you set it up

### Enable Real Security Scanner (Optional)

#### Prerequisites
- Python 3.7+
- Flask and Flask-CORS
- Nmap installed on your system

#### Setup Steps

**1. Install Dependencies**
```bash
pip install flask flask-cors
```

**2. Install Nmap**
- **macOS**: `brew install nmap`
- **Linux**: `sudo apt install nmap`
- **Windows**: Download from https://nmap.org/download.html

**3. Run Backend**
```bash
python scanner_backend.py
```

The backend will start on `http://localhost:5000` and the portfolio will automatically detect it.

---

## 🔍 Key Features

### Portfolio Highlights
- **Professional Design**: Dark theme with cyan accents inspired by cybersecurity tools
- **Responsive Layout**: Works on desktop, tablet, and mobile
- **Tab Navigation**: Easy switching between portfolio and scanner
- **Social Links**: Direct links to GitHub, LinkedIn, and email
- **Project Showcase**: 6 featured GitHub projects with descriptions

### Security Scanner Features
- ✅ Real ICMP ping tests
- ✅ Professional Nmap scans with service detection
- ✅ Authorization confirmation modal
- ✅ Live result display
- ✅ Quick and Full scan modes
- ✅ Automatic backend status detection

---

## 📁 File Structure

```
portfolio/
├── index.html              # Main portfolio website
├── scanner_backend.py      # Flask backend for network scanning
└── README.md              # This file
```

---

## 🛠️ Backend API Reference

### Health Check Endpoint
```
GET /health
Response: 200 OK if backend is running
```

### Scan Endpoint
```
POST /scan
Content-Type: application/json

Request Body:
{
  "target": "localhost|192.168.1.1|example.com",
  "scan_type": "quick|full"
}

Response:
{
  "ping": "ICMP ping results",
  "nmap": "Nmap scan results"
}
```

---

## 📊 About My Experience

### Current Role
**Cybersecurity Research Member @ NextTechLab** (Remote)
- Risk monitoring for blockchain/stablecoin ecosystems
- ECU security analysis in connected vehicles
- CAN bus vulnerability research

### Recent Internship
**Cyber Security & Ethical Hacking Intern @ SparkIIT x Wipro**
- Web security dashboard development
- Phishing simulation platform
- Professional penetration testing tools

### Skills
- **SIEM & Log Analysis**: Splunk, log aggregation
- **Network Tools**: Nmap, Wireshark, Burp Suite
- **Threat Detection**: MITRE ATT&CK, anomaly detection
- **Programming**: Python, Java
- **Operating Systems**: Linux hardening, Windows security
- **5G/6G Security**: Digital twin environments, network slicing

---

## 🏆 Achievements

- 🥇 **TryHackMe Top 9%** - 194,052 rank, 86 rooms completed, 10 badges
- 📚 **Published Researcher** - IEEE paper on Quantum Technologies
- 🎯 **SIH Top 50** - Out of 2,500 students
- 📜 **Coursework**: Networks, OS, Cryptography, InfoSec, Linux, Wireless Comms

---

## 🔗 Connect With Me

- **GitHub**: https://github.com/Ananyacodes
- **LinkedIn**: https://linkedin.com/in/ananya-kar-6378291b4
- **Email**: ananyakar2007@gmail.com
- **Location**: Bangalore, India

---

## ⚠️ Legal Notice

This portfolio includes a real network scanning tool. Users are responsible for ensuring they have proper authorization before scanning any targets. Unauthorized network scanning may violate local laws. Always obtain explicit written permission before conducting security assessments.

---

## 📝 License

This portfolio is open source and available for reference. Feel free to use it as inspiration for your own portfolio!

**Last Updated**: May 2026
