# 🐚 ShellForge V3 - The Insane Shell Generator

![ShellForge](https://img.shields.io/badge/ShellForge-V3-red?style=for-the-badge) ![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge) ![Status](https://img.shields.io/badge/Status-Insane-orange?style=for-the-badge)

> **"The most comprehensive, modular, and advanced shell generation framework in the world."**

ShellForge V3 is a complete rewrite of the legendary payload generator, designed for Red Teamers, Pentesters, and Security Researchers who need **more than just a reverse shell**. It brings **polyglot generation**, **polymorphic obfuscation**, **LOLBin bypasses**, and **steganography** into a single, easy-to-use tool.

---

## 🔥 Features

### 🚀 40+ Payload Types
From standard web shells to system binaries and rare esoteric languages:
- **Web**: `php`, `asp`, `aspx`, `jsp`, `cfm`, `js` (Node)
- **System**: `python`, `bash`, `perl`, `ruby`, `lua`, `go`, `c`
- **Windows**: `powershell`, `bat`, `vbs`, `hta`
- **Rare/Esoteric**: `groovy`, `sql` (Postgres), `yaml` (K8s), `tcl`, `awk`, `war`
- **Red Team**: `cs` (C# Source), `java` (Android Source), `vba` (Office Macros), `html_smuggle`

### 🎭 True Polyglot Generation
Generate valid files that double as payloads:
- **PDF**: Valid PDF with embedded JavaScript triggers (`/OpenAction`).
- **PNG/JPG**: Valid images with payloads hidden in custom chunks or appended.
- **XML**: XXE Injection payloads disguised as valid XML.

### 👻 Evasion & Obfuscation
- **Polymorphic Engine**: Dynamic obfuscation for scripts (PHP, Python, Bash, PowerShell).
  - **PowerShell**: Case Randomization (`InVoKe`), Backticks (`I`n`v`o`k`e`), String Splitting.
- **Steganography**:
  - **BMP LSB**: Hide payloads inside the pixels of a BMP image.
  - **Whitespace**: Hide payloads in the tabs/spaces of a text file.

### 🛠️ Advanced Bypasses (LOLBins)
Living Off the Land binaries to bypass application whitelisting:
- **MSBuild**: XML project files executable via `MSBuild.exe`.
- **AMSI Bypass**: PowerShell scripts with embedded AMSI evasion.
- **Squiblydoo**: SCT scriptlets executable via `regsvr32`.
- **WMIC**: XSL stylesheets executable via `wmic`.
- **InstallUtil**: .NET binaries executable via `InstallUtil.exe`.

### 🎖️ Red Team Arsenal
**Bind Shells**: Listen on the target instead of connecting back (for NAT/firewall scenarios)
- Available for: PHP, Python, Bash, Perl, Ruby, PowerShell

**Sandbox/VM Detection**: Anti-analysis checks to prevent payload burns
- VM detection (VirtualBox, VMware, QEMU)
- RAM & Uptime checks
- Automated evasion for PowerShell, Python, Bash

**Persistence**: Maintain access across reboots
- Registry Run Keys (no admin required)
- Scheduled Tasks (hidden, runs at logon)
- Startup Folder (LNK shortcuts)

### 🎮 Handler Mode (All-in-One)
Automate your staging workflow with a single command:
- Auto-generates the second-stage payload (`run.ps1`).
- Starts a background HTTP server.
- Generates the bypass payload pointing to your server.
- Prints the exact command to run on the victim.

---

## 📦 Installation

```bash
git clone https://github.com/Wael-Rd/shellforge.git
cd shellforge
sudo pip3 install -e .
```

Now you can run `shellforge` from anywhere!

## ⚡ Usage

### Basic Reverse Shell
```bash
shellforge <LHOST> <LPORT> <EXTENSION>
# Example:
shellforge 192.168.1.100 4444 php -o shell.php
```

### Handler Mode (Auto-Staging)
The easiest way to use advanced bypasses:
```bash
shellforge 192.168.1.100 4444 amsi --serve
```
*Starts a server, generates the payload, and gives you the command to run!*

### Steganography
Hide a shell in a README file:
```bash
shellforge 192.168.1.100 4444 bash --stego-txt README.txt -o innocent.txt
```

### Polyglot PDF
Create a PDF that triggers a shell when opened:
```bash
shellforge 192.168.1.100 4444 pdf -o report.pdf
```

### Obfuscated PowerShell
Generate an AMSI-bypassing payload with randomized signatures:
```bash
shellforge 192.168.1.100 4444 ps1 --obfuscate -o bypass.ps1
```

---

## 🛡️ Disclaimer
This tool is for **educational purposes and authorized security testing only**. The authors are not responsible for any misuse. Always obtain permission before testing on systems you do not own.

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/Wael-Rd">Wael-Rd</a>
</p>
