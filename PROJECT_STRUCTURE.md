# ShellForge - Project Structure

## 📁 Directory Layout

```
shellforge/
├── README.md                      # Main project documentation
├── LICENSE                        # MIT License
├── CONTRIBUTING.md                # Contribution guidelines
├── install.py                     # Installation script
├── shellforge.py                  # Main application
├── .gitignore                     # Git ignore rules
├── docs/                          # Documentation
│   ├── ADVANCED_2025_FEATURES.md  # 2025 features guide
│   └── ALL_EXTENSIONS.md          # Complete extensions list
└── tests/                         # Test directory (future)
```

## 🔧 Core Files

### shellforge.py
Main application file containing:
- `ShellForge` class - Core functionality
- Template definitions for 65+ extensions
- 14 obfuscation methods
- 11 bypass techniques
- CLI interface

**Size:** ~145KB  
**Lines:** ~2200  
**Language:** Python 3.6+

### install.py
Installation script that:
- Checks for root permissions
- Copies `shellforge.py` to `/usr/local/bin/shellforge`
- Makes it executable
- Provides installation confirmation

## 📚 Documentation

### README.md
Comprehensive documentation including:
- Project overview
- Feature list
- Installation instructions
- Usage examples
- Command reference
- Legal disclaimer

### docs/ADVANCED_2025_FEATURES.md
Detailed guide for 2025 features:
- Advanced obfuscation methods
- Bypass techniques
- Use cases and examples
- Comparison matrices

### docs/ALL_EXTENSIONS.md
Complete extension reference:
- All 65+ supported extensions
- Category breakdown
- Usage examples per category

### CONTRIBUTING.md
Guidelines for contributors:
- How to report bugs
- How to suggest features
- Pull request process
- Development guidelines
- Testing procedures

## 🎯 Key Components

### Templates System
- **Location:** `_load_templates()` method
- **Count:** 1000+ templates across 65+ extensions
- **Format:** Dictionary structure with extension as key
- **Placeholders:** `{host}`, `{port}`, `{cmd}`

### Obfuscation Engine
- **Methods:** 14 total (6 classic + 8 advanced)
- **Location:** `_obfuscate_*` methods
- **Features:** Polymorphic, multilayer, compression

### Bypass Engine
- **Methods:** 11 techniques
- **Location:** `_bypass_*` methods
- **Features:** Archive nesting, magic bytes, unicode tricks

### CLI Interface
- **Parser:** argparse-based
- **Modes:** Positional and named arguments
- **Lists:** Extensions, obfuscation, bypasses, templates

## 🔄 Data Flow

```
User Input
    ↓
CLI Parser
    ↓
ShellForge Class
    ↓
Template Selection
    ↓
Parameter Substitution ({host}, {port})
    ↓
Obfuscation (optional)
    ↓
Encoding (optional)
    ↓
Bypass Method (optional)
    ↓
Output File / Display
```

## 🛠️ Installation Paths

### Development
```
/path/to/shellforge/shellforge.py
```

### System-Wide (Post-Installation)
```
/usr/local/bin/shellforge
```

## 📦 Dependencies

**None!** Uses only Python standard library:
- `json` - Configuration handling
- `os` - File operations
- `sys` - System operations
- `argparse` - CLI parsing
- `base64` - Encoding
- `random` - Randomization
- `string` - String operations
- `zipfile` - Archive creation
- `io` - I/O operations
- `pathlib` - Path handling

## 🔒 Security Considerations

### Code Design
- No external dependencies = reduced attack surface
- Input validation on all parameters
- Safe file operations
- Error handling throughout

### Ethical Design
- Clear legal disclaimers
- Educational focus
- Responsible disclosure encouragement
- No malicious intent

## 📊 Statistics

| Metric | Value |
|--------|-------|
| **Total Extensions** | 65+ |
| **Obfuscation Methods** | 14 |
| **Bypass Techniques** | 11 |
| **Total Templates** | 1000+ |
| **Lines of Code** | ~2200 |
| **File Size** | ~145KB |
| **Python Version** | 3.6+ |
| **Dependencies** | 0 external |

## 🚀 Release Process

1. Update version in README.md
2. Test all features
3. Update CHANGELOG (if exists)
4. Create git tag
5. Push to GitHub
6. Create release notes

## 🔮 Future Enhancements

Potential additions:
- [ ] More language templates (C#, Swift, Kotlin)
- [ ] Custom template support
- [ ] Configuration file support
- [ ] Integration with Metasploit
- [ ] GUI version
- [ ] Cloud shell generation
- [ ] API endpoint mode

---

**Last Updated:** 2025-11-05  
**Version:** 2.0.0
