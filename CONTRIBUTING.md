# Contributing to ShellForge

Thank you for considering contributing to ShellForge! This document outlines the process and guidelines for contributions.

## Code of Conduct

- Be respectful and professional
- Follow ethical guidelines for security research
- Do not submit malicious code
- Help maintain a welcoming community

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/yourusername/shellforge/issues)
2. Create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (OS, Python version)

### Suggesting Enhancements

1. Check existing [Issues](https://github.com/yourusername/shellforge/issues) and [Discussions](https://github.com/yourusername/shellforge/discussions)
2. Create a new issue or discussion with:
   - Clear description of the enhancement
   - Use cases and benefits
   - Possible implementation approach

### Pull Requests

1. Fork the repository
2. Create a new branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guide
- Add comments for complex logic
- Update documentation if needed
- Test on Python 3.6+
- Keep code clean and readable

### Adding New Extensions

To add a new file extension:

1. Add templates to the `self.templates` dictionary in `_load_templates()`
2. Include at least:
   - `reverse`: Reverse shell template with `{host}` and `{port}` placeholders
   - `basic`: Basic shell template
3. Test the new extension thoroughly

### Adding New Obfuscation Methods

1. Add method to `self.obfuscation_methods` dictionary
2. Implement the method (e.g., `def _obfuscate_yourmethod(self, text: str) -> str:`)
3. Add to CLI choices in `parser.add_argument('--obfuscate')`
4. Add to `--list-obfuscation` output
5. Document the method

### Adding New Bypass Methods

1. Add method to `self.bypass_methods` dictionary
2. Implement the method (e.g., `def _bypass_yourmethod(self, filename: str, shell_content: str) -> tuple:`)
3. Add to CLI choices in `parser.add_argument('--bypass')`
4. Add to `--list-bypasses` output
5. Document the method

## Development Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/Wael-Rd/shellforge.git
   cd shellforge
   ```

2. **Install in Development Mode**
   ```bash
   pip3 install -e .
   ```
   This installs ShellForge globally while keeping your local changes active.

3. **Run Tests**
   ```bash
   # Test basic generation
   shellforge 192.168.1.100 4444 php -o test.php
   
   # Test obfuscation
   shellforge 192.168.1.100 4444 ps1 --obfuscate -o test.ps1
   ```

## Project Structure

```
shellforge/
├── setup.py              # Installation configuration
├── bin/shellforge        # Entry point script
├── shellforge/           # Main package
│   ├── main.py          # CLI entry point
│   ├── core/            # Core generators
│   │   ├── config.py
│   │   ├── generator.py
│   │   └── polyglot.py
│   ├── templates/       # Base64 encoded templates
│   │   ├── data.py
│   │   └── manager.py
│   ├── obfuscators/     # Polymorphic engines
│   │   ├── polymorphic.py
│   │   └── steganography.py
│   └── bypasses/        # Evasion modules
│       ├── archives.py
│       ├── sandbox.py
│       └── persistence.py
├── docs/                # Documentation
└── README.md
```

## Testing

Before submitting a PR, test:

```bash
# Basic functionality
python3 shellforge.py 192.168.1.100 4444 php

# New obfuscation (if added)
python3 shellforge.py 192.168.1.100 4444 php --obfuscate yourmethod

# New bypass (if added)
python3 shellforge.py 192.168.1.100 4444 php --bypass yourmethod --output test.php

# List commands
python3 shellforge.py --list-extensions
python3 shellforge.py --list-obfuscation
python3 shellforge.py --list-bypasses
```

## Questions?

Feel free to open a [Discussion](https://github.com/yourusername/shellforge/discussions) if you have questions!

---

Thank you for contributing to ShellForge! 🚀
