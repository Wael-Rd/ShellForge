# ShellForge Configuration

VERSION = "3.3.0"
AUTHOR = "Wael-Rd"

# Extension aliases (e.g., ps1 -> powershell)
EXTENSION_ALIASES = {
    "ps1": "powershell",
    "py": "python",
    "sh": "bash",
    "perl": "pl",
    "ruby": "rb",
}

SUPPORTED_EXTENSIONS = [
    # Web
    "php", "asp", "aspx", "jsp", "cfm",
    # Scripting
    "python", "bash", "pl", "rb", "lua", "js", "go",
    # Windows
    "powershell", "bat", "vbs", "hta",
    # System
    "c",
    # Polyglot
    "pdf", "png", "jpg",
    # Rare/Esoteric
    "groovy", "sql", "yaml", "tcl", "awk", "war",
    # Advanced Red Team
    "cs", "java", "vba", "html_smuggle",
    # Evasion & Bypass
    "msbuild", "xml_xxe",
    # LOLBin Bypasses
    "amsi", "sct", "xsl", "installutil"
]

# Add aliases to supported extensions for CLI
SUPPORTED_EXTENSIONS_WITH_ALIASES = SUPPORTED_EXTENSIONS + list(EXTENSION_ALIASES.keys())

# Available bypass techniques
BYPASS_TECHNIQUES = [
    "zip_in_zip",      # Nested ZIP archive
]

# AV/EDR Bypass levels
AV_BYPASS_LEVELS = [
    "amsi",            # AMSI bypass only (basic)
    "full",            # AMSI + ETW bypass (recommended)
    "max",             # AMSI + ETW + SBL + Anti-debug (aggressive)
]

# Persistence methods
PERSISTENCE_METHODS = [
    "registry",        # HKCU Run key
    "task",            # Scheduled Task
    "startup",         # Startup folder LNK
]

DEFAULT_PORT = 4444
DEFAULT_HTTP_PORT = 8080