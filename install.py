#!/usr/bin/env python3
"""
ShellForge Installer
Installs shellforge to /usr/local/bin for system-wide access
"""

import os
import sys
import shutil
from pathlib import Path

def main():
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║                   ShellForge Installer                            ║
╚═══════════════════════════════════════════════════════════════════╝
""")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("❌ Error: This installer must be run as root!")
        print("   Please run: sudo python3 install.py")
        sys.exit(1)
    
    # Paths
    script_dir = Path(__file__).parent
    source_file = script_dir / 'shellforge.py'
    install_dir = Path('/usr/local/bin')
    target_file = install_dir / 'shellforge'
    
    # Check if source exists
    if not source_file.exists():
        print(f"❌ Error: shellforge.py not found in {script_dir}")
        sys.exit(1)
    
    try:
        # Create install directory if it doesn't exist
        install_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy file
        print(f"📦 Installing shellforge to {target_file}...")
        shutil.copy2(source_file, target_file)
        
        # Make executable
        os.chmod(target_file, 0o755)
        
        print("✅ Installation successful!")
        print(f"   ShellForge installed to: {target_file}")
        print("\n🎉 You can now use 'shellforge' command from anywhere!")
        print("\n📖 Quick Start:")
        print("   shellforge --help")
        print("   shellforge --list-extensions")
        print("   shellforge 192.168.1.100 4444 php")
        print("\n" + "═"*67)
        
    except Exception as e:
        print(f"❌ Installation failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
