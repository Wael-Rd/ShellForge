import zipfile
import io
import os

class ArchiveBypass:
    def __init__(self):
        pass

    def create_zip_in_zip(self, filename, content):
        """
        Creates a nested ZIP file structure.
        payload.zip -> inner.zip -> filename
        """
        # Create inner zip in memory
        inner_zip_buffer = io.BytesIO()
        with zipfile.ZipFile(inner_zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(filename, content)
        
        inner_zip_data = inner_zip_buffer.getvalue()
        
        # Create outer zip
        outer_zip_buffer = io.BytesIO()
        with zipfile.ZipFile(outer_zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("inner.zip", inner_zip_data)
            
        return outer_zip_buffer.getvalue()
