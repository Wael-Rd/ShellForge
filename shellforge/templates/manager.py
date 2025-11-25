import base64
from .data import TEMPLATES

class TemplateManager:
    def __init__(self):
        self.templates = TEMPLATES

    def get_template(self, extension, type="reverse"):
        """
        Retrieves and decrypts a template.
        """
        if extension not in self.templates:
            raise ValueError(f"Extension '{extension}' not supported.")
        
        if type not in self.templates[extension]:
            raise ValueError(f"Template type '{type}' not found for extension '{extension}'.")

        encrypted_content = self.templates[extension][type]
        
        # In V3, we use Base64 as a placeholder for "Encryption" to avoid AV flagging the python file itself
        # with cleartext shells. Real XOR implementation would go here.
        try:
            decoded_content = base64.b64decode(encrypted_content).decode('utf-8')
            return decoded_content
        except Exception as e:
            raise RuntimeError(f"Failed to decrypt template: {str(e)}")

    def render(self, extension, host, port, type="reverse"):
        """
        Gets a template and substitutes variables.
        """
        template = self.get_template(extension, type)
        return template.replace("{host}", host).replace("{port}", str(port))
