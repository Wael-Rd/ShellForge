import os

class SteganographyEngine:
    def __init__(self):
        pass

    def hide_in_bmp(self, payload, cover_image_path, output_path):
        """
        Hides payload in the Least Significant Bit (LSB) of a BMP image.
        Note: This is a simplified implementation for standard 24-bit BMPs.
        """
        try:
            with open(cover_image_path, 'rb') as f:
                bmp_data = bytearray(f.read())
            
            # BMP Header is usually 54 bytes
            header = bmp_data[:54]
            pixel_data = bmp_data[54:]
            
            # Prepare payload: length + payload
            payload_bytes = payload.encode('utf-8')
            payload_len = len(payload_bytes)
            # Store length as 4 bytes (32 bits)
            full_payload = payload_len.to_bytes(4, 'big') + payload_bytes
            
            if len(full_payload) * 8 > len(pixel_data):
                raise ValueError("Payload too large for cover image.")
            
            # Embed payload bits into LSB of pixel bytes
            data_index = 0
            for byte in full_payload:
                for i in range(7, -1, -1):
                    bit = (byte >> i) & 1
                    # Clear LSB and set new bit
                    pixel_data[data_index] = (pixel_data[data_index] & 0xFE) | bit
                    data_index += 1
            
            with open(output_path, 'wb') as f:
                f.write(header + pixel_data)
                
            return True
        except Exception as e:
            print(f"[-] Steganography Error: {e}")
            return False

    def hide_in_whitespace(self, payload, cover_text_path, output_path):
        """
        Hides payload in whitespace (tabs/spaces) at the end of lines.
        0 -> Space
        1 -> Tab
        """
        try:
            with open(cover_text_path, 'r') as f:
                lines = f.readlines()
            
            payload_bits = ''.join(format(ord(c), '08b') for c in payload)
            
            # Distribute bits across lines
            new_lines = []
            bit_idx = 0
            for line in lines:
                line = line.rstrip('\r\n')
                hidden_part = ""
                # Embed up to 8 bits per line to keep it subtle, or just append as much as needed
                # For simplicity, we append 1 bit per line if we have enough lines, or multiple
                if bit_idx < len(payload_bits):
                    # Let's put 4 bits per line
                    chunk = payload_bits[bit_idx:bit_idx+4]
                    for bit in chunk:
                        if bit == '0':
                            hidden_part += " "
                        else:
                            hidden_part += "\t"
                    bit_idx += 4
                
                new_lines.append(line + hidden_part + "\n")
            
            # If we have leftover bits, append empty lines with hidden data
            while bit_idx < len(payload_bits):
                chunk = payload_bits[bit_idx:bit_idx+4]
                hidden_part = ""
                for bit in chunk:
                    if bit == '0':
                        hidden_part += " "
                    else:
                        hidden_part += "\t"
                new_lines.append(hidden_part + "\n")
                bit_idx += 4

            with open(output_path, 'w') as f:
                f.writelines(new_lines)
            
            return True
        except Exception as e:
            print(f"[-] Steganography Error: {e}")
            return False
