import random
import string

class PolymorphicEngine:
    def __init__(self):
        pass

    def obfuscate(self, content, extension):
        """
        Applies polymorphic obfuscation based on extension.
        """
        if extension == "php":
            return self._obfuscate_php(content)
        elif extension == "python":
            return self._obfuscate_python(content)
        elif extension == "bash":
            return self._obfuscate_bash(content)
        elif extension in ["powershell", "amsi", "ps1"]:
            return self._obfuscate_powershell(content)
        return content

    def _random_string(self, length=5):
        return ''.join(random.choices(string.ascii_letters, k=length))

    def _random_case(self, text):
        return ''.join(random.choice([c.upper(), c.lower()]) for c in text)

    def _insert_backticks(self, text):
        if len(text) < 2: return text
        # Insert 1 or 2 backticks randomly
        chars = list(text)
        num_backticks = random.randint(1, len(text) // 2)
        for _ in range(num_backticks):
            idx = random.randint(1, len(chars) - 1)
            if chars[idx-1] != '`' and chars[idx] != '`':
                chars.insert(idx, '`')
        return ''.join(chars)

    def _split_string(self, text):
        # Splits a string into concatenated parts: 'Am'+'si'
        if len(text) < 4: return f"'{text}'"
        split_idx = random.randint(1, len(text) - 1)
        p1 = text[:split_idx]
        p2 = text[split_idx:]
        return f"('{p1}'+'{p2}')"

    def _obfuscate_php(self, content):
        # Simple variable renaming and comment injection
        # In a real "Insane" tool, this would parse the AST
        
        # Inject random comments
        lines = content.split('\n')
        new_lines = []
        for line in lines:
            if random.random() > 0.7:
                new_lines.append(f"/* {self._random_string(10)} */")
            new_lines.append(line)
        
        return '\n'.join(new_lines)

    def _obfuscate_python(self, content):
        # Add random junk code
        junk_var = self._random_string()
        junk_val = random.randint(1, 1000)
        junk_code = f"{junk_var} = {junk_val} * 2\n"
        return junk_code + content

    def _obfuscate_bash(self, content):
        # Add random comments
        return f"# {self._random_string(20)}\n" + content

    def _obfuscate_powershell(self, content):
        """
        Advanced PowerShell Obfuscation:
        - Case Randomization
        - Backtick Insertion
        - String Concatenation
        """
        # Keywords to obfuscate (Case + Backticks)
        keywords = [
            "System", "Management", "Automation", "AmsiUtils", "amsiInitFailed", 
            "NonPublic", "Static", "SetValue", "GetField", "GetType", "Assembly", 
            "Ref", "Net.WebClient", "DownloadString", "IEX", "Invoke-Expression",
            "New-Object"
        ]
        
        # Sensitive strings to split (Concatenation)
        sensitive_strings = [
            "AmsiUtils", "amsiInitFailed", "System.Management.Automation.AmsiUtils"
        ]

        obfuscated = content

        # 1. String Splitting (Do this first to avoid breaking keywords inside strings if they overlap)
        # Actually, we should be careful. The template uses single quotes for these strings.
        # We will replace 'String' with ('Str'+'ing')
        for s in sensitive_strings:
            if f"'{s}'" in obfuscated:
                obfuscated = obfuscated.replace(f"'{s}'", self._split_string(s))

        # 2. Keyword Obfuscation (Case + Backticks)
        # We need to be careful not to break the concatenated strings we just made.
        # But keywords like 'System' might be used as types [System...]
        for kw in keywords:
            # Randomly choose strategy: Case or Backtick or Both
            strategy = random.choice(["case", "backtick", "both"])
            
            replacement = kw
            if strategy in ["case", "both"]:
                replacement = self._random_case(replacement)
            if strategy in ["backtick", "both"]:
                replacement = self._insert_backticks(replacement)
            
            # Simple replace might be dangerous if keyword is substring of another.
            # For this MVP, we'll assume keywords are distinct enough or use regex boundaries if needed.
            # But 'System' is in 'System.Management'.
            # So we should probably not replace 'System' if it's part of a larger dot-notation we already handled?
            # Actually, let's just replace them. PowerShell handles `S`y`s`t`e`m just fine.
            
            # We skip replacing if it's inside a string we just split (which has quotes).
            # But our keywords list includes things that are usually types or cmdlets.
            
            # To be safe, let's just do Case Randomization for now on everything, 
            # and Backticks only on specific cmdlets/types where valid.
            if kw in ["IEX", "Invoke-Expression", "New-Object", "GetField", "GetType", "SetValue", "Assembly"]:
                 obfuscated = obfuscated.replace(kw, replacement)
            else:
                 # For .NET types like System.Management, backticks might break resolution if not careful?
                 # Actually `S`ystem works in PS.
                 obfuscated = obfuscated.replace(kw, replacement)

        return obfuscated
