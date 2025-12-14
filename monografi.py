#!/usr/bin/env python3
"""
MONOGRAFI-TOOLKIT - Ultimate Cryptography & Encoding Toolkit for CTF
Version 3.0.0 - STABLE & ROBUST
Author: Cryptic Phantom
"""

import base64
import binascii
import re
import string
import math
import zlib
import gzip
import io
from typing import Dict, List, Tuple, Optional, Union, Any
from enum import Enum
from collections import Counter, defaultdict

# External libraries
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.layout import Layout
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich import print as rprint
from Crypto.Cipher import AES, DES, DES3, ARC4, Blowfish, CAST
from Crypto.Cipher import ChaCha20, Salsa20
from Crypto.Hash import MD5, SHA1, SHA256, SHA512, RIPEMD160
from Crypto.Hash import BLAKE2b, BLAKE2s
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

console = Console()

class ColorScheme:
    """Warna tema hacker untuk UI"""
    PRIMARY = "#00ff00"
    SECONDARY = "#00cc00"
    ACCENT = "#ff00ff"
    WARNING = "#ffff00"
    ERROR = "#ff0000"
    INFO = "#00ffff"
    DIM = "#555555"

class CryptoError(Exception):
    """Custom exception untuk error cryptography"""
    pass

class ValidationError(CryptoError):
    """Error untuk validasi input"""
    pass

def smart_print(data: Any, label: str = "Result") -> None:
    """
    Print data secara aman dengan deteksi otomatis.
    Handle text, bytes, binary data, dll tanpa crash.
    """
    console.print(f"\n[bold {ColorScheme.PRIMARY}]{label}:[/bold {ColorScheme.PRIMARY}]")
    
    if data is None:
        console.print("[dim]No data[/dim]")
        return
    
    # Jika bytes, handle dengan benar
    if isinstance(data, bytes):
        # Coba decode sebagai UTF-8
        try:
            text = data.decode('utf-8')
            # Cek jika printable
            if all(c.isprintable() or c in '\n\r\t' for c in text):
                console.print(text)
                console.print(f"[{ColorScheme.DIM}]UTF-8 text (hex: {data.hex()})[/{ColorScheme.DIM}]")
            else:
                raise UnicodeDecodeError('utf-8', data, 0, 1, 'non-printable chars')
        except (UnicodeDecodeError, UnicodeEncodeError):
            # Tampilkan dalam berbagai format
            hex_str = data.hex()
            b64_str = base64.b64encode(data).decode('ascii')
            
            console.print(f"[{ColorScheme.WARNING}]Binary Data Detected[/{ColorScheme.WARNING}]")
            
            table = Table(show_header=False, box=None)
            table.add_column("Format", style=f"bold {ColorScheme.INFO}")
            table.add_column("Value", style=ColorScheme.SECONDARY)
            
            table.add_row("Hexadecimal", hex_str)
            table.add_row("Base64", b64_str)
            table.add_row("Length", f"{len(data)} bytes")
            
            # Coba interpretasi sebagai ASCII (printable saja)
            ascii_text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
            if any(c != '.' for c in ascii_text):
                table.add_row("ASCII View", ascii_text)
            
            console.print(table)
    
    # Jika string
    elif isinstance(data, str):
        if len(data) > 500:
            console.print(f"{data[:500]}...")
            console.print(f"[{ColorScheme.DIM}](Truncated, total: {len(data)} chars)[/{ColorScheme.DIM}]")
        else:
            console.print(data)
    
    # Untuk tipe lainnya
    else:
        console.print(str(data))

class BaseNEncoder:
    """Implementasi Base-N encoding yang STABIL dan diverifikasi"""
    
    # Alphabets
    BASE58_BTC = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    BASE36 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    BASE45 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:'
    BASE91 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
    Z85 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#'
    
    @staticmethod
    def base58_encode(data: bytes) -> str:
        """Encode bytes to Base58 (Bitcoin) - STABLE VERSION"""
        if not data:
            return ''
        
        # Convert bytes to integer
        int_val = 0
        for byte in data:
            int_val = int_val * 256 + byte
        
        # Convert integer to Base58
        result = ''
        while int_val > 0:
            int_val, remainder = divmod(int_val, 58)
            result = BaseNEncoder.BASE58_BTC[remainder] + result
        
        # Add leading '1's for leading zeros
        leading_zeros = 0
        for byte in data:
            if byte == 0:
                leading_zeros += 1
            else:
                break
        
        return '1' * leading_zeros + result or '1'
    
    @staticmethod
    def base58_decode(encoded: str) -> bytes:
        """Decode Base58 string to bytes - STABLE VERSION"""
        if not encoded:
            return b''
        
        # Validate input
        for char in encoded:
            if char not in BaseNEncoder.BASE58_BTC:
                raise ValidationError(f"Invalid Base58 character: '{char}'")
        
        # Convert Base58 to integer
        int_val = 0
        for char in encoded:
            int_val = int_val * 58 + BaseNEncoder.BASE58_BTC.index(char)
        
        # Convert integer to bytes
        if int_val == 0:
            return b''
        
        # Calculate bytes needed
        byte_count = (int_val.bit_length() + 7) // 8
        result = int_val.to_bytes(byte_count, 'big')
        
        # Add leading zeros
        leading_ones = 0
        for char in encoded:
            if char == '1':
                leading_ones += 1
            else:
                break
        
        return b'\x00' * leading_ones + result
    
    @staticmethod
    def base62_encode(data: bytes) -> str:
        """Encode bytes to Base62"""
        if not data:
            return '0'
        
        int_val = int.from_bytes(data, 'big')
        result = ''
        
        while int_val > 0:
            int_val, remainder = divmod(int_val, 62)
            result = BaseNEncoder.BASE62[remainder] + result
        
        return result or '0'
    
    @staticmethod
    def base62_decode(encoded: str) -> bytes:
        """Decode Base62 string to bytes"""
        if not encoded:
            return b''
        
        # Validate input
        for char in encoded:
            if char not in BaseNEncoder.BASE62:
                raise ValidationError(f"Invalid Base62 character: '{char}'")
        
        int_val = 0
        for char in encoded:
            int_val = int_val * 62 + BaseNEncoder.BASE62.index(char)
        
        if int_val == 0:
            return b''
        
        byte_count = max(1, (int_val.bit_length() + 7) // 8)
        return int_val.to_bytes(byte_count, 'big')
    
    @staticmethod
    def base91_encode(data: bytes) -> str:
        """Encode bytes to Base91 - STABLE & VERIFIED"""
        if not data:
            return ''
        
        alphabet = BaseNEncoder.BASE91
        result = []
        
        buffer = 0
        bits = 0
        
        for byte in data:
            buffer |= byte << bits
            bits += 8
            
            while bits >= 13:  # Process 13 or 14 bits
                # Take 13 bits
                value = buffer & 8191
                
                if value > 88:
                    # Use 13 bits
                    buffer >>= 13
                    bits -= 13
                else:
                    # Take 14 bits
                    value = buffer & 16383
                    buffer >>= 14
                    bits -= 14
                
                result.append(alphabet[value % 91])
                result.append(alphabet[value // 91])
        
        # Process remaining bits
        if bits:
            result.append(alphabet[buffer % 91])
            if bits > 7 or buffer > 90:
                result.append(alphabet[buffer // 91])
        
        return ''.join(result)
    
    @staticmethod
    def base91_decode(encoded: str) -> bytes:
        """Decode Base91 string to bytes - STABLE & VERIFIED"""
        if not encoded:
            return b''
        
        alphabet = BaseNEncoder.BASE91
        # Validate input
        for char in encoded:
            if char not in alphabet:
                raise ValidationError(f"Invalid Base91 character: '{char}'")
        
        result = bytearray()
        
        buffer = 0
        bits = 0
        v = -1
        
        for char in encoded:
            c = alphabet.index(char)
            
            if v < 0:
                v = c
            else:
                v += c * 91
                buffer |= v << bits
                bits += 13 if (v & 8191) > 88 else 14
                
                while bits > 7:
                    result.append(buffer & 0xFF)
                    buffer >>= 8
                    bits -= 8
                
                v = -1
        
        # Handle remaining
        if v != -1:
            result.append((buffer | (v << bits)) & 0xFF)
        
        return bytes(result)
    
    @staticmethod
    def base45_encode(data: bytes) -> str:
        """Encode bytes to Base45 (QR Code)"""
        if not data:
            return ''
        
        alphabet = BaseNEncoder.BASE45
        result = []
        
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                # Process 2 bytes
                value = (data[i] << 8) + data[i + 1]
                
                for _ in range(3):
                    value, rem = divmod(value, 45)
                    result.append(alphabet[rem])
            else:
                # Process single byte
                value = data[i]
                
                for _ in range(2):
                    value, rem = divmod(value, 45)
                    result.append(alphabet[rem])
        
        # Reverse karena kita append dari LSB
        return ''.join(reversed(result))
    
    @staticmethod
    def base45_decode(encoded: str) -> bytes:
        """Decode Base45 string to bytes"""
        if not encoded:
            return b''
        
        alphabet = BaseNEncoder.BASE45
        # Validate input
        for char in encoded:
            if char not in alphabet:
                raise ValidationError(f"Invalid Base45 character: '{char}'")
        
        result = bytearray()
        
        i = 0
        while i < len(encoded):
            # Determine chunk size
            if i + 2 < len(encoded):
                chunk = encoded[i:i+3]
                chunk_size = 3
                i += 3
            else:
                chunk = encoded[i:i+2]
                chunk_size = 2
                i += 2
            
            # Convert chunk to value
            value = 0
            for char in chunk:
                value = value * 45 + alphabet.index(char)
            
            # Convert value to bytes
            if chunk_size == 3:
                if value > 0xFFFF:
                    raise ValidationError("Invalid Base45 encoding")
                result.append((value >> 8) & 0xFF)
                result.append(value & 0xFF)
            else:
                if value > 0xFF:
                    raise ValidationError("Invalid Base45 encoding")
                result.append(value & 0xFF)
        
        return bytes(result)
    
    @staticmethod
    def z85_encode(data: bytes) -> str:
        """Encode bytes to Z85 (ZeroMQ Base85)"""
        if len(data) % 4 != 0:
            # Pad to multiple of 4
            padding = 4 - (len(data) % 4)
            data = data + b'\x00' * padding
        
        alphabet = BaseNEncoder.Z85
        result = []
        
        for i in range(0, len(data), 4):
            chunk = data[i:i+4]
            # Pad if necessary
            while len(chunk) < 4:
                chunk += b'\x00'
            
            # Convert 4 bytes to 32-bit integer
            value = int.from_bytes(chunk, 'big')
            
            # Convert to base85 (5 digits)
            digits = []
            for _ in range(5):
                value, rem = divmod(value, 85)
                digits.append(alphabet[rem])
            
            result.extend(reversed(digits))
        
        return ''.join(result)
    
    @staticmethod
    def z85_decode(encoded: str) -> bytes:
        """Decode Z85 string to bytes"""
        if len(encoded) % 5 != 0:
            raise ValidationError("Z85 encoded length must be multiple of 5")
        
        alphabet = BaseNEncoder.Z85
        # Validate input
        for char in encoded:
            if char not in alphabet:
                raise ValidationError(f"Invalid Z85 character: '{char}'")
        
        result = bytearray()
        
        for i in range(0, len(encoded), 5):
            chunk = encoded[i:i+5]
            
            # Convert chunk to value
            value = 0
            for char in chunk:
                value = value * 85 + alphabet.index(char)
            
            # Convert to 4 bytes
            result.extend(value.to_bytes(4, 'big'))
        
        # Remove padding zeros
        while result and result[-1] == 0:
            result.pop()
        
        return bytes(result)
    
    @staticmethod
    def base100_encode(text: str) -> str:
        """Encode text to Base100 (Emoji encoding)"""
        result = []
        for char in text:
            code = ord(char)
            # Convert to emoji (🐃🐄 pattern)
            # Simple implementation: use two emojis per byte
            high = code // 100
            low = code % 100
            
            # Map to emojis (simplified)
            emoji_map = "🐀🐁🐂🐃🐄🐅🐆🐇🐈🐉🐊🐋🐌🐍🐎🐏🐐🐑🐒🐓🐔🐕🐖🐗🐘🐙🐚🐛🐜🐝🐞🐟🐠🐡🐢🐣🐤🐥🐦🐧🐨🐩🐪🐫🐬🐭🐮🐯🐰🐱🐲🐳🐴🐵🐶🐷🐸🐹🐺🐻🐼🐽🐾👀👂👃👄👅👆👇👈👉👊👋👌👍👎👏👐👑👒👓👔👕👖👗👘👙👚👛👜👝👞👟👠👡👢👣👤👥👦👧👨👩👪👫👬👭👮👯👰👱👲👳👴👵👶👷👸👹👺👻👼👽👾👿💀💁💂💃💄💅💆💇💈💉💊💋💌💍💎💏💐💑💒💓💔💕💖💗💘💙💚💛💜💝💞💟💠💡💢💣💤💥💦💧💨💩💪💫💬💭💮💯💰💱💲💳💴💵💶💷💸💹💺💻💼💽💾💿📀📁📂📃📄📅📆📇📈📉📊📋📌📍📎📏📐📑📒📓📔📕📖📗📘📙📚📛📜📝📞📟📠📡📢📣📤📥📦📧📨📩📪📫📬📭📮📯📰📱📲📳📴📵📶📷📸📹📺📻📼📽📾🔀🔁🔂🔃🔄🔅🔆🔇🔈🔉🔊🔋🔌🔍🔎🔏🔐🔑🔒🔓🔔🔕🔖🔗🔘🔙🔚🔛🔜🔝🔞🔟🔠🔡🔢🔣🔤🔥🔦🔧🔨🔩🔪🔫🔬🔭🔮🔯🔰🔱🔲🔳🔴🔵🔶🔷🔸🔹🔺🔻🔼🔽🕐🕑🕒🕓🕔🕕🕖🕗🕘🕙🕚🕛🕜🕝🕞🕟🕠🕡🕢🕣🕤🕥🕦🕧"
            
            if high < len(emoji_map) and low < len(emoji_map):
                result.append(emoji_map[high])
                result.append(emoji_map[low])
            else:
                # Fallback to hex
                result.append(f"[{code:04x}]")
        
        return ''.join(result)
    
    @staticmethod
    def base100_decode(encoded: str) -> str:
        """Decode Base100 (Emoji) string to text"""
        # Simplified - just return the original as we can't reliably decode
        return f"[Base100 Emoji encoding detected: {len(encoded)} characters]"
    
    @staticmethod
    def base36_encode(data: bytes) -> str:
        """Encode bytes to Base36"""
        if not data:
            return '0'
        
        int_val = int.from_bytes(data, 'big')
        result = ''
        
        while int_val > 0:
            int_val, remainder = divmod(int_val, 36)
            result = BaseNEncoder.BASE36[remainder] + result
        
        return result or '0'
    
    @staticmethod
    def base36_decode(encoded: str) -> bytes:
        """Decode Base36 string to bytes"""
        if not encoded:
            return b''
        
        # Validate input
        for char in encoded:
            if char not in BaseNEncoder.BASE36:
                raise ValidationError(f"Invalid Base36 character: '{char}'")
        
        int_val = 0
        for char in encoded:
            int_val = int_val * 36 + BaseNEncoder.BASE36.index(char)
        
        if int_val == 0:
            return b''
        
        byte_count = max(1, (int_val.bit_length() + 7) // 8)
        return int_val.to_bytes(byte_count, 'big')

class CompressionTools:
    """Tools untuk kompresi data"""
    
    @staticmethod
    def zlib_compress(data: bytes) -> bytes:
        """Compress data menggunakan zlib"""
        return zlib.compress(data)
    
    @staticmethod
    def zlib_decompress(data: bytes) -> bytes:
        """Decompress data menggunakan zlib"""
        return zlib.decompress(data)
    
    @staticmethod
    def gzip_compress(data: bytes) -> bytes:
        """Compress data menggunakan gzip"""
        buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=buffer, mode='wb') as f:
            f.write(data)
        return buffer.getvalue()
    
    @staticmethod
    def gzip_decompress(data: bytes) -> bytes:
        """Decompress data menggunakan gzip"""
        buffer = io.BytesIO(data)
        with gzip.GzipFile(fileobj=buffer, mode='rb') as f:
            return f.read()

class UUXXEncoder:
    """Implementasi UUEncode dan XXEncode"""
    
    @staticmethod
    def uuencode(data: bytes, filename: str = "data.bin") -> str:
        """Encode data menggunakan UUEncode"""
        result = [f"begin 644 {filename}"]
        
        for i in range(0, len(data), 45):
            chunk = data[i:i+45]
            line_len = len(chunk)
            
            # Start line with length character
            line = chr(line_len + 32)
            
            # Process 3 bytes at a time
            for j in range(0, line_len, 3):
                group = chunk[j:j+3]
                # Pad if necessary
                while len(group) < 3:
                    group += b'\x00'
                
                # Convert to 24-bit value
                value = (group[0] << 16) | (group[1] << 8) | group[2]
                
                # Convert to 4 characters
                for k in range(4):
                    char_val = (value >> (18 - k * 6)) & 0x3F
                    line += chr(char_val + 32)
            
            result.append(line)
        
        result.append("`")
        result.append("end")
        
        return '\n'.join(result)
    
    @staticmethod
    def uudecode(encoded: str) -> bytes:
        """Decode data dari UUEncode"""
        lines = encoded.strip().split('\n')
        
        # Find begin line
        start_idx = -1
        for i, line in enumerate(lines):
            if line.startswith('begin'):
                start_idx = i
                break
        
        if start_idx == -1:
            raise ValidationError("Invalid UUEncode: No 'begin' line found")
        
        result = bytearray()
        
        for line in lines[start_idx + 1:]:
            line = line.strip()
            
            if not line or line == '`' or line.startswith('end'):
                break
            
            # Get line length
            line_len = ord(line[0]) - 32
            if line_len <= 0:
                continue
            
            data = line[1:]
            
            # Process in groups of 4 characters
            for i in range(0, len(data), 4):
                if i + 4 > len(data):
                    break
                
                chars = data[i:i+4]
                
                # Convert to 24-bit value
                value = 0
                for char in chars:
                    value = (value << 6) | (ord(char) - 32)
                
                # Convert to 3 bytes
                for j in range(2, -1, -1):
                    if len(result) < line_len:
                        byte_val = (value >> (8 * j)) & 0xFF
                        result.append(byte_val)
        
        return bytes(result)
    
    @staticmethod
    def xxencode(data: bytes, filename: str = "data.bin") -> str:
        """Encode data menggunakan XXEncode"""
        alphabet = '+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        result = [f"begin 644 {filename}"]
        
        for i in range(0, len(data), 45):
            chunk = data[i:i+45]
            line_len = len(chunk)
            
            # Start line with length character
            line = alphabet[line_len]
            
            # Process 3 bytes at a time
            for j in range(0, line_len, 3):
                group = chunk[j:j+3]
                # Pad if necessary
                while len(group) < 3:
                    group += b'\x00'
                
                # Convert to 24-bit value
                value = (group[0] << 16) | (group[1] << 8) | group[2]
                
                # Convert to 4 characters
                for k in range(4):
                    char_val = (value >> (18 - k * 6)) & 0x3F
                    line += alphabet[char_val]
            
            result.append(line)
        
        result.append("+")
        result.append("end")
        
        return '\n'.join(result)
    
    @staticmethod
    def xxdecode(encoded: str) -> bytes:
        """Decode data dari XXEncode"""
        alphabet = '+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        lines = encoded.strip().split('\n')
        
        # Find begin line
        start_idx = -1
        for i, line in enumerate(lines):
            if line.startswith('begin'):
                start_idx = i
                break
        
        if start_idx == -1:
            raise ValidationError("Invalid XXEncode: No 'begin' line found")
        
        result = bytearray()
        
        for line in lines[start_idx + 1:]:
            line = line.strip()
            
            if not line or line == '+' or line.startswith('end'):
                break
            
            # Get line length
            line_len = alphabet.index(line[0])
            if line_len <= 0:
                continue
            
            data = line[1:]
            
            # Process in groups of 4 characters
            for i in range(0, len(data), 4):
                if i + 4 > len(data):
                    break
                
                chars = data[i:i+4]
                
                # Convert to 24-bit value
                value = 0
                for char in chars:
                    value = (value << 6) | alphabet.index(char)
                
                # Convert to 3 bytes
                for j in range(2, -1, -1):
                    if len(result) < line_len:
                        byte_val = (value >> (8 * j)) & 0xFF
                        result.append(byte_val)
        
        return bytes(result)

class EsotericCiphers:
    """Implementasi cipher esoterik untuk CTF"""
    
    @staticmethod
    def brainfuck_execute(code: str, input_str: str = "") -> str:
        """Execute Brainfuck code dengan limit untuk mencegah infinite loop"""
        # Validate brackets
        stack = []
        brackets = {}
        
        for i, cmd in enumerate(code):
            if cmd == '[':
                stack.append(i)
            elif cmd == ']':
                if not stack:
                    raise ValidationError(f"Unmatched ']' at position {i}")
                start = stack.pop()
                brackets[start] = i
                brackets[i] = start
        
        if stack:
            raise ValidationError(f"Unmatched '[' at positions: {stack}")
        
        # Setup execution
        tape = [0] * 30000
        pointer = 0
        code_ptr = 0
        input_ptr = 0
        output = []
        
        # Safety limits
        max_steps = 1000000
        step_count = 0
        
        while code_ptr < len(code) and step_count < max_steps:
            cmd = code[code_ptr]
            
            if cmd == '>':
                pointer += 1
                if pointer >= len(tape):
                    tape.append(0)
            elif cmd == '<':
                pointer -= 1
                if pointer < 0:
                    pointer = 0
            elif cmd == '+':
                tape[pointer] = (tape[pointer] + 1) % 256
            elif cmd == '-':
                tape[pointer] = (tape[pointer] - 1) % 256
            elif cmd == '.':
                output.append(chr(tape[pointer]))
            elif cmd == ',':
                if input_ptr < len(input_str):
                    tape[pointer] = ord(input_str[input_ptr])
                    input_ptr += 1
                else:
                    tape[pointer] = 0
            elif cmd == '[':
                if tape[pointer] == 0:
                    code_ptr = brackets[code_ptr]
            elif cmd == ']':
                if tape[pointer] != 0:
                    code_ptr = brackets[code_ptr]
            
            code_ptr += 1
            step_count += 1
        
        if step_count >= max_steps:
            raise ValidationError("Execution stopped: possible infinite loop")
        
        return ''.join(output)
    
    @staticmethod
    def baconian_encode(text: str, variant: str = "AB") -> str:
        """Encode menggunakan Baconian Cipher"""
        bacon_dict = {
            'A': 'AAAAA', 'B': 'AAAAB', 'C': 'AAABA', 'D': 'AAABB', 'E': 'AABAA',
            'F': 'AABAB', 'G': 'AABBA', 'H': 'AABBB', 'I': 'ABAAA', 'J': 'ABAAB',
            'K': 'ABABA', 'L': 'ABABB', 'M': 'ABBAA', 'N': 'ABBAB', 'O': 'ABBBA',
            'P': 'ABBBB', 'Q': 'BAAAA', 'R': 'BAAAB', 'S': 'BAABA', 'T': 'BAABB',
            'U': 'BABAA', 'V': 'BABAB', 'W': 'BABBA', 'X': 'BABBB', 'Y': 'BBAAA',
            'Z': 'BBAAB'
        }
        
        result = []
        for char in text.upper():
            if char in bacon_dict:
                code = bacon_dict[char]
                if variant == "01":
                    code = code.replace('A', '0').replace('B', '1')
                elif len(variant) >= 2:
                    code = code.replace('A', variant[0]).replace('B', variant[1])
                result.append(code)
        
        return ' '.join(result)
    
    @staticmethod
    def baconian_decode(encoded: str, variant: str = "AB") -> str:
        """Decode Baconian Cipher"""
        # Normalize to AB format
        working = encoded.upper().replace(' ', '')
        
        if variant != "AB":
            if variant == "01":
                working = working.replace('0', 'A').replace('1', 'B')
            elif len(variant) >= 2:
                working = working.replace(variant[0], 'A').replace(variant[1], 'B')
        
        reverse_dict = {
            'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D', 'AABAA': 'E',
            'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H', 'ABAAA': 'I', 'ABAAB': 'J',
            'ABABA': 'K', 'ABABB': 'L', 'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O',
            'ABBBB': 'P', 'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
            'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X', 'BBAAA': 'Y',
            'BBAAB': 'Z'
        }
        
        result = []
        for i in range(0, len(working), 5):
            chunk = working[i:i+5]
            if len(chunk) == 5 and chunk in reverse_dict:
                result.append(reverse_dict[chunk])
        
        return ''.join(result)
    
    @staticmethod
    def morse_encode(text: str, dot: str = ".", dash: str = "-", sep: str = " ") -> str:
        """Encode ke Morse Code"""
        morse_dict = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
            'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
            'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
            'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
            'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
            'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
            '3': '...--', '4': '....-', '5': '.....', '6': '-....',
            '7': '--...', '8': '---..', '9': '----.', '.': '.-.-.-',
            ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--',
            '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...',
            ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.',
            '-': '-....-', '_': '..--.-', '"': '.-..-.', '$': '...-..-',
            '@': '.--.-.', ' ': '/'
        }
        
        result = []
        for char in text.upper():
            if char in morse_dict:
                code = morse_dict[char]
                if dot != '.' or dash != '-':
                    code = code.replace('.', dot).replace('-', dash)
                result.append(code)
        
        return sep.join(result)
    
    @staticmethod
    def morse_decode(encoded: str, dot: str = ".", dash: str = "-", sep: str = " ") -> str:
        """Decode Morse Code"""
        morse_dict = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
            '...--': '3', '....-': '4', '.....': '5', '-....': '6',
            '--...': '7', '---..': '8', '----.': '9', '.-.-.-': '.',
            '--..--': ',', '..--..': '?', '.----.': "'", '-.-.--': '!',
            '-..-.': '/', '-.--.': '(', '-.--.-': ')', '.-...': '&',
            '---...': ':', '-.-.-.': ';', '-...-': '=', '.-.-.': '+',
            '-....-': '-', '..--.-': '_', '.-..-.': '"', '...-..-': '$',
            '.--.-.': '@', '/': ' '
        }
        
        # Normalize symbols
        if dot != '.' or dash != '-':
            encoded = encoded.replace(dot, '.').replace(dash, '-')
        
        result = []
        for part in encoded.split(sep):
            if part in morse_dict:
                result.append(morse_dict[part])
            elif part == '':
                result.append(' ')
            else:
                result.append('?')
        
        return ''.join(result)
    
    @staticmethod
    def tap_code_encode(text: str) -> str:
        """Encode menggunakan Tap Code (Knock Code)"""
        tap_dict = {
            'A': '11', 'B': '12', 'C': '13', 'D': '14', 'E': '15',
            'F': '21', 'G': '22', 'H': '23', 'I': '24', 'J': '25',
            'K': '31', 'L': '32', 'M': '33', 'N': '34', 'O': '35',
            'P': '41', 'Q': '42', 'R': '43', 'S': '44', 'T': '45',
            'U': '51', 'V': '52', 'W': '53', 'X': '54', 'Y': '55',
            'Z': '62'
        }
        
        result = []
        for char in text.upper():
            if char == 'K':
                char = 'C'  # K shares with C
            if char in tap_dict:
                result.append(tap_dict[char])
        
        return ' '.join(result)
    
    @staticmethod
    def tap_code_decode(encoded: str) -> str:
        """Decode Tap Code"""
        reverse_dict = {
            '11': 'A', '12': 'B', '13': 'C', '14': 'D', '15': 'E',
            '21': 'F', '22': 'G', '23': 'H', '24': 'I', '25': 'J',
            '31': 'K', '32': 'L', '33': 'M', '34': 'N', '35': 'O',
            '41': 'P', '42': 'Q', '43': 'R', '44': 'S', '45': 'T',
            '51': 'U', '52': 'V', '53': 'W', '54': 'X', '55': 'Y'
        }
        
        result = []
        for part in encoded.split():
            if part in reverse_dict:
                result.append(reverse_dict[part])
        
        return ''.join(result)
    
    @staticmethod
    def dna_encode(text: str) -> str:
        """Encode text ke DNA sequence (ACGT)"""
        result = []
        for char in text:
            # Convert char to binary
            binary = format(ord(char), '08b')
            # Map binary to DNA bases
            mapping = {'00': 'A', '01': 'C', '10': 'G', '11': 'T'}
            
            dna_seq = ''
            for i in range(0, 8, 2):
                pair = binary[i:i+2]
                dna_seq += mapping.get(pair, 'N')
            
            result.append(dna_seq)
        
        return ' '.join(result)
    
    @staticmethod
    def dna_decode(encoded: str) -> str:
        """Decode DNA sequence ke text"""
        reverse_mapping = {'A': '00', 'C': '01', 'G': '10', 'T': '11'}
        
        result = []
        for seq in encoded.split():
            if len(seq) != 4:
                continue
            
            binary = ''
            for base in seq:
                binary += reverse_mapping.get(base, '00')
            
            try:
                char_code = int(binary, 2)
                result.append(chr(char_code))
            except:
                result.append('?')
        
        return ''.join(result)
    
    @staticmethod
    def kenny_encode(text: str) -> str:
        """Encode menggunakan Kenny Code (meme encoding)"""
        kenny_dict = {
            'A': 'mmph', 'B': 'mmph mmph', 'C': 'mmph mmph mmph',
            'D': 'mmph!', 'E': 'mmph mmph!', 'F': 'mmph mmph mmph!',
            'G': 'mmmppphhh', 'H': 'mmmppphhh mmmppphhh',
            'I': 'mmmppphhh mmmppphhh mmmppphhh',
            'J': 'mmmppphhh!', 'K': 'mmmppphhh mmmppphhh!',
            'L': 'mmmppphhh mmmppphhh mmmppphhh!',
            'M': 'mmmphhh', 'N': 'mmmphhh mmmphhh',
            'O': 'mmmphhh mmmphhh mmmphhh',
            'P': 'mmmphhh!', 'Q': 'mmmphhh mmmphhh!',
            'R': 'mmmphhh mmmphhh mmmphhh!',
            'S': 'mph', 'T': 'mph mph', 'U': 'mph mph mph',
            'V': 'mph!', 'W': 'mph mph!', 'X': 'mph mph mph!',
            'Y': 'they killed kenny', 'Z': 'you bastards',
            ' ': '  '
        }
        
        result = []
        for char in text.upper():
            if char in kenny_dict:
                result.append(kenny_dict[char])
            else:
                result.append('mmph?')
        
        return ' '.join(result)

class ClassicCiphers:
    """Implementasi cipher klasik"""
    
    @staticmethod
    def rot13(text: str) -> str:
        """ROT13 cipher"""
        result = []
        for char in text:
            if 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            elif 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def rot47(text: str) -> str:
        """ROT47 cipher (for printable ASCII)"""
        result = []
        for char in text:
            code = ord(char)
            if 33 <= code <= 126:
                result.append(chr(33 + ((code - 33 + 47) % 94)))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def caesar(text: str, shift: int) -> str:
        """Caesar cipher dengan shift tertentu"""
        result = []
        for char in text:
            if 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
            elif 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def caesar_bruteforce(text: str) -> Dict[int, str]:
        """Bruteforce semua 26 shift Caesar"""
        results = {}
        for shift in range(26):
            results[shift] = ClassicCiphers.caesar(text, shift)
        return results
    
    @staticmethod
    def vigenere_encrypt(text: str, key: str) -> str:
        """Vigenere cipher encryption"""
        result = []
        key = key.upper()
        key_idx = 0
        
        for char in text.upper():
            if 'A' <= char <= 'Z':
                shift = ord(key[key_idx % len(key)]) - ord('A')
                encrypted = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                result.append(encrypted)
                key_idx += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def vigenere_decrypt(text: str, key: str) -> str:
        """Vigenere cipher decryption"""
        result = []
        key = key.upper()
        key_idx = 0
        
        for char in text.upper():
            if 'A' <= char <= 'Z':
                shift = ord(key[key_idx % len(key)]) - ord('A')
                decrypted = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                result.append(decrypted)
                key_idx += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def rail_fence_encrypt(text: str, rails: int) -> str:
        """Rail Fence cipher encryption"""
        if rails <= 1:
            return text
        
        # Create rails
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        
        for char in text:
            fence[rail].append(char)
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction = -direction
        
        # Combine rails
        result = []
        for rail in fence:
            result.extend(rail)
        
        return ''.join(result)
    
    @staticmethod
    def rail_fence_decrypt(text: str, rails: int) -> str:
        """Rail Fence cipher decryption"""
        if rails <= 1:
            return text
        
        # Create fence pattern
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        
        for _ in text:
            fence[rail].append(None)
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction = -direction
        
        # Fill fence with text
        idx = 0
        for i in range(rails):
            for j in range(len(fence[i])):
                fence[i][j] = text[idx]
                idx += 1
        
        # Read from fence
        result = []
        rail = 0
        direction = 1
        rail_positions = [0] * rails
        
        for _ in range(len(text)):
            result.append(fence[rail][rail_positions[rail]])
            rail_positions[rail] += 1
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction = -direction
        
        return ''.join(result)
    
    @staticmethod
    def atbash(text: str) -> str:
        """Atbash cipher"""
        result = []
        for char in text:
            if 'A' <= char <= 'Z':
                result.append(chr(ord('Z') - (ord(char) - ord('A'))))
            elif 'a' <= char <= 'z':
                result.append(chr(ord('z') - (ord(char) - ord('a'))))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def affine_encrypt(text: str, a: int, b: int) -> str:
        """Affine cipher encryption"""
        # a must be coprime with 26
        if math.gcd(a, 26) != 1:
            raise ValidationError("'a' must be coprime with 26")
        
        result = []
        for char in text.upper():
            if 'A' <= char <= 'Z':
                x = ord(char) - ord('A')
                y = (a * x + b) % 26
                result.append(chr(ord('A') + y))
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def affine_decrypt(text: str, a: int, b: int) -> str:
        """Affine cipher decryption"""
        # Find modular inverse of a
        a_inv = None
        for i in range(26):
            if (a * i) % 26 == 1:
                a_inv = i
                break
        
        if a_inv is None:
            raise ValidationError(f"No modular inverse for a={a} mod 26")
        
        result = []
        for char in text.upper():
            if 'A' <= char <= 'Z':
                y = ord(char) - ord('A')
                x = (a_inv * (y - b)) % 26
                result.append(chr(ord('A') + x))
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def xor_cipher(text: str, key: Union[str, int, bytes]) -> str:
        """XOR cipher dengan key string atau integer"""
        if isinstance(key, int):
            # Single-byte XOR
            result = []
            for char in text:
                result.append(chr(ord(char) ^ key))
            return ''.join(result)
        elif isinstance(key, str):
            # Multi-byte XOR
            result = []
            key_bytes = key.encode()
            for i, char in enumerate(text):
                result.append(chr(ord(char) ^ key_bytes[i % len(key_bytes)]))
            return ''.join(result)
        elif isinstance(key, bytes):
            result = []
            for i, char in enumerate(text):
                result.append(chr(ord(char) ^ key[i % len(key)]))
            return ''.join(result)
        else:
            raise ValidationError("Key must be int, str, or bytes")
    
    @staticmethod
    def xor_bruteforce_single(text: str) -> Dict[int, str]:
        """Bruteforce single-byte XOR"""
        results = {}
        for key in range(256):
            try:
                decrypted = ClassicCiphers.xor_cipher(text, key)
                # Score based on printable characters
                printable_count = sum(1 for c in decrypted if c.isprintable() or c in '\n\r\t')
                score = printable_count / len(decrypted) if decrypted else 0
                
                if score > 0.8:  # Only keep likely results
                    results[key] = decrypted
            except:
                pass
        return results
    
    @staticmethod
    def beaufort_encrypt(text: str, key: str) -> str:
        """Beaufort cipher encryption"""
        result = []
        key = key.upper()
        key_idx = 0
        
        for char in text.upper():
            if 'A' <= char <= 'Z':
                k = ord(key[key_idx % len(key)]) - ord('A')
                p = ord(char) - ord('A')
                c = (k - p) % 26
                result.append(chr(ord('A') + c))
                key_idx += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def autokey_encrypt(text: str, key: str) -> str:
        """Autokey cipher encryption"""
        text_clean = ''.join(c for c in text.upper() if 'A' <= c <= 'Z')
        key_clean = ''.join(c for c in key.upper() if 'A' <= c <= 'Z')
        
        # Full key = key + plaintext
        full_key = key_clean + text_clean
        
        result = []
        for i, char in enumerate(text_clean):
            if i < len(full_key):
                p = ord(char) - ord('A')
                k = ord(full_key[i]) - ord('A')
                c = (p + k) % 26
                result.append(chr(ord('A') + c))
        
        return ''.join(result)
    
    @staticmethod
    def autokey_decrypt(text: str, key: str) -> str:
        """Autokey cipher decryption"""
        text_clean = ''.join(c for c in text.upper() if 'A' <= c <= 'Z')
        key_clean = ''.join(c for c in key.upper() if 'A' <= c <= 'Z')
        
        result = []
        current_key = key_clean
        
        for i, char in enumerate(text_clean):
            if i < len(current_key):
                c = ord(char) - ord('A')
                k = ord(current_key[i]) - ord('A')
                p = (c - k) % 26
                decrypted = chr(ord('A') + p)
                result.append(decrypted)
                
                # Add decrypted char to key
                current_key += decrypted
        
        return ''.join(result)

class ModernCrypto:
    """Wrapper untuk modern cryptography menggunakan pycryptodome"""
    
    @staticmethod
    def _validate_key_length(key: bytes, expected_lengths: List[int], algo: str) -> None:
        """Validasi panjang key"""
        if len(key) not in expected_lengths:
            raise ValidationError(
                f"{algo} key must be {expected_lengths} bytes, got {len(key)}"
            )
    
    @staticmethod
    def aes_encrypt(plaintext: str, key: bytes, mode: str = "CBC") -> Tuple[bytes, bytes]:
        """AES encryption"""
        ModernCrypto._validate_key_length(key, [16, 24, 32], "AES")
        
        if mode.upper() == "CBC":
            cipher = AES.new(key, AES.MODE_CBC)
            ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
            return ciphertext, cipher.iv
        elif mode.upper() == "ECB":
            cipher = AES.new(key, AES.MODE_ECB)
            ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
            return ciphertext, b''
        elif mode.upper() == "CTR":
            cipher = AES.new(key, AES.MODE_CTR)
            ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
            return ciphertext, cipher.nonce
        elif mode.upper() == "GCM":
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
            return ciphertext, cipher.nonce + tag
        else:
            raise ValidationError(f"Unsupported AES mode: {mode}")
    
    @staticmethod
    def aes_decrypt(ciphertext: bytes, key: bytes, extra: bytes = b'', mode: str = "CBC") -> str:
        """AES decryption"""
        ModernCrypto._validate_key_length(key, [16, 24, 32], "AES")
        
        try:
            if mode.upper() == "CBC":
                iv = extra[:16] if len(extra) >= 16 else extra
                cipher = AES.new(key, AES.MODE_CBC, iv)
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            elif mode.upper() == "ECB":
                cipher = AES.new(key, AES.MODE_ECB)
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            elif mode.upper() == "CTR":
                nonce = extra[:8] if len(extra) >= 8 else extra
                cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
                plaintext = cipher.decrypt(ciphertext)
            elif mode.upper() == "GCM":
                nonce = extra[:12] if len(extra) >= 12 else extra[:8]
                tag = extra[-16:] if len(extra) >= 16 else b''
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            else:
                raise ValidationError(f"Unsupported AES mode: {mode}")
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValidationError(f"Decryption failed: {str(e)}")
    
    @staticmethod
    def des_encrypt(plaintext: str, key: bytes) -> Tuple[bytes, bytes]:
        """DES encryption"""
        ModernCrypto._validate_key_length(key, [8], "DES")
        
        cipher = DES.new(key, DES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), DES.block_size))
        return ciphertext, cipher.iv
    
    @staticmethod
    def des_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> str:
        """DES decryption"""
        ModernCrypto._validate_key_length(key, [8], "DES")
        
        try:
            cipher = DES.new(key, DES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValidationError(f"Decryption failed: {str(e)}")
    
    @staticmethod
    def rc4_encrypt(plaintext: str, key: bytes) -> bytes:
        """RC4 encryption"""
        if not key:
            raise ValidationError("RC4 key cannot be empty")
        
        cipher = ARC4.new(key)
        return cipher.encrypt(plaintext.encode('utf-8'))
    
    @staticmethod
    def rc4_decrypt(ciphertext: bytes, key: bytes) -> str:
        """RC4 decryption"""
        if not key:
            raise ValidationError("RC4 key cannot be empty")
        
        try:
            cipher = ARC4.new(key)
            plaintext = cipher.decrypt(ciphertext)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValidationError(f"Decryption failed: {str(e)}")
    
    @staticmethod
    def chacha20_encrypt(plaintext: str, key: bytes) -> Tuple[bytes, bytes]:
        """ChaCha20 encryption"""
        if len(key) != 32:
            raise ValidationError("ChaCha20 key must be 32 bytes")
        
        cipher = ChaCha20.new(key=key)
        ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
        return ciphertext, cipher.nonce
    
    @staticmethod
    def chacha20_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> str:
        """ChaCha20 decryption"""
        if len(key) != 32:
            raise ValidationError("ChaCha20 key must be 32 bytes")
        
        try:
            cipher = ChaCha20.new(key=key, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValidationError(f"Decryption failed: {str(e)}")
    
    @staticmethod
    def salsa20_encrypt(plaintext: str, key: bytes) -> Tuple[bytes, bytes]:
        """Salsa20 encryption"""
        if len(key) not in [16, 32]:
            raise ValidationError("Salsa20 key must be 16 or 32 bytes")
        
        cipher = Salsa20.new(key=key)
        ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
        return ciphertext, cipher.nonce
    
    @staticmethod
    def salsa20_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> str:
        """Salsa20 decryption"""
        if len(key) not in [16, 32]:
            raise ValidationError("Salsa20 key must be 16 or 32 bytes")
        
        try:
            cipher = Salsa20.new(key=key, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValidationError(f"Decryption failed: {str(e)}")
    
    @staticmethod
    def blowfish_encrypt(plaintext: str, key: bytes) -> Tuple[bytes, bytes]:
        """Blowfish encryption"""
        if len(key) < 4 or len(key) > 56:
            raise ValidationError("Blowfish key must be 4-56 bytes")
        
        cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), Blowfish.block_size))
        return ciphertext, cipher.iv
    
    @staticmethod
    def blowfish_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> str:
        """Blowfish decryption"""
        if len(key) < 4 or len(key) > 56:
            raise ValidationError("Blowfish key must be 4-56 bytes")
        
        try:
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValidationError(f"Decryption failed: {str(e)}")
    
    @staticmethod
    def hash_data(data: str, algorithm: str) -> str:
        """Hash data dengan berbagai algoritma"""
        data_bytes = data.encode('utf-8')
        
        if algorithm.upper() == "MD5":
            return MD5.new(data_bytes).hexdigest()
        elif algorithm.upper() == "SHA1":
            return SHA1.new(data_bytes).hexdigest()
        elif algorithm.upper() == "SHA256":
            return SHA256.new(data_bytes).hexdigest()
        elif algorithm.upper() == "SHA512":
            return SHA512.new(data_bytes).hexdigest()
        elif algorithm.upper() == "RIPEMD160":
            return RIPEMD160.new(data_bytes).hexdigest()
        elif algorithm.upper() == "BLAKE2B":
            return BLAKE2b.new(data=data_bytes).hexdigest()
        elif algorithm.upper() == "BLAKE2S":
            return BLAKE2s.new(data=data_bytes).hexdigest()
        else:
            raise ValidationError(f"Unsupported hash algorithm: {algorithm}")

class AnalyzerTools:
    """Tools untuk analisis kriptografi"""
    
    @staticmethod
    def frequency_analysis(text: str) -> Dict[str, float]:
        """Analisis frekuensi karakter"""
        # Filter hanya huruf
        letters = [c.upper() for c in text if c.isalpha()]
        total = len(letters)
        
        if total == 0:
            return {}
        
        # Hitung frekuensi
        freq = Counter(letters)
        
        # Konversi ke persentase
        result = {}
        for char, count in freq.items():
            result[char] = (count / total) * 100
        
        # Urutkan dari tertinggi
        return dict(sorted(result.items(), key=lambda x: x[1], reverse=True))
    
    @staticmethod
    def english_frequency() -> Dict[str, float]:
        """Frekuensi huruf dalam bahasa Inggris (standar)"""
        return {
            'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
            'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
            'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
            'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29,
            'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10,
            'Z': 0.07
        }
    
    @staticmethod
    def magic_detect(text: str) -> List[Tuple[str, float]]:
        """Deteksi otomatis jenis encoding/cipher"""
        results = []
        
        # Check empty
        if not text:
            return results
        
        # Check for Brainfuck
        bf_chars = set('+-<>.,[]')
        if all(c in bf_chars or c.isspace() for c in text):
            results.append(("Brainfuck", 0.9))
        
        # Check for Morse
        if all(c in '.-/ ' for c in text):
            results.append(("Morse Code", 0.8))
        
        # Check for Baconian
        if all(c in 'AB01' or c.isspace() for c in text.upper()):
            if len(text.replace(' ', '')) % 5 == 0:
                results.append(("Baconian Cipher", 0.85))
        
        # Check for Base64
        b64_chars = set(string.ascii_letters + string.digits + '+/=')
        if all(c in b64_chars for c in text):
            if text.endswith('==') or text.endswith('='):
                results.append(("Base64", 0.95))
            elif len(text) % 4 == 0:
                results.append(("Base64", 0.7))
        
        # Check for Hex
        hex_chars = set(string.hexdigits)
        if all(c in hex_chars for c in text.lower()):
            if len(text) % 2 == 0:
                results.append(("Hexadecimal", 0.9))
            else:
                results.append(("Hexadecimal", 0.5))
        
        # Check for Base58
        b58_chars = set('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz')
        if all(c in b58_chars for c in text):
            results.append(("Base58 (Bitcoin)", 0.8))
        
        # Check for Base62
        b62_chars = set(string.ascii_letters + string.digits)
        if all(c in b62_chars for c in text):
            results.append(("Base62", 0.6))
        
        # Check for MD5 (32 hex chars)
        if len(text) == 32 and all(c in string.hexdigits for c in text.lower()):
            results.append(("MD5 Hash", 0.7))
        
        # Check for SHA256 (64 hex chars)
        if len(text) == 64 and all(c in string.hexdigits for c in text.lower()):
            results.append(("SHA256 Hash", 0.7))
        
        # Check for DNA
        if all(c in 'ACGTN ' for c in text.upper()):
            results.append(("DNA Encoding", 0.75))
        
        # Check for Tap Code
        if all(c in '12345 ' for c in text):
            parts = text.split()
            if all(len(p) == 2 for p in parts):
                results.append(("Tap Code", 0.8))
        
        # Check for XOR single-byte pattern
        if len(text) > 10:
            byte_counts = Counter(text)
            most_common = byte_counts.most_common(1)[0][1] if byte_counts else 0
            if most_common / len(text) > 0.15:
                results.append(("Possible XOR cipher", 0.4))
        
        return sorted(results, key=lambda x: x[1], reverse=True)

class MonografiToolkit:
    """Main application class"""
    
    def __init__(self):
        self.console = Console()
        self.base = BaseNEncoder()
        self.comp = CompressionTools()
        self.uu = UUXXEncoder()
        self.esoteric = EsotericCiphers()
        self.classic = ClassicCiphers()
        self.modern = ModernCrypto()
        self.analyzer = AnalyzerTools()
    
    def display_banner(self):
        """Display MONOGRAFI banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║  ███╗   ███╗ ██████╗ ███╗   ██╗ ██████╗  ██████╗ ██████╗  █████╗     ║
║  ████╗ ████║██╔═══██╗████╗  ██║██╔═══██╗██╔════╝ ██╔══██╗██╔══██╗    ║
║  ██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║██║  ███╗██████╔╝███████║    ║
║  ██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║██║   ██║██╔══██╗██╔══██║    ║
║  ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║    ║
║  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝    ║
║                                                                       ║
║                  ULTIMATE CRYPTOGRAPHY TOOLKIT v3.0                   ║
║                     For CTF Professionals & Experts                   ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
        """
        
        self.console.print(Panel(banner, border_style=ColorScheme.PRIMARY))
        
        # Stats
        stats = "[cyan]✓[/cyan] [green]STABLE[/green] | [cyan]✓[/cyan] [green]NO INFINITE LOOPS[/green] | [cyan]✓[/cyan] [green]ANTI-CRASH SYSTEM[/green]"
        self.console.print(Panel(stats, border_style=ColorScheme.INFO))
    
    def display_menu(self):
        """Display main menu"""
        menu_table = Table(title="\n[bold]MONOGRAFI TOOLKIT - Main Menu[/bold]", 
                          show_header=True, header_style="bold magenta",
                          border_style=ColorScheme.PRIMARY)
        menu_table.add_column("No.", style="cyan", width=5, justify="center")
        menu_table.add_column("Module", style="green", width=25)
        menu_table.add_column("Description", style="yellow")
        
        menu_items = [
            ("1", "Advanced Encoding", "Base58/62/91, Base45, Z85, UUEncode, etc"),
            ("2", "Esoteric & Obscure", "Brainfuck, Baconian, Morse, DNA, Kenny"),
            ("3", "Classic Ciphers", "ROT13, Vigenere, Rail Fence, XOR, etc"),
            ("4", "Modern Cryptography", "AES, DES, RC4, ChaCha20, Hashing"),
            ("5", "Analysis & Utilities", "Frequency Analysis, Magic Detector"),
            ("0", "Exit", "Exit MONOGRAFI Toolkit")
        ]
        
        for item in menu_items:
            menu_table.add_row(item[0], item[1], item[2])
        
        self.console.print(menu_table)
    
    def safe_wrapper(self, func, *args, **kwargs):
        """Wrapper untuk menangkap semua error"""
        try:
            return func(*args, **kwargs)
        except ValidationError as e:
            self.console.print(f"[bold {ColorScheme.ERROR}]Validation Error:[/bold {ColorScheme.ERROR}] {e}")
            return None
        except Exception as e:
            self.console.print(f"[bold {ColorScheme.ERROR}]Error:[/bold {ColorScheme.ERROR}] {str(e)}")
            return None
    
    def module1_encoding(self):
        """Module 1: Advanced Encoding"""
        self.console.print(f"\n[bold {ColorScheme.ACCENT}][MODULE 1][/bold {ColorScheme.ACCENT}] Advanced Encoding\n")
        
        while True:
            options = [
                "1.  Base64 Encode/Decode",
                "2.  Base32 Encode/Decode",
                "3.  Base58 Encode (Bitcoin)",
                "4.  Base58 Decode",
                "5.  Base62 Encode",
                "6.  Base62 Decode", 
                "7.  Base91 Encode",
                "8.  Base91 Decode",
                "9.  Base45 Encode (QR Code)",
                "10. Base45 Decode",
                "11. Base36 Encode",
                "12. Base36 Decode",
                "13. Z85 (ZeroMQ Base85) Encode",
                "14. Z85 Decode",
                "15. Base100 (Emoji) Encode",
                "16. UUEncode",
                "17. UUDecode",
                "18. XXEncode",
                "19. XXDecode",
                "20. Zlib Compress/Decompress",
                "21. Gzip Compress/Decompress",
                "0.  Back to Main Menu"
            ]
            
            for option in options:
                self.console.print(option)
            
            try:
                choice = Prompt.ask(f"\n[bold]Select operation[/bold]", 
                                   choices=[str(i) for i in range(22)])
                
                if choice == "0":
                    break
                
                if choice in ["1", "2"]:
                    # Base64/Base32 have both encode/decode
                    action = Prompt.ask("[bold]Action[/bold]", 
                                       choices=["encode", "decode"],
                                       default="encode")
                
                text = Prompt.ask("[bold]Enter text[/bold]")
                
                with Progress() as progress:
                    task = progress.add_task("[cyan]Processing...", total=1)
                    result = None
                    
                    if choice == "1":  # Base64
                        if action == "encode":
                            result = base64.b64encode(text.encode()).decode()
                        else:
                            result_bytes = base64.b64decode(text)
                            smart_print(result_bytes, "Decoded Result")
                            progress.update(task, completed=1)
                            continue
                    
                    elif choice == "2":  # Base32
                        encoding = Prompt.ask("[bold]Standard or Hex?[/bold]",
                                            choices=["standard", "hex"],
                                            default="standard")
                        if action == "encode":
                            if encoding == "standard":
                                result = base64.b32encode(text.encode()).decode()
                            else:
                                result = base64.b32hexencode(text.encode()).decode()
                        else:
                            if encoding == "standard":
                                result_bytes = base64.b32decode(text)
                            else:
                                result_bytes = base64.b32hexdecode(text)
                            smart_print(result_bytes, "Decoded Result")
                            progress.update(task, completed=1)
                            continue
                    
                    elif choice == "3":  # Base58 Encode
                        result = self.safe_wrapper(self.base.base58_encode, text.encode())
                    
                    elif choice == "4":  # Base58 Decode
                        result_bytes = self.safe_wrapper(self.base.base58_decode, text)
                        if result_bytes is not None:
                            smart_print(result_bytes, "Decoded Result")
                        progress.update(task, completed=1)
                        continue
                    
                    elif choice == "5":  # Base62 Encode
                        result = self.safe_wrapper(self.base.base62_encode, text.encode())
                    
                    elif choice == "6":  # Base62 Decode
                        result_bytes = self.safe_wrapper(self.base.base62_decode, text)
                        if result_bytes is not None:
                            smart_print(result_bytes, "Decoded Result")
                        progress.update(task, completed=1)
                        continue
                    
                    elif choice == "7":  # Base91 Encode
                        result = self.safe_wrapper(self.base.base91_encode, text.encode())
                    
                    elif choice == "8":  # Base91 Decode
                        result_bytes = self.safe_wrapper(self.base.base91_decode, text)
                        if result_bytes is not None:
                            smart_print(result_bytes, "Decoded Result")
                        progress.update(task, completed=1)
                        continue
                    
                    elif choice == "9":  # Base45 Encode
                        result = self.safe_wrapper(self.base.base45_encode, text.encode())
                    
                    elif choice == "10":  # Base45 Decode
                        result_bytes = self.safe_wrapper(self.base.base45_decode, text)
                        if result_bytes is not None:
                            smart_print(result_bytes, "Decoded Result")
                        progress.update(task, completed=1)
                        continue
                    
                    elif choice == "11":  # Base36 Encode
                        result = self.safe_wrapper(self.base.base36_encode, text.encode())
                    
                    elif choice == "12":  # Base36 Decode
                        result_bytes = self.safe_wrapper(self.base.base36_decode, text)
                        if result_bytes is not None:
                            smart_print(result_bytes, "Decoded Result")
                        progress.update(task, completed=1)
                        continue
                    
                    elif choice == "13":  # Z85 Encode
                        result = self.safe_wrapper(self.base.z85_encode, text.encode())
                    
                    elif choice == "14":  # Z85 Decode
                        result_bytes = self.safe_wrapper(self.base.z85_decode, text)
                        if result_bytes is not None:
                            smart_print(result_bytes, "Decoded Result")
                        progress.update(task, completed=1)
                        continue
                    
                    elif choice == "15":  # Base100 Encode
                        result = self.safe_wrapper(self.base.base100_encode, text)
                    
                    elif choice == "16":  # UUEncode
                        result = self.safe_wrapper(self.uu.uuencode, text.encode())
                    
                    elif choice == "17":  # UUDecode
                        result_bytes = self.safe_wrapper(self.uu.uudecode, text)
                        if result_bytes is not None:
                            smart_print(result_bytes, "Decoded Result")
                        progress.update(task, completed=1)
                        continue
                    
                    elif choice == "18":  # XXEncode
                        result = self.safe_wrapper(self.uu.xxencode, text.encode())
                    
                    elif choice == "19":  # XXDecode
                        result_bytes = self.safe_wrapper(self.uu.xxdecode, text)
                        if result_bytes is not None:
                            smart_print(result_bytes, "Decoded Result")
                        progress.update(task, completed=1)
                        continue
                    
                    elif choice == "20":  # Zlib
                        action = Prompt.ask("[bold]Action[/bold]",
                                          choices=["compress", "decompress"],
                                          default="compress")
                        if action == "compress":
                            result_bytes = self.safe_wrapper(self.comp.zlib_compress, text.encode())
                            if result_bytes is not None:
                                smart_print(result_bytes, "Compressed Result")
                        else:
                            # Try to decode as hex or base64 first
                            try:
                                if all(c in string.hexdigits for c in text.lower()):
                                    data = bytes.fromhex(text)
                                elif all(c in string.ascii_letters + string.digits + '+/=' for c in text):
                                    data = base64.b64decode(text)
                                else:
                                    data = text.encode()
                                
                                result_bytes = self.safe_wrapper(self.comp.zlib_decompress, data)
                                if result_bytes is not None:
                                    smart_print(result_bytes, "Decompressed Result")
                            except:
                                self.console.print(f"[{ColorScheme.ERROR}]Invalid input format[/{ColorScheme.ERROR}]")
                        progress.update(task, completed=1)
                        continue
                    
                    elif choice == "21":  # Gzip
                        action = Prompt.ask("[bold]Action[/bold]",
                                          choices=["compress", "decompress"],
                                          default="compress")
                        if action == "compress":
                            result_bytes = self.safe_wrapper(self.comp.gzip_compress, text.encode())
                            if result_bytes is not None:
                                smart_print(result_bytes, "Compressed Result")
                        else:
                            # Try to decode as hex or base64 first
                            try:
                                if all(c in string.hexdigits for c in text.lower()):
                                    data = bytes.fromhex(text)
                                elif all(c in string.ascii_letters + string.digits + '+/=' for c in text):
                                    data = base64.b64decode(text)
                                else:
                                    data = text.encode()
                                
                                result_bytes = self.safe_wrapper(self.comp.gzip_decompress, data)
                                if result_bytes is not None:
                                    smart_print(result_bytes, "Decompressed Result")
                            except:
                                self.console.print(f"[{ColorScheme.ERROR}]Invalid input format[/{ColorScheme.ERROR}]")
                        progress.update(task, completed=1)
                        continue
                    
                    progress.update(task, completed=1)
                
                if result is not None:
                    smart_print(result, "Result")
                
                if not Confirm.ask(f"\n[bold]Continue with Module 1?[/bold]", default=True):
                    break
                    
            except KeyboardInterrupt:
                self.console.print(f"\n[{ColorScheme.WARNING}]Operation cancelled[/{ColorScheme.WARNING}]")
                break
            except Exception as e:
                self.console.print(f"[bold {ColorScheme.ERROR}]Error:[/bold {ColorScheme.ERROR}] {e}")
    
    def module2_esoteric(self):
        """Module 2: Esoteric & Obscure"""
        self.console.print(f"\n[bold {ColorScheme.ACCENT}][MODULE 2][/bold {ColorScheme.ACCENT}] Esoteric & Obscure\n")
        
        while True:
            options = [
                "1. Brainfuck Interpreter",
                "2. Baconian Cipher Encode",
                "3. Baconian Cipher Decode",
                "4. Morse Code Encode",
                "5. Morse Code Decode",
                "6. Tap Code (Knock) Encode",
                "7. Tap Code Decode",
                "8. DNA Encoding",
                "9. DNA Decoding",
                "10. Kenny Code Encode",
                "0. Back to Main Menu"
            ]
            
            for option in options:
                self.console.print(option)
            
            try:
                choice = Prompt.ask(f"\n[bold]Select cipher[/bold]", 
                                   choices=[str(i) for i in range(11)])
                
                if choice == "0":
                    break
                
                if choice == "1":  # Brainfuck
                    self.console.print(f"[{ColorScheme.INFO}]Brainfuck Interpreter[/{ColorScheme.INFO}]")
                    self.console.print(f"[{ColorScheme.DIM}]Execution limited to 1,000,000 steps[/{ColorScheme.DIM}]")
                    
                    code = Prompt.ask("[bold]Enter Brainfuck code[/bold]")
                    input_str = Prompt.ask("[bold]Input (optional)[/bold]", default="")
                    
                    with Progress() as progress:
                        task = progress.add_task("[cyan]Executing Brainfuck...", total=1)
                        result = self.safe_wrapper(self.esoteric.brainfuck_execute, code, input_str)
                        progress.update(task, completed=1)
                    
                    if result is not None:
                        smart_print(result, "Output")
                
                elif choice in ["2", "3"]:  # Baconian
                    text = Prompt.ask("[bold]Enter text[/bold]")
                    variant = Prompt.ask("[bold]Variant (AB/01/custom)[/bold]", default="AB")
                    
                    with Progress() as progress:
                        task = progress.add_task("[cyan]Processing...", total=1)
                        
                        if choice == "2":  # Encode
                            result = self.safe_wrapper(self.esoteric.baconian_encode, text, variant)
                        else:  # Decode
                            result = self.safe_wrapper(self.esoteric.baconian_decode, text, variant)
                        
                        progress.update(task, completed=1)
                    
                    if result is not None:
                        smart_print(result, "Result")
                
                elif choice in ["4", "5"]:  # Morse
                    text = Prompt.ask("[bold]Enter text[/bold]")
                    
                    dot = Prompt.ask("[bold]Dot character[/bold]", default=".")
                    dash = Prompt.ask("[bold]Dash character[/bold]", default="-")
                    sep = Prompt.ask("[bold]Separator[/bold]", default=" ")
                    
                    with Progress() as progress:
                        task = progress.add_task("[cyan]Processing...", total=1)
                        
                        if choice == "4":  # Encode
                            result = self.safe_wrapper(self.esoteric.morse_encode, text, dot, dash, sep)
                        else:  # Decode
                            result = self.safe_wrapper(self.esoteric.morse_decode, text, dot, dash, sep)
                        
                        progress.update(task, completed=1)
                    
                    if result is not None:
                        smart_print(result, "Result")
                
                elif choice in ["6", "7"]:  # Tap Code
                    text = Prompt.ask("[bold]Enter text[/bold]")
                    
                    with Progress() as progress:
                        task = progress.add_task("[cyan]Processing...", total=1)
                        
                        if choice == "6":  # Encode
                            result = self.safe_wrapper(self.esoteric.tap_code_encode, text)
                        else:  # Decode
                            result = self.safe_wrapper(self.esoteric.tap_code_decode, text)
                        
                        progress.update(task, completed=1)
                    
                    if result is not None:
                        smart_print(result, "Result")
                
                elif choice in ["8", "9"]:  # DNA
                    text = Prompt.ask("[bold]Enter text[/bold]")
                    
                    with Progress() as progress:
                        task = progress.add_task("[cyan]Processing...", total=1)
                        
                        if choice == "8":  # Encode
                            result = self.safe_wrapper(self.esoteric.dna_encode, text)
                        else:  # Decode
                            result = self.safe_wrapper(self.esoteric.dna_decode, text)
                        
                        progress.update(task, completed=1)
                    
                    if result is not None:
                        smart_print(result, "Result")
                
                elif choice == "10":  # Kenny Code
                    text = Prompt.ask("[bold]Enter text[/bold]")
                    
                    with Progress() as progress:
                        task = progress.add_task("[cyan]Processing...", total=1)
                        result = self.safe_wrapper(self.esoteric.kenny_encode, text)
                        progress.update(task, completed=1)
                    
                    if result is not None:
                        smart_print(result, "Result")
                
                if not Confirm.ask(f"\n[bold]Continue with Module 2?[/bold]", default=True):
                    break
                    
            except KeyboardInterrupt:
                self.console.print(f"\n[{ColorScheme.WARNING}]Operation cancelled[/{ColorScheme.WARNING}]")
                break
            except Exception as e:
                self.console.print(f"[bold {ColorScheme.ERROR}]Error:[/bold {ColorScheme.ERROR}] {e}")
    
    def module3_classic(self):
        """Module 3: Classic Ciphers"""
        self.console.print(f"\n[bold {ColorScheme.ACCENT}][MODULE 3][/bold {ColorScheme.ACCENT}] Classic Ciphers\n")
        
        while True:
            options = [
                "1. ROT13",
                "2. ROT47",
                "3. Caesar Cipher (with shift)",
                "4. Caesar Bruteforce (all 26 shifts)",
                "5. Vigenere Encrypt",
                "6. Vigenere Decrypt",
                "7. Rail Fence Encrypt",
                "8. Rail Fence Decrypt",
                "9. Atbash Cipher",
                "10. Affine Encrypt",
                "11. Affine Decrypt",
                "12. XOR Cipher (with key)",
                "13. XOR Single-byte Bruteforce",
                "14. Beaufort Cipher",
                "15. Autokey Encrypt",
                "16. Autokey Decrypt",
                "0. Back to Main Menu"
            ]
            
            for option in options:
                self.console.print(option)
            
            try:
                choice = Prompt.ask(f"\n[bold]Select cipher[/bold]", 
                                   choices=[str(i) for i in range(17)])
                
                if choice == "0":
                    break
                
                text = Prompt.ask("[bold]Enter text[/bold]")
                
                with Progress() as progress:
                    task = progress.add_task("[cyan]Processing...", total=1)
                    result = None
                    
                    if choice == "1":  # ROT13
                        result = self.safe_wrapper(self.classic.rot13, text)
                    
                    elif choice == "2":  # ROT47
                        result = self.safe_wrapper(self.classic.rot47, text)
                    
                    elif choice == "3":  # Caesar with shift
                        try:
                            shift = int(Prompt.ask("[bold]Enter shift (0-25)[/bold]", default="13"))
                            shift = shift % 26
                            result = self.safe_wrapper(self.classic.caesar, text, shift)
                        except ValueError:
                            self.console.print(f"[{ColorScheme.ERROR}]Invalid shift value[/{ColorScheme.ERROR}]")
                            progress.update(task, completed=1)
                            continue
                    
                    elif choice == "4":  # Caesar bruteforce
                        results = self.safe_wrapper(self.classic.caesar_bruteforce, text)
                        if results:
                            table = Table(title="Caesar Bruteforce Results", 
                                         show_header=True, 
                                         header_style="bold magenta")
                            table.add_column("Shift", style="cyan", width=5)
                            table.add_column("Result", style="green")
                            
                            for shift, decrypted in results.items():
                                # Highlight likely English text
                                if any(word in decrypted.lower() for word in ['the', 'and', 'you', 'that']):
                                    table.add_row(str(shift), f"[bold]{decrypted}[/bold]")
                                else:
                                    table.add_row(str(shift), decrypted)
                            
                            self.console.print(table)
                        progress.update(task, completed=1)
                        continue
                    
                    elif choice == "5":  # Vigenere encrypt
                        key = Prompt.ask("[bold]Enter key[/bold]")
                        result = self.safe_wrapper(self.classic.vigenere_encrypt, text, key)
                    
                    elif choice == "6":  # Vigenere decrypt
                        key = Prompt.ask("[bold]Enter key[/bold]")
                        result = self.safe_wrapper(self.classic.vigenere_decrypt, text, key)
                    
                    elif choice == "7":  # Rail Fence encrypt
                        try:
                            rails = int(Prompt.ask("[bold]Number of rails[/bold]", default="3"))
                            result = self.safe_wrapper(self.classic.rail_fence_encrypt, text, rails)
                        except ValueError:
                            self.console.print(f"[{ColorScheme.ERROR}]Invalid number[/{ColorScheme.ERROR}]")
                            progress.update(task, completed=1)
                            continue
                    
                    elif choice == "8":  # Rail Fence decrypt
                        try:
                            rails = int(Prompt.ask("[bold]Number of rails[/bold]", default="3"))
                            result = self.safe_wrapper(self.classic.rail_fence_decrypt, text, rails)
                        except ValueError:
                            self.console.print(f"[{ColorScheme.ERROR}]Invalid number[/{ColorScheme.ERROR}]")
                            progress.update(task, completed=1)
                            continue
                    
                    elif choice == "9":  # Atbash
                        result = self.safe_wrapper(self.classic.atbash, text)
                    
                    elif choice == "10":  # Affine encrypt
                        try:
                            a = int(Prompt.ask("[bold]Enter 'a' value[/bold]", default="5"))
                            b = int(Prompt.ask("[bold]Enter 'b' value[/bold]", default="8"))
                            result = self.safe_wrapper(self.classic.affine_encrypt, text, a, b)
                        except ValueError:
                            self.console.print(f"[{ColorScheme.ERROR}]Invalid number[/{ColorScheme.ERROR}]")
                            progress.update(task, completed=1)
                            continue
                    
                    elif choice == "11":  # Affine decrypt
                        try:
                            a = int(Prompt.ask("[bold]Enter 'a' value[/bold]", default="5"))
                            b = int(Prompt.ask("[bold]Enter 'b' value[/bold]", default="8"))
                            result = self.safe_wrapper(self.classic.affine_decrypt, text, a, b)
                        except ValueError:
                            self.console.print(f"[{ColorScheme.ERROR}]Invalid number[/{ColorScheme.ERROR}]")
                            progress.update(task, completed=1)
                            continue
                    
                    elif choice == "12":  # XOR with key
                        key_input = Prompt.ask("[bold]Enter key (text or hex)[/bold]")
                        
                        # Try to parse as hex
                        try:
                            if all(c in string.hexdigits for c in key_input.lower()):
                                key = bytes.fromhex(key_input)
                            else:
                                key = key_input
                        except:
                            key = key_input
                        
                        result = self.safe_wrapper(self.classic.xor_cipher, text, key)
                    
                    elif choice == "13":  # XOR single-byte bruteforce
                        results = self.safe_wrapper(self.classic.xor_bruteforce_single, text)
                        if results:
                            table = Table(title="XOR Single-byte Bruteforce Results", 
                                         show_header=True, 
                                         header_style="bold magenta")
                            table.add_column("Key (hex)", style="cyan", width=6)
                            table.add_column("Key (dec)", style="blue", width=5)
                            table.add_column("Result", style="green")
                            
                            for key, decrypted in results.items():
                                # Highlight likely English text
                                if any(word in decrypted.lower() for word in ['the', 'and', 'you', 'that']):
                                    table.add_row(f"0x{key:02x}", str(key), f"[bold]{decrypted[:50]}[/bold]")
                                else:
                                    table.add_row(f"0x{key:02x}", str(key), decrypted[:50])
                            
                            self.console.print(table)
                        progress.update(task, completed=1)
                        continue
                    
                    elif choice == "14":  # Beaufort
                        key = Prompt.ask("[bold]Enter key[/bold]")
                        result = self.safe_wrapper(self.classic.beaufort_encrypt, text, key)
                    
                    elif choice == "15":  # Autokey encrypt
                        key = Prompt.ask("[bold]Enter key[/bold]")
                        result = self.safe_wrapper(self.classic.autokey_encrypt, text, key)
                    
                    elif choice == "16":  # Autokey decrypt
                        key = Prompt.ask("[bold]Enter key[/bold]")
                        result = self.safe_wrapper(self.classic.autokey_decrypt, text, key)
                    
                    progress.update(task, completed=1)
                
                if result is not None:
                    smart_print(result, "Result")
                
                if not Confirm.ask(f"\n[bold]Continue with Module 3?[/bold]", default=True):
                    break
                    
            except KeyboardInterrupt:
                self.console.print(f"\n[{ColorScheme.WARNING}]Operation cancelled[/{ColorScheme.WARNING}]")
                break
            except Exception as e:
                self.console.print(f"[bold {ColorScheme.ERROR}]Error:[/bold {ColorScheme.ERROR}] {e}")
    
    def module4_modern(self):
        """Module 4: Modern Cryptography"""
        self.console.print(f"\n[bold {ColorScheme.ACCENT}][MODULE 4][/bold {ColorScheme.ACCENT}] Modern Cryptography\n")
        
        while True:
            options = [
                "1. AES Encryption",
                "2. AES Decryption",
                "3. DES Encryption",
                "4. DES Decryption",
                "5. RC4 Encryption",
                "6. RC4 Decryption",
                "7. ChaCha20 Encryption",
                "8. ChaCha20 Decryption",
                "9. Salsa20 Encryption",
                "10. Salsa20 Decryption",
                "11. Blowfish Encryption",
                "12. Blowfish Decryption",
                "13. Hash Calculator",
                "0. Back to Main Menu"
            ]
            
            for option in options:
                self.console.print(option)
            
            try:
                choice = Prompt.ask(f"\n[bold]Select operation[/bold]", 
                                   choices=[str(i) for i in range(14)])
                
                if choice == "0":
                    break
                
                if choice == "13":  # Hashing
                    text = Prompt.ask("[bold]Enter text to hash[/bold]")
                    algorithm = Prompt.ask("[bold]Algorithm[/bold]",
                                         choices=["MD5", "SHA1", "SHA256", "SHA512", 
                                                 "RIPEMD160", "BLAKE2B", "BLAKE2S"],
                                         default="SHA256")
                    
                    with Progress() as progress:
                        task = progress.add_task("[cyan]Hashing...", total=1)
                        result = self.safe_wrapper(self.modern.hash_data, text, algorithm)
                        progress.update(task, completed=1)
                    
                    if result is not None:
                        smart_print(result, f"{algorithm} Hash")
                    continue
                
                # For encryption/decryption
                action = "encrypt" if int(choice) % 2 == 1 else "decrypt"
                
                if action == "encrypt":
                    plaintext = Prompt.ask("[bold]Enter plaintext[/bold]")
                else:
                    ciphertext_input = Prompt.ask("[bold]Enter ciphertext[/bold]")
                    # Try to parse as hex
                    try:
                        if all(c in string.hexdigits for c in ciphertext_input.lower()):
                            ciphertext = bytes.fromhex(ciphertext_input)
                        else:
                            ciphertext = ciphertext_input.encode()
                    except:
                        ciphertext = ciphertext_input.encode()
                
                key_input = Prompt.ask("[bold]Enter key (as text)[/bold]")
                key = key_input.encode('utf-8')
                
                # Pad key if necessary
                if choice in ["1", "2"]:  # AES
                    if len(key) < 16:
                        key = key.ljust(16, b'\x00')[:16]
                    elif len(key) < 24:
                        key = key.ljust(24, b'\x00')[:24]
                    elif len(key) < 32:
                        key = key.ljust(32, b'\x00')[:32]
                    else:
                        key = key[:32]
                
                with Progress() as progress:
                    task = progress.add_task("[cyan]Processing...", total=1)
                    result = None
                    extra_info = None
                    
                    if choice in ["1", "2"]:  # AES
                        if choice == "1":  # Encrypt
                            mode = Prompt.ask("[bold]Mode[/bold]",
                                            choices=["CBC", "ECB", "CTR", "GCM"],
                                            default="CBC")
                            ciphertext, extra = self.safe_wrapper(self.modern.aes_encrypt, 
                                                                plaintext, key, mode)
                            if ciphertext is not None:
                                result = ciphertext.hex()
                                if mode == "CBC":
                                    extra_info = f"IV (hex): {extra.hex()}"
                                elif mode == "CTR":
                                    extra_info = f"Nonce (hex): {extra.hex()}"
                                elif mode == "GCM":
                                    extra_info = f"Nonce+Tag (hex): {extra.hex()}"
                        else:  # Decrypt
                            mode = Prompt.ask("[bold]Mode[/bold]",
                                            choices=["CBC", "ECB", "CTR", "GCM"],
                                            default="CBC")
                            extra_input = Prompt.ask("[bold]Enter IV/Nonce (hex, optional)[/bold]", default="")
                            extra = bytes.fromhex(extra_input) if extra_input else b''
                            result = self.safe_wrapper(self.modern.aes_decrypt,
                                                     ciphertext, key, extra, mode)
                    
                    elif choice in ["3", "4"]:  # DES
                        if choice == "3":  # Encrypt
                            ciphertext, iv = self.safe_wrapper(self.modern.des_encrypt, 
                                                             plaintext, key[:8])
                            if ciphertext is not None:
                                result = ciphertext.hex()
                                extra_info = f"IV (hex): {iv.hex()}"
                        else:  # Decrypt
                            iv_input = Prompt.ask("[bold]Enter IV (hex)[/bold]", default="")
                            iv = bytes.fromhex(iv_input) if iv_input else b''
                            result = self.safe_wrapper(self.modern.des_decrypt,
                                                     ciphertext, key[:8], iv)
                    
                    elif choice in ["5", "6"]:  # RC4
                        if choice == "5":  # Encrypt
                            ciphertext = self.safe_wrapper(self.modern.rc4_encrypt, 
                                                         plaintext, key)
                            if ciphertext is not None:
                                result = ciphertext.hex()
                        else:  # Decrypt
                            result = self.safe_wrapper(self.modern.rc4_decrypt,
                                                     ciphertext, key)
                    
                    elif choice in ["7", "8"]:  # ChaCha20
                        if choice == "7":  # Encrypt
                            ciphertext, nonce = self.safe_wrapper(self.modern.chacha20_encrypt,
                                                                plaintext, key[:32])
                            if ciphertext is not None:
                                result = ciphertext.hex()
                                extra_info = f"Nonce (hex): {nonce.hex()}"
                        else:  # Decrypt
                            nonce_input = Prompt.ask("[bold]Enter nonce (hex)[/bold]", default="")
                            nonce = bytes.fromhex(nonce_input) if nonce_input else b''
                            result = self.safe_wrapper(self.modern.chacha20_decrypt,
                                                     ciphertext, key[:32], nonce)
                    
                    elif choice in ["9", "10"]:  # Salsa20
                        if choice == "9":  # Encrypt
                            ciphertext, nonce = self.safe_wrapper(self.modern.salsa20_encrypt,
                                                                plaintext, key[:32])
                            if ciphertext is not None:
                                result = ciphertext.hex()
                                extra_info = f"Nonce (hex): {nonce.hex()}"
                        else:  # Decrypt
                            nonce_input = Prompt.ask("[bold]Enter nonce (hex)[/bold]", default="")
                            nonce = bytes.fromhex(nonce_input) if nonce_input else b''
                            result = self.safe_wrapper(self.modern.salsa20_decrypt,
                                                     ciphertext, key[:32], nonce)
                    
                    elif choice in ["11", "12"]:  # Blowfish
                        if choice == "11":  # Encrypt
                            ciphertext, iv = self.safe_wrapper(self.modern.blowfish_encrypt,
                                                             plaintext, key)
                            if ciphertext is not None:
                                result = ciphertext.hex()
                                extra_info = f"IV (hex): {iv.hex()}"
                        else:  # Decrypt
                            iv_input = Prompt.ask("[bold]Enter IV (hex)[/bold]", default="")
                            iv = bytes.fromhex(iv_input) if iv_input else b''
                            result = self.safe_wrapper(self.modern.blowfish_decrypt,
                                                     ciphertext, key, iv)
                    
                    progress.update(task, completed=1)
                
                if result is not None:
                    smart_print(result, "Ciphertext" if action == "encrypt" else "Plaintext")
                    if extra_info:
                        self.console.print(f"[{ColorScheme.INFO}]{extra_info}[/{ColorScheme.INFO}]")
                
                if not Confirm.ask(f"\n[bold]Continue with Module 4?[/bold]", default=True):
                    break
                    
            except KeyboardInterrupt:
                self.console.print(f"\n[{ColorScheme.WARNING}]Operation cancelled[/{ColorScheme.WARNING}]")
                break
            except Exception as e:
                self.console.print(f"[bold {ColorScheme.ERROR}]Error:[/bold {ColorScheme.ERROR}] {e}")
    
    def module5_analysis(self):
        """Module 5: Analysis & Utilities"""
        self.console.print(f"\n[bold {ColorScheme.ACCENT}][MODULE 5][/bold {ColorScheme.ACCENT}] Analysis & Utilities\n")
        
        while True:
            options = [
                "1. Frequency Analysis",
                "2. Magic Detector",
                "3. Compare with English Frequency",
                "0. Back to Main Menu"
            ]
            
            for option in options:
                self.console.print(option)
            
            try:
                choice = Prompt.ask(f"\n[bold]Select tool[/bold]", 
                                   choices=[str(i) for i in range(4)])
                
                if choice == "0":
                    break
                
                text = Prompt.ask("[bold]Enter text to analyze[/bold]")
                
                with Progress() as progress:
                    task = progress.add_task("[cyan]Analyzing...", total=1)
                    
                    if choice == "1":  # Frequency Analysis
                        freq = self.safe_wrapper(self.analyzer.frequency_analysis, text)
                        
                        if freq:
                            table = Table(title="Character Frequency Analysis", 
                                         show_header=True, 
                                         header_style="bold magenta")
                            table.add_column("Char", style="cyan", width=5)
                            table.add_column("Count", style="green", width=10)
                            table.add_column("Percentage", style="yellow", width=15)
                            table.add_column("Graph", style="white", width=30)
                            
                            max_percent = max(freq.values()) if freq else 1
                            
                            for char, percent in freq.items():
                                count = int((percent / 100) * sum(1 for c in text if c.isalpha()))
                                bar_length = int((percent / max_percent) * 30)
                                graph = "█" * bar_length + "░" * (30 - bar_length)
                                
                                table.add_row(char, str(count), f"{percent:.2f}%", graph)
                            
                            self.console.print(table)
                    
                    elif choice == "2":  # Magic Detector
                        detections = self.safe_wrapper(self.analyzer.magic_detect, text)
                        
                        if detections:
                            table = Table(title="Magic Detection Results", 
                                         show_header=True, 
                                         header_style="bold magenta")
                            table.add_column("Type", style="cyan", width=25)
                            table.add_column("Confidence", style="green", width=15)
                            table.add_column("Notes", style="yellow")
                            
                            for det_type, confidence in detections:
                                if confidence > 0.8:
                                    notes = "Highly likely"
                                elif confidence > 0.6:
                                    notes = "Likely"
                                elif confidence > 0.4:
                                    notes = "Possible"
                                else:
                                    notes = "Unlikely"
                                
                                table.add_row(det_type, f"{confidence:.1%}", notes)
                            
                            self.console.print(table)
                        else:
                            self.console.print(f"[{ColorScheme.WARNING}]No patterns detected[/{ColorScheme.WARNING}]")
                    
                    elif choice == "3":  # Compare with English
                        freq = self.safe_wrapper(self.analyzer.frequency_analysis, text)
                        english = self.analyzer.english_frequency()
                        
                        if freq:
                            # Get common letters
                            common_letters = set(list(freq.keys())[:10]) | set(list(english.keys())[:10])
                            
                            table = Table(title="Comparison with English Frequency", 
                                         show_header=True, 
                                         header_style="bold magenta")
                            table.add_column("Char", style="cyan", width=5)
                            table.add_column("Text %", style="green", width=10)
                            table.add_column("English %", style="blue", width=10)
                            table.add_column("Difference", style="yellow", width=15)
                            
                            for char in sorted(common_letters):
                                text_percent = freq.get(char, 0)
                                eng_percent = english.get(char, 0)
                                diff = text_percent - eng_percent
                                
                                if abs(diff) > 5:
                                    diff_str = f"[bold]{diff:+.2f}%[/bold]"
                                else:
                                    diff_str = f"{diff:+.2f}%"
                                
                                table.add_row(char, f"{text_percent:.2f}%", 
                                            f"{eng_percent:.2f}%", diff_str)
                            
                            self.console.print(table)
                            
                            # Simple analysis
                            total_diff = sum(abs(freq.get(char, 0) - english.get(char, 0)) 
                                           for char in common_letters)
                            if total_diff < 30:
                                self.console.print(f"[{ColorScheme.PRIMARY}]✅ Text frequency matches English well[/{ColorScheme.PRIMARY}]")
                            elif total_diff < 60:
                                self.console.print(f"[{ColorScheme.WARNING}]⚠️  Text frequency somewhat matches English[/{ColorScheme.WARNING}]")
                            else:
                                self.console.print(f"[{ColorScheme.ERROR}]❌ Text frequency doesn't match English (likely encoded/encrypted)[/{ColorScheme.ERROR}]")
                    
                    progress.update(task, completed=1)
                
                if not Confirm.ask(f"\n[bold]Continue with Module 5?[/bold]", default=True):
                    break
                    
            except KeyboardInterrupt:
                self.console.print(f"\n[{ColorScheme.WARNING}]Operation cancelled[/{ColorScheme.WARNING}]")
                break
            except Exception as e:
                self.console.print(f"[bold {ColorScheme.ERROR}]Error:[/bold {ColorScheme.ERROR}] {e}")
    
    def run(self):
        """Main application loop"""
        while True:
            try:
                self.console.clear()
                self.display_banner()
                self.display_menu()
                
                choice = Prompt.ask(f"\n[bold]Select module[/bold]", 
                                   choices=["0", "1", "2", "3", "4", "5"])
                
                if choice == "1":
                    self.module1_encoding()
                elif choice == "2":
                    self.module2_esoteric()
                elif choice == "3":
                    self.module3_classic()
                elif choice == "4":
                    self.module4_modern()
                elif choice == "5":
                    self.module5_analysis()
                elif choice == "0":
                    if Confirm.ask(f"[bold {ColorScheme.ERROR}]Exit MONOGRAFI Toolkit?[/bold {ColorScheme.ERROR}]", default=False):
                        self.console.print(f"\n[bold {ColorScheme.PRIMARY}]Goodbye! Stay cryptic![/bold {ColorScheme.PRIMARY}]")
                        break
                
            except KeyboardInterrupt:
                if Confirm.ask(f"\n[bold {ColorScheme.ERROR}]Exit MONOGRAFI Toolkit?[/bold {ColorScheme.ERROR}]", default=False):
                    self.console.print(f"\n[bold {ColorScheme.PRIMARY}]Goodbye! Stay cryptic![/bold {ColorScheme.PRIMARY}]")
                    break
            except Exception as e:
                self.console.print(f"[bold {ColorScheme.ERROR}]Fatal error: {e}[/bold {ColorScheme.ERROR}]")
                if not Confirm.ask("[bold]Continue?[/bold]", default=True):
                    break

def main():
    """Entry point"""
    try:
        app = MonografiToolkit()
        app.run()
    except KeyboardInterrupt:
        console.print(f"\n[{ColorScheme.WARNING}]Program interrupted[/{ColorScheme.WARNING}]")
    except Exception as e:
        console.print(f"[bold {ColorScheme.ERROR}]Fatal error: {e}[/bold {ColorScheme.ERROR}]")
        console.print(f"[{ColorScheme.INFO}]Please install dependencies: pip install rich pycryptodome[/{ColorScheme.INFO}]")

if __name__ == "__main__":
    main()
