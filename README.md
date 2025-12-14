# 🔐 MONOGRAFI: The Ultimate Cryptography Toolkit

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Security-CTF-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Stable-green?style=for-the-badge)

**MONOGRAFI** adalah alat kriptografi "All-in-One" berbasis terminal yang dirancang untuk kompetisi **CTF (Capture The Flag)** dan edukasi keamanan siber. Alat ini mencakup algoritma klasik, modern, hingga encoding langka (*esoteric*) yang sering muncul dalam tantangan krypto.

> *"Decrypt the unseen, Encode the impossible."*

## 🔥 Fitur Utama

### 🛠️ Module 1: Advanced Encoding (Manual Logic)
Implementasi algoritma manual tanpa dependency berat:
- **Base58** (Bitcoin Address)
- **Base62, Base36**
- **Base91** (basE91)
- **Base45** (QR Code standard)
- **Z85** (ZeroMQ)

### 🧠 Module 2: Esoteric & Obscure
- **Brainfuck Interpreter:** Eksekusi kode esoterik langsung di terminal.
- **Baconian Cipher:** Decode pesan rahasia (A/B).
- **Morse Code & Tap Code:** Komunikasi sandi klasik.

### 🛡️ Module 3: Modern Cryptography
Wrapper kuat menggunakan `pycryptodome`:
- **AES** (CBC, ECB, CTR)
- **DES & 3DES**
- **Salsa20 & ChaCha20**
- **Blowfish & CAST-128**
- **RC4**

### 🔮 Module 4: Magic Detector
Fitur pintar yang menganalisis input string dan menebak jenis enkripsinya secara otomatis (Smart Heuristics).

## 🚀 Instalasi

1. **Clone repository ini:**
   ```bash
   git clone https://github.com/rasyakeselekbatuginjal-lang/MonoGrafi.git
   cd monografi
   pip install -r requirements.txt
   python monografi.py
