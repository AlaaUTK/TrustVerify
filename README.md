# TrustVerify CLI

## Overview
TrustVerify is a Python-based Command Line Interface (CLI) tool that ensures file integrity and authenticity.
It allows a Sender to createa manifest of files (hashing with SHA-256) and sign it using an RSA Private Key.
A Receiver can then verify the files and the signature using the Sender's Public Key, ensuring non-repudiation.

## Requirements
- Python 3.x
- `cryptography` library

Install the required library using:
```bash
pip install cryptography
```
-------------------------------------------------------------------------------------------------------------------------------------------

Setup

Clone or download this repository.(The only required file for it to work is `trustverify.py`)

Create a folder named testfolder in the same directory as the script.

Place the files you want to check inside testfolder.

-------------------------------------------------------------------------------------------------------------------------------------------

How to Run

Run the `run.bat` file, or open your terminal/command prompt and execute: `python trustverify.py`.

-------------------------------------------------------------------------------------------------------------------------------------------

Menu Options

[0] Manifest Oluştur: Scans testfolder and generates metadata.json with SHA-256 hashes.

[1] Güvenlik Taraması Yap: Checks the integrity of files in testfolder (detects modified, missing, or new files).

[2] RSA Anahtar Çifti Oluştur: Generates private_key.pem and public_key.pem (2048-bit).

[3] Manifest Dosyasını İmzala: Signs metadata.json using your Private Key and creates signature.sig.

[4] İmzayı Doğrula: Verifies the signature using the Public Key to ensure authenticity and integrity.

[q] Çıkış Yap: Exits the application.
