import hashlib
import os
import json
import subprocess
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

# --- RENK KODLARI ------------------------------------------------------------------------------------------------------------------------
class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# --- TASK 1: Dosyanın parmak izini alma --------------------------------------------------------------------------------------------------

def generate_file_hash(filename):
    with open(filename, "rb") as f:
        bytes = f.read()
        return hashlib.sha256(bytes).hexdigest()

# --- TASK 2: 'metadata.json' oluşturma ---------------------------------------------------------------------------------------------------

def generate_manifest(directory_path):
    if not os.path.exists(directory_path):
        print(f"\n{Color.RED}[HATA] '{directory_path}' adında bir klasör bulunamadı!{Color.RESET}")
        return

    manifest_data = {}
    print(f"\n{Color.CYAN}[BİLGİ] '{directory_path}' klasörü taranıyor...{Color.RESET}")
    
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        if os.path.isfile(file_path):
            file_hash = generate_file_hash(file_path)
            manifest_data[filename] = file_hash

    with open("metadata.json", "w") as json_file:
        json.dump(manifest_data, json_file, indent=4)

    print(f"{Color.GREEN}[BAŞARILI] metadata.json oluşturuldu!{Color.RESET}")

# --- TASK 3: Bütünlük Kontrolü (Check) ---------------------------------------------------------------------------------------------------

def verify_integrity(directory_path):
    if not os.path.exists(directory_path):
        print(f"\n{Color.RED}[HATA] '{directory_path}' adında bir klasör bulunamadı!{Color.RESET}")
        return

    manifest_path = "metadata.json"
    if not os.path.exists(manifest_path):
        print(f"\n{Color.RED}[HATA] metadata.json bulunamadı!{Color.RESET}")
        return

    with open(manifest_path, "r") as json_file:
        saved_manifest = json.load(json_file)

    print(f"\n{Color.BOLD}--- BÜTÜNLÜK KONTROLÜ BAŞLIYOR ---{Color.RESET}")
    tampered_files = False

    # 1. Silinmiş ve Değiştirilmiş Dosyalar
    for filename, original_hash in saved_manifest.items():
        file_path = os.path.join(directory_path, filename)
        
        # SİLİNMİŞ DOSYA
        if not os.path.exists(file_path):
            print(f"{Color.RED}[EKSİK] {filename} dosyası silinmiş!{Color.RESET}")
            tampered_files = True
            continue

        current_hash = generate_file_hash(file_path)
        
        # GÜVENLİ DOSYA -> YEŞİL
        if current_hash == original_hash:
            print(f"{Color.GREEN}[GÜVENLİ] {filename}{Color.RESET}")
            
        # DEĞİŞTİRİLMİŞ DOSYA -> MAVİ (Senin isteğin üzerine)
        else:
            print(f"{Color.BLUE}[DEĞİŞTİRİLMİŞ] {filename} -> İçeriği kurcalanmış!{Color.RESET}")
            tampered_files = True

    # 2. Sonradan Eklenen Dosyalar
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        if os.path.isfile(file_path):
            
            # YABANCI DOSYA -> KIRMIZI
            if filename not in saved_manifest:
                print(f"{Color.RED}[YABANCI] {filename} -> MANİFESTTE YOK (Sonradan Eklenmiş)!{Color.RESET}")
                tampered_files = True

    if not tampered_files:
        print(f"\n{Color.GREEN}{Color.BOLD}[SONUÇ] Tüm dosyalar güvende. Değişiklik yok.{Color.RESET}")
    else:
        print(f"\n{Color.RED}{Color.BOLD}[SONUÇ] DİKKAT! Dosyalarda sorun tespit edildi.{Color.RESET}")

# --- TASK 4: RSA Anahtar Çifti Oluşturma -------------------------------------------------------------------------------------------------

def generate_keys():
    print(f"\n{Color.CYAN}[BİLGİ] RSA Anahtar çifti oluşturuluyor (2048-bit)...{Color.RESET}")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"{Color.GREEN}[BAŞARILI] 'private_key.pem' ve 'public_key.pem' dosyaları oluşturuldu!{Color.RESET}")

# --- TASK 5: Manifest Dosyasını İmzalama -------------------------------------------------------------------------------------------------

def sign_manifest():
    if not os.path.exists("private_key.pem") or not os.path.exists("metadata.json"):
        print(f"\n{Color.RED}[HATA] private_key.pem veya metadata.json eksik!{Color.RESET}")
        return

    print(f"\n{Color.CYAN}[BİLGİ] metadata.json, Private Key ile imzalanıyor...{Color.RESET}")

    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    with open("metadata.json", "rb") as f:
        manifest_data = f.read()

    signature = private_key.sign(
        manifest_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    with open("signature.sig", "wb") as f:
        f.write(signature)

    print(f"{Color.GREEN}[BAŞARILI] İmzalama tamamlandı! 'signature.sig' dosyası oluşturuldu.{Color.RESET}")

# --- TASK 6: İmzayı Doğrulama ------------------------------------------------------------------------------------------------------------

def verify_signature():
    if not os.path.exists("public_key.pem") or not os.path.exists("metadata.json") or not os.path.exists("signature.sig"):
        print(f"\n{Color.RED}[HATA] Doğrulama için dosyalar (public_key.pem, metadata.json, signature.sig) eksik!{Color.RESET}")
        return

    print(f"\n{Color.CYAN}[BİLGİ] İmza, Public Key kullanılarak doğrulanıyor...{Color.RESET}")

    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    with open("metadata.json", "rb") as f:
        manifest_data = f.read()
        
    with open("signature.sig", "rb") as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            manifest_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print(f"\n{Color.GREEN}{Color.BOLD}[BAŞARILI] İMZA GEÇERLİ! Bu manifest kesinlikle göndericiye ait.{Color.RESET}")
    except InvalidSignature:
        print(f"\n{Color.RED}{Color.BOLD}[KRİTİK TEHLİKE] İMZA GEÇERSİZ (Verification Failed)! Manifest dosyası kurcalanmış.{Color.RESET}")

def clear():
    subprocess.run('cls' if os.name == 'nt' else 'clear', shell=True)

# --- ANA MENÜ ----------------------------------------------------------------------------------------------------------------------------

def main():

    clear()
    subprocess.run("color", shell=True)
    
    hedef_klasor = "testfolder"

    while True:
        print(f"\n{Color.YELLOW}{Color.BOLD}" + "="*45)
        print("          TrustVerify CLI Aracı")
        print("="*45 + f"{Color.RESET}")
        print(f"[0] Manifest Oluştur ({hedef_klasor})")
        print(f"[1] Güvenlik Taraması Yap ({hedef_klasor})")
        print("[2] RSA Anahtar Çifti Oluştur (Keygen)")
        print("[3] Manifest Dosyasını İmzala (Signing)")
        print("[4] İmzayı Doğrula (Verification)")
        print("[q] Çıkış Yap")
        print(f"{Color.YELLOW}" + "="*45 + f"{Color.RESET}")
        
        secim = input("Lütfen bir işlem seçin: ")
        
        if secim == '0':
            clear()
            generate_manifest(hedef_klasor)
        elif secim == '1':
            clear()
            verify_integrity(hedef_klasor)
        elif secim == '2':
            clear()
            generate_keys()
        elif secim == '3':
            clear()
            sign_manifest()
        elif secim == '4':
            clear()
            verify_signature()
        elif secim.lower() == 'q':
            print(f"{Color.CYAN}Çıkılıyor...{Color.RESET}")
            break
        else:
            clear()
            print(f"{Color.RED}[HATA] Geçersiz seçim!{Color.RESET}")
            
if __name__ == "__main__":
    main()