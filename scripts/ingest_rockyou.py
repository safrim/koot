# scripts/ingest_rockyou.py
import sys
import os
import requests
import shutil

# Add project root to path so it can find 'koot'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from koot.plugins.breach_radar import BreachRadarPlugin

class StandaloneSensor:
    def get_available_ram_mb(self): return 1024
    def get_available_disk_mb(self): return 500 # Force RockYou mode

def check_disk_space(required_mb):
    """Checks if the actual physical disk has enough room."""
    _, _, free = shutil.disk_usage("/")
    free_mb = free // (1024 * 1024)
    return free_mb > required_mb

def print_progress(current, total, prefix='', suffix='', length=40):
    """Visual feedback for the user."""
    percent = ("{0:.1f}").format(100 * (current / float(total)))
    filled_length = int(length * current // total)
    bar = '█' * filled_length + '-' * (length - filled_length)
    sys.stdout.write(f'\r{prefix} |{bar}| {percent}% {suffix}')
    sys.stdout.flush()

def ingest_rockyou():
    ROCKYOU_URL = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
    # Keeping data out of the plugins folder
    DATA_PATH = "data/rockyou.txt"
    BIN_PATH = "data/breach_radar.bin"
    
    if not check_disk_space(250):
        print("[!] Fatal: Insufficient disk space. Need at least 250MB.")
        return

    print("[*] Initializing Koot Breach Radar...")
    # Ensure data directory exists
    os.makedirs("data", exist_ok=True)
    
    radar = BreachRadarPlugin(StandaloneSensor(), is_enabled=True, filepath=BIN_PATH)

    # 1. Download
    if not os.path.exists(DATA_PATH):
        print(f"[*] Downloading RockYou dataset...")
        response = requests.get(ROCKYOU_URL, stream=True)
        total_size = int(response.headers.get('content-length', 0))
        downloaded = 0
        with open(DATA_PATH, 'wb') as f:
            for chunk in response.iter_content(chunk_size=1024*1024):
                f.write(chunk)
                downloaded += len(chunk)
                print_progress(downloaded, total_size, prefix='Download:', suffix=f'{downloaded//1024//1024}MB')
        print("\n[+] Download complete.")

    # 2. Ingestion (Fixed Loop)
    file_size = os.path.getsize(DATA_PATH)
    print(f"[*] Ingesting passwords into persistent binary...")
    
    try:
        with open(DATA_PATH, "rb") as f: # Read in binary mode for faster processing and tell() accuracy
            count = 0
            while True:
                line = f.readline()
                if not line:
                    break
                
                # Decode to string for the Bloom Filter
                password = line.strip().decode('utf-8', errors='ignore')
                if password:
                    radar.ingest_compromised_password(password)
                    count += 1
                
                # Update progress bar every 20,000 lines
                if count % 20000 == 0:
                    print_progress(f.tell(), file_size, prefix='Ingestion:', suffix=f'{count} items')
            
            # Final update
            print_progress(file_size, file_size, prefix='Ingestion:', suffix=f'{count} items')
                    
    except KeyboardInterrupt:
        print("\n[!] Ingestion interrupted. Progress saved.")
    
    radar.close()
    print(f"\n[*] Success. Filter saved to {BIN_PATH}")
    print("[*] You can now delete 'data/rockyou.txt' to free up space.")

if __name__ == "__main__":
    ingest_rockyou()