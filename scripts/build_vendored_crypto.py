#!/usr/bin/env python3
import os
import subprocess
import sys
import shutil
import platform

# Identify paths based on the Domain-Driven structure
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VENDORED_DIR = os.path.join(PROJECT_ROOT, "koot", "crypto", "vendored")
LIBOQS_REPO = "https://github.com/open-quantum-safe/liboqs.git"
LIBOQS_BUILD_DIR = os.path.join(VENDORED_DIR, "liboqs_build")
LIBOQS_INSTALL_DIR = os.path.join(VENDORED_DIR, "liboqs")

def build_liboqs():
    """
    Clones and compiles the liboqs repository for Post-Quantum Cryptography (ML-KEM/Kyber).
    This satisfies the 'Cryptographic Vendoring' requirement.
    """
    print(f"[*] Starting liboqs build pipeline...")
    
    # Ensure cmake and git are available
    if not shutil.which("git") or not shutil.which("cmake"):
        print("[!] Error: 'git' and 'cmake' are required to build liboqs.")
        sys.exit(1)

    # Step 1: Clone the repository if it doesn't exist
    if not os.path.exists(LIBOQS_BUILD_DIR):
        print(f"[*] Cloning liboqs from {LIBOQS_REPO}...")
        try:
            subprocess.run(["git", "clone", "--depth", "1", LIBOQS_REPO, LIBOQS_BUILD_DIR], check=True)
        except subprocess.CalledProcessError:
            print("[!] Failed to clone liboqs.")
            sys.exit(1)
    else:
        print("[*] liboqs source already exists. Skipping clone.")

    # Step 2: Configure and build using CMake
    build_path = os.path.join(LIBOQS_BUILD_DIR, "build")
    os.makedirs(build_path, exist_ok=True)

    print("[*] Configuring liboqs with CMake...")
    cmake_cmd = [
        "cmake",
        "-GNinja", # Try Ninja first for speed
        "-DCMAKE_INSTALL_PREFIX=" + LIBOQS_INSTALL_DIR,
        "-DBUILD_SHARED_LIBS=ON",
        "-DOQS_USE_OPENSSL=ON", # Integrate with OpenSSL for hybrid modes
        ".."
    ]
    
    try:
        # Fallback to Makefiles if Ninja isn't installed
        if not shutil.which("ninja"):
            cmake_cmd.remove("-GNinja")
            
        subprocess.run(cmake_cmd, cwd=build_path, check=True)
        
        print("[*] Compiling liboqs...")
        subprocess.run(["cmake", "--build", "."], cwd=build_path, check=True)
        
        print("[*] Installing liboqs to vendored directory...")
        subprocess.run(["cmake", "--install", "."], cwd=build_path, check=True)
        
        print("[+] liboqs Build successful.")
    except subprocess.CalledProcessError as e:
        print("[!] liboqs Compilation failed!")
        sys.exit(1)

def build_aes_gcm():
    """
    Compiles the vendored C layer for AES-GCM.
    Links against OpenSSL (libcrypto) to enable hardware acceleration (AES-NI).
    """
    source_file = os.path.join(VENDORED_DIR, "aes_gcm_vendored.c")
    
    # Set the output filename based on the OS to maintain the Adaptive requirement
    if platform.system() == "Windows":
        output_file = os.path.join(VENDORED_DIR, "aes_gcm.dll")
    else:
        output_file = os.path.join(VENDORED_DIR, "aes_gcm.so")
    
    print(f"[*] Starting AES-GCM build: {source_file}")
    
    if not os.path.exists(source_file):
        print(f"[!] Error: Source file not found at {source_file}")
        sys.exit(1)

    # The compilation command explicitly includes -lcrypto
    # -shared: Create a shared library
    # -fPIC: Position Independent Code (required for shared libraries)
    # -O3: Aggressive optimization for cryptographic operations
    # -lcrypto: Link against OpenSSL's libcrypto for EVP API
    compile_cmd = [
        "gcc", 
        "-O3",
        "-shared", 
        "-o", output_file, 
        "-fPIC", 
        source_file, 
        "-lcrypto"
    ]

    try:
        print(f"[*] Running: {' '.join(compile_cmd)}")
        result = subprocess.run(compile_cmd, check=True, capture_output=True, text=True)
        print("[+] AES-GCM Build successful.")
        print(f"[+] Binary located at: {output_file}")
    except subprocess.CalledProcessError as e:
        print("[!] AES-GCM Compilation failed!")
        print(e.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("[!] Error: 'gcc' compiler not found. Please install build-essential or equivalent.")
        sys.exit(1)

def cleanup():
    """
    Removes temporary build directories to keep the vendored folder clean.
    """
    if os.path.exists(LIBOQS_BUILD_DIR):
        print("\n[*] Cleaning up temporary liboqs build files...")
        shutil.rmtree(LIBOQS_BUILD_DIR)
        print("[+] Cleanup complete.")

if __name__ == "__main__":
    # Ensure the vendored directory exists before starting
    os.makedirs(VENDORED_DIR, exist_ok=True)
    
    # 1. Build the Classical layer (AES-GCM)
    build_aes_gcm()
    
    # 2. Build the Post-Quantum layer (Kyber/liboqs)
    build_liboqs()
    
    # 3. Securely clean up build artifacts
    cleanup()
    
    print("\n[SUCCESS] Cryptographic vendoring complete. The Koot core is ready.")