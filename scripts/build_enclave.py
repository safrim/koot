import os
import subprocess
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ENCLAVE_DIR = os.path.join(PROJECT_ROOT, "koot", "crypto", "enclave")
C_SOURCE = os.path.join(ENCLAVE_DIR, "memory_lock.c")

def build_enclave():
    print("\n[--- Building C-Enclave (Memory Lock) ---]")
    os.makedirs(ENCLAVE_DIR, exist_ok=True)
    
    lib_ext = ".dll" if sys.platform == "win32" else ".dylib" if sys.platform == "darwin" else ".so"
    dest_lib = os.path.join(ENCLAVE_DIR, f"libmemorylock{lib_ext}")
    
    # Compile the C file as a position-independent shared object
    cmd = ["gcc", "-shared", "-O3", "-fPIC", "-o", dest_lib, C_SOURCE]
    print(f"[*] Executing: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    print(f"[+] C-Enclave secured at: {dest_lib}")
    
    # create __init__.py so the folder acts as a module in Python
    with open(os.path.join(ENCLAVE_DIR, "__init__.py"), "w") as f:
        f.write("# OS-Locked C-Enclave Module\n")

if __name__ == "__main__":
    try:
        build_enclave()
        print("\n[SUCCESS] Phase 2, Session 3 (C-Enclave Foundation) complete.")
    except subprocess.CalledProcessError as e:
        print(f"\n[FATAL] Enclave build failed: {e}")
        sys.exit(1)