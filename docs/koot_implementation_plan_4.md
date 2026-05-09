Here is the structured, granular implementation plan to integrate these four extreme countermeasures into the `koot` architecture.

Because I am `koot`—a hyper-paranoid, headless Zero-Trust subsystem—this plan is organized sequentially to ensure that foundational security (supply chain and memory) is locked down before we implement the coercion defenses and UI-level guardrails.

---

### **Phase 1: Supply Chain & Build Hardening**
*Addressing Countermeasure C: Strict Hash Pinning & Vendoring. This must be done first to ensure no malicious code is introduced while we build the other countermeasures.*

**Session 1: Dependency Hash Verification**
    * **Objective:** Prevent dynamic injection of poisoned open-source libraries.
    * **Action:** Audit the current `requirements.txt`. Use `pip-compile` (from `pip-tools`) with the `--generate-hashes` flag to lock every single dependency and sub-dependency to its exact cryptographic SHA-256 hash.
    * **Outcome:** The CI/CD pipeline and the deployment server will instantly crash and refuse to boot if PyPI serves a compromised version of any package.

**Session 2: Cryptographic Vendoring**
    * **Objective:** Take absolute local ownership of the highest-risk mathematical primitives.
    * **Action:** Create a `koot/crypto/vendored/` directory. Download the audited source code for your ML-KEM (Kyber) wrapper and your AES-GCM software fallback. Remove them from `requirements.txt` entirely. Write a script to compile them locally during the build process.
    * **Outcome:** State-sponsored actors can no longer compromise your encryption via third-party repository takeovers.

---

### **Phase 2: Core Memory Isolation (The C-Enclave)**
*Addressing Countermeasure A: The Language Trap. We must move the Master Key out of Python's garbage-collected memory space entirely.*

**Session 3: The C-Enclave Foundation**
    * **Objective:** Allocate OS-locked, non-pageable memory.
    * **Action:** Write a highly restricted C library (`koot/crypto/enclave/memory_lock.c`). Implement two functions: `allocate_secure_key()` which uses `mlock()` (Linux/macOS) or `VirtualLock` (Windows) to reserve memory, and `destroy_secure_key()` which uses `explicit_bzero()` or `memset_s()` to cryptographically wipe that memory. Compile this into a shared object (`.so` or `.dll`).
    * **Outcome:** The operating system is mathematically forbidden from writing the key to the hard drive's swap file, and we guarantee immediate memory destruction.

**Session 4: Python FFI Integration**
    * **Objective:** Connect the `koot` Python engine to the C-Enclave.
    * **Action:** Refactor `EntropyPipeline` in `koot/identity/derivation/pipeline.py`. Use Python's `ctypes` or `cffi` library to pass the derived Master Key directly to `allocate_secure_key()` in the C-Enclave. Ensure Python immediately calls `del` and `gc.collect()` on its own temporary variables. Update the "Go Cold" (lock) function to trigger `destroy_secure_key()`.
    * **Outcome:** Python no longer holds the actual Master Key during standard operations; it only references the secure C pointer.

---

### **Phase 3: Coercion Defense & Governance**
*Addressing Countermeasure D: Rubber-Hose Cryptanalysis. Integrating physical threat defenses into the authentication layer.*

**Session 5: The Duress Protocol (Fake Vault)**
    * **Objective:** Provide plausible deniability under threat of physical violence.
    * **Action:** Modify the boot sequence and `EntropyPipeline`. Hash a pre-determined "Duress Password." If entered, the engine suppresses all errors, sets an internal `is_duress_mode = True` flag, and points the `StorageDriver` and `ShadowLedger` to secondary, decoy file paths (`shadow_ledger_dummy.json`).
    * **Outcome:** You can safely comply with an attacker's demand for the password. They will unlock a fully functional, mathematically valid `koot` core filled entirely with fabricated data.

**Session 6: The Terminal Nuke Key**

* **Objective:** Instant cryptographic shredding of the core.
* **Action:** Define a "Terminal Key" (e.g., your master password spelled backward). If the authentication gateway detects this exact string, it bypasses all delays and directly invokes `NukeProtocol.trigger_now()`. The system immediately overwrites the real Shadow Ledger with random noise, triggers the C-Enclave `destroy_secure_key()`, and shuts down the main process.
* **Outcome:** By the time the attacker hits "Enter" on your keyboard, the vault ceases to exist.

---

### **Phase 4: Client-Side OS Guardrails**

*Addressing Countermeasure B: Endpoint Compromise. Since the `koot` core is headless, these defenses are built into the UI application (Tauri/Electron/Mobile) that communicates with the core.*

**Session 7: Ephemeral Clipboard & Memory Noise**

* **Objective:** Defeat keyloggers and basic memory-scraping malware.
* **Action:** In the UI codebase, update the "Copy Password" function. When clicked, copy the plaintext to the OS clipboard, but instantly spawn an asynchronous background thread that waits exactly 9.0 seconds before overwriting the clipboard with an empty string. Additionally, upon vault unlock, instantiate a background routine that generates 500 fake dictionary-based credential objects and randomly moves them around the UI's allocated heap memory.
* **Outcome:** Malware scraping the clipboard gets nothing if they wait too long, and malware dumping the UI's RAM gets buried in hundreds of fake credentials.

**Session 8: Anti-Screen Capture OS Hooks**

* **Objective:** Blind remote desktop malware and unauthorized screen recordings.
* **Action:** If building with Tauri (Rust) or Electron (Node), tap into the native OS window APIs. On Windows, call `SetWindowDisplayAffinity(WDA_MONITOR)`. On macOS, set `NSWindowSharingNone`.
* **Outcome:** If malware tries to take a screenshot or record the screen while the user is viewing a decrypted password, the OS will forcibly render the `koot` application window as a solid black square in the recording.