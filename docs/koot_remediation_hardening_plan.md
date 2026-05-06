### **koot: Codebase Remediation Plan (Plan 2)**

#### **Phase 1: Remediation of The Adaptive Core & Entropy**

* **Session 1.1: Securing IPC Communication (Countermeasure for Unencrypted IPC Pipes).**
    * **Objective:** Prevent potential snooping of data transmitted between the core kernel and plugins over the OS inter-process communication layer.
    * **Action:** Refactor `_actor_loop` in `koot/core/bus/registry.py`. Instead of sending raw plaintext over `multiprocessing.Pipe`, implement a localized, volatile symmetric key exchange (e.g., a fast ChaCha20-Poly1305 stream cipher) established upon plugin initialization. Ensure all data traversing the pipe is encrypted before transmission and decrypted upon receipt within the plugin sandbox.

* **Session 1.2: Activating Dynamic Throttling (Countermeasure for Stubbed Predictive Ramp-Up).**
    * **Objective:** Ensure the system actually adapts to real-time memory pressure, preventing OOM crashes on low-power devices as theoretically designed.
    * **Action:** Fulfill the stubbed `_evaluate_hardware()` method in `koot/storage/chunking/buffered_adaptive.py`. Integrate with the `EnvironmentSensor` or `AnalyticsEngine` telemetry. Implement the logic to dynamically adjust the `current_chunk_size` down from 64KB (e.g., to 32KB or 16KB) if available RAM drops below predefined safety thresholds during heavy streaming operations.

#### **Phase 2: Remediation of Quantum-Safe Cryptography**

* **Session 2.1: Hardening the Hybrid Combiner (Countermeasure for Concatenation Vulnerability).**
    * **Objective:** Prevent collision attacks in the hybrid key derivation process, ensuring future-proofing if variable-length keys are ever adopted.
    * **Action:** Modify the `derive_hybrid_key` method in `koot/crypto/combiner/hkdf.py`. Before concatenating the classical and quantum keys, strictly enforce length prefixing. The code should explicitly format the input material as `[Length of AES Key][AES Key][Length of Kyber Key][Kyber Key]` before feeding it into the HKDF extract phase.

#### **Phase 3: Remediation of Media Handling & Scalability**

* **Session 3.1: Out-of-Core Merkle Tree Construction (Countermeasure for In-Memory Tree Construction).**
    * **Objective:** Prevent massive RAM spikes (and subsequent OOM crashes) when generating the Merkle tree for extremely large files (e.g., multi-gigabyte videos).
    * **Action:** Refactor the `build()` method in `koot/storage/integrity/merkle.py`. Transition from an in-memory recursive array (`self.tree`) to a disk-backed or highly optimized streaming construction process. The system must calculate and persist lower-level hashes to a temporary store (or memory-mapped file) rather than holding the entire tree in active RAM simultaneously.

#### **Phase 4: Remediation of Telemetry & Governance**

* **Session 4.1: Asynchronous Log Rotation (Countermeasure for Thread-Blocking Log Sealing).**
    * **Objective:** Ensure that the cryptographic sealing of large audit logs does not block the primary event loop, preventing temporary system unresponsiveness during high-velocity operations.
    * **Action:** Refactor the `rotate()` method in `koot/governance/audit/log.py`. Decouple the reading and hashing of the 50MB file from the main logging thread. Implement an asynchronous worker queue or background task to handle the final hash computation and sealing, allowing the system to immediately begin writing to the new active log without waiting for the disk I/O of the previous file to complete.
