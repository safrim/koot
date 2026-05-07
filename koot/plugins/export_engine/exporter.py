import csv
import json
import os
from typing import List, Dict

class ExportEscrowPlugin:
    def __init__(self, bus, override_matrix):
        """
        Initializes the Export & Escrow Utility with access to the core bus
        and the override matrix for security clearance.
        """
        self.bus = bus
        self.override_matrix = override_matrix

    def export_to_csv(self, vault_ids: List[str], output_path: str, admin_token: str) -> bool:
        """
        Exports decrypted secrets to a plaintext CSV. 
        Requires explicit authorization via the Override Matrix.
        """
        # 1. Trigger Override Matrix for plaintext export warning
        if not self.override_matrix.request_authorization("PLAINTEXT_CSV_EXPORT", admin_token):
            raise PermissionError(
                "Export aborted: Admin override authorization failed for plaintext CSV export. "
                "Plaintext exports pose a severe security risk."
            )

        # 2. Decrypt in volatile memory
        decrypted_records = self._decrypt_envelopes(vault_ids)

        if not decrypted_records:
            raise ValueError("No records found or decrypted.")

        # 3. Write to CSV
        keys = decrypted_records[0].keys()
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(decrypted_records)
        finally:
            # 4. Volatile memory wipe simulation 
            # In a stricter memory-managed environment, overwrite the memory blocks here.
            decrypted_records.clear()
            
        return True

    def export_to_koot_archive(self, vault_ids: List[str], output_path: str) -> bool:
        """
        Exports secrets into a standardized koot-archive format.
        """
        # 1. Decrypt in volatile memory
        decrypted_records = self._decrypt_envelopes(vault_ids)

        # 2. Package into koot-archive format
        archive_payload = {
            "format": "koot-archive",
            "version": "1.0",
            "data": decrypted_records
        }

        # Note: In a full pipeline, archive_payload is passed to the Hybrid-PQC engine
        # to be re-encrypted with a user-provided Escrow password before touching the disk.
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(archive_payload, f, indent=4)
        finally:
            # 3. Volatile memory wipe
            decrypted_records.clear()
            
        return True

    def _decrypt_envelopes(self, vault_ids: List[str]) -> List[Dict]:
        """
        Internal helper to fetch and decrypt envelopes via the Registry Bus.
        """
        records = []
        for v_id in vault_ids:
            # Dispatch to the bus to handle cryptographic unsealing
            response = self.bus.dispatch("storage", "unvault_secret", payload={"uuid": v_id})
            if response and "data" in response:
                records.append(response["data"])
        return records