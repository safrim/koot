import argparse
import asyncio
import json
import getpass
import sys

class KootCLI:
    """
    Koot Zero-Trust Command Line Interface.
    Acts as a thin terminal client communicating with the Koot Core 
    via Unix Domain Sockets.
    """
    def __init__(self, socket_path="/tmp/koot.sock"):
        self.socket_path = socket_path

    async def send_command(self, action, payload=None):
        """JSON-over-IPC transmission logic."""
        try:
            reader, writer = await asyncio.open_unix_connection(self.socket_path)
            message = {"action": action, "payload": payload or {}}
            
            writer.write(json.dumps(message).encode())
            await writer.drain()
            
            # Read response from the core server
            data = await reader.read(8192)
            writer.close()
            await writer.wait_closed()
            
            return json.loads(data.decode())
        except FileNotFoundError:
            return {"status": "error", "message": "Koot Core is not running (Socket not found)."}
        except ConnectionRefusedError:
            return {"status": "error", "message": "Connection refused. Is 'start_core.py' active?"}
        except Exception as e:
            return {"status": "error", "message": f"CLI error: {str(e)}"}

def main():
    parser = argparse.ArgumentParser(description="Koot Zero-Trust CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. COMMAND: unlock
    subparsers.add_parser("unlock", help="Authenticate and open the vault session")

    # 2. COMMAND: add (Create/Update)
    add_p = subparsers.add_parser("add", help="Encrypt and save a secret")
    add_p.add_argument("key", help="The name/alias for the secret")
    add_p.add_argument("value", help="The plaintext data to encrypt")

    # 3. COMMAND: read (Read)
    read_p = subparsers.add_parser("read", help="Retrieve and decrypt a secret")
    read_p.add_argument("key", help="The alias of the secret to read")

    # 4. COMMAND: delete (Delete)
    del_p = subparsers.add_parser("delete", help="Purge a secret from the vault")
    del_p.add_argument("key", help="The alias of the secret to remove")

    # 5. COMMAND: override (System Management)
    over_p = subparsers.add_parser("override", help="System management and emergency protocols")
    over_p.add_argument("--nuke", action="store_true", help="Total cryptographic wipe and shutdown")

    args = parser.parse_args()
    cli = KootCLI()

    # --- ROUTING LOGIC ---

    if args.command == "unlock":
        pw = getpass.getpass("Enter Master Password: ")
        resp = asyncio.run(cli.send_command("vault.unlock", {"password": pw}))
        print(json.dumps(resp, indent=2))

    elif args.command == "add":
        resp = asyncio.run(cli.send_command("vault.add", {"key": args.key, "value": args.value}))
        print(json.dumps(resp, indent=2))

    elif args.command == "read":
        resp = asyncio.run(cli.send_command("vault.read", {"key": args.key}))
        # Print the raw data if successful, otherwise print the JSON error
        if resp.get("status") == "success":
            print(resp.get("data"))
        else:
            print(json.dumps(resp, indent=2))

    elif args.command == "delete":
        resp = asyncio.run(cli.send_command("vault.delete", {"key": args.key}))
        print(json.dumps(resp, indent=2))

    elif args.command == "override":
        if args.nuke:
            confirm = input("CRITICAL: This will destroy all vault data and the salt. Proceed? (y/N): ")
            if confirm.lower() == 'y':
                resp = asyncio.run(cli.send_command("system.override", {"command": "nuke"}))
                print(json.dumps(resp, indent=2))
            else:
                print("Nuke aborted.")
        else:
            print("Usage: koot override --nuke")

if __name__ == "__main__":
    main()