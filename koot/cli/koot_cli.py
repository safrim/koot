import asyncio
import json
import argparse
import sys
import os

class KootCLI:
    """
    The Headless Shell for koot.
    Contains zero cryptographic logic. Strictly forwards commands to the IPC Gateway.
    """
    def __init__(self, socket_path: str = "/tmp/koot.sock"):
        self.socket_path = socket_path

    async def send_command(self, action: str, payload: dict) -> dict:
        """Opens a connection to the local Unix Socket and sends the JSON command."""
        if not os.path.exists(self.socket_path):
            print(f"Error: Koot Core is not running or socket not found at {self.socket_path}")
            sys.exit(1)

        try:
            reader, writer = await asyncio.open_unix_connection(self.socket_path)
            
            request = {
                "action": action,
                "payload": payload
            }
            
            writer.write(json.dumps(request).encode())
            await writer.drain()

            data = await reader.read(4096)
            writer.close()
            await writer.wait_closed()
            
            return json.loads(data.decode())
            
        except Exception as e:
            print(f"IPC Communication Error: {e}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="koot Headless Shell (koot-cli)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Command: koot unlock
    unlock_parser = subparsers.add_parser("unlock", help="Unlock the local koot vault")
    
    # Command: koot get [uuid]
    get_parser = subparsers.add_parser("get", help="Retrieve a vaulted item by UUID")
    get_parser.add_argument("uuid", type=str, help="The UUID of the envelope to retrieve")

    # Command: koot override --nuke
    override_parser = subparsers.add_parser("override", help="Trigger a system override matrix command")
    override_parser.add_argument("--nuke", action="store_true", help="Execute the Dead Man's Switch protocol")

    args = parser.parse_args()
    cli = KootCLI()

    # Route the commands
    if args.command == "unlock":
        response = asyncio.run(cli.send_command("vault.unlock", {}))
    elif args.command == "get":
        response = asyncio.run(cli.send_command("vault.get", {"uuid": args.uuid}))
    elif args.command == "override":
        if args.nuke:
            response = asyncio.run(cli.send_command("system.override", {"command": "nuke"}))
        else:
            print("Error: Missing override flag (e.g., --nuke)")
            sys.exit(1)
    
    # Output the JSON response from the Koot Core
    print(json.dumps(response, indent=2))

if __name__ == "__main__":
    main()