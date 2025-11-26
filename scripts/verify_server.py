import socket
import json
import time

HOST = '127.0.0.1'
PORT = 65432

def send_command(cmd):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(cmd.encode('utf-8'))
            data = s.recv(4096)
            return data.decode('utf-8')
    except Exception as e:
        return f"ERROR: {e}"

def verify():
    print("Verifying commands...")
    
    # 1. gettimestamp
    res = send_command("gettimestamp")
    print(f"gettimestamp: {res.strip()}")
    assert "Current Timestamp" in res
    
    # 2. getbalance (genesis)
    genesis = "91423993fe5c3a7e0c0d466d9a26f502adf9d39f370649d25d1a6c2500d277212e8aa23e0e10c887cb4b6340d2eebce6"
    res = send_command(f"getbalance {genesis}")
    print(f"getbalance: {res.strip()}")
    assert "BALANCE:" in res
    
    # 3. getsequence
    res = send_command(f"getsequence {genesis}")
    print(f"getsequence: {res.strip()}")
    assert "SEQUENCE:" in res
    
    # 4. history
    res = send_command(f"history {genesis}")
    print(f"history: {res.strip()}")
    assert "HISTORY:" in res

    print("Verification successful!")

if __name__ == "__main__":
    verify()
