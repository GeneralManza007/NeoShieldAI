import socket
for i in range(30):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect(("192.168.1.129", 22))
        s.close()
        print(f"{i+1} OK")
    except: pass