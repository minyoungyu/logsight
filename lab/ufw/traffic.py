import socket, time, sys
SRV="203.0.113.10"
def tcp(dst, port, src=None, send=b""):
    s=socket.socket(); s.settimeout(0.5)
    if src: s.bind((src,0))
    try:
        s.connect((dst,port))
        if send: s.sendall(send); s.recv(512)
        return True
    except Exception: return False
    finally: s.close()
def udp(dst,port):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"\x00probe",(dst,port)); s.close()
step=sys.argv[1]
if step=="benign":
    for _ in range(5):
        tcp("198.51.100.10",80,src="198.51.100.77",send=b"GET / HTTP/1.0\r\n\r\n"); time.sleep(1)
    tcp("198.51.100.10",443,src="198.51.100.77")
elif step=="scan":
    for p in [21,22,23,25,53,80,110,135,139,143,443,445,1433,3306,3389,5432,5900,6379,8080,8443,9200,27017]:
        tcp(SRV,p,src="203.0.113.50"); time.sleep(0.05)
    for p in [53,123,161,1900]: udp(SRV,p)
elif step=="brute":
    for i in range(25):
        tcp(SRV,22,src="203.0.113.50",send=b"SSH-2.0-libssh2_1.10\r\n"); time.sleep(0.2)
elif step=="web":
    for path in ["/","/.env","/.git/config","/wp-login.php","/admin"]:
        tcp(SRV,80,src="203.0.113.50",send=f"GET {path} HTTP/1.0\r\n\r\n".encode()); time.sleep(0.3)
    tcp(SRV,443,src="203.0.113.50")
