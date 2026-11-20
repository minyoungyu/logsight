import socket, threading, http.server, socketserver
def acceptor(port):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",port)); s.listen(64)
    while True:
        c,_=s.accept()
        try: c.sendall(b"SSH-2.0-OpenSSH_9.6\r\n" if port==22 else b""); 
        except Exception: pass
        c.close()
for p in (22,443): threading.Thread(target=acceptor,args=(p,),daemon=True).start()
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self,*a): pass
socketserver.ThreadingTCPServer.allow_reuse_address=True
socketserver.ThreadingTCPServer(("0.0.0.0",80),H).serve_forever()
