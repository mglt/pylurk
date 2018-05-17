import http.server
import socketserver
import ssl


"""
Instantiates a HTTPS server in order to be able to capture 
parameters and test LURK exchanges.

start the server: 
    set auth to 'rsa' or 'ecdhe-rsa'

capture the tls session exchange with wireshark using:
    penssl s_client -connect localhost:443
"""
auth = 'ecdhe-rsa'

#rsa
if auth == 'rsa':
    certfile = '../data/serverX509Cert.pem'
    keyfile = '../data//serverX509Key.pem'
    ciphers = 'AES128-GCM-SHA256'
elif auth == 'ecdhe-rsa':
    certfile = './serverX509Cert.pem'
    keyfile = './serverX509Key.pem'
    ciphers = 'ECDHE-RSA-AES128-GCM-SHA256'
#ecdhe-ecdsa
if auth == 'ecdhe-ecdsa':
    certfile = './cert-rsa-sig.pem'
    keyfile = './key-rsa-sig.pem'
    ciphers = 'ECDHE-RSA-AES128-GCM-SHA256'

ssl_ctx = ssl.SSLContext(protocol = ssl.PROTOCOL_TLSv1_2)
ssl_ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
ssl_ctx.set_ciphers( ciphers)

ssl_ctx.set_ecdh_curve('prime256v1')
PORT= 443

Handler = http.server.SimpleHTTPRequestHandler



with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print("serving at port", PORT)
    httpd.socket = ssl_ctx.wrap_socket (httpd.socket,
                                server_side=True ) 
    httpd.serve_forever()



