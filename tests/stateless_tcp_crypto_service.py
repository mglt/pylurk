
import sys 
sys.path.insert(0, '/home/emigdan/gitlab/pylurk.git/src')
import pylurk.cs
import pylurk.conf
import socketserver


sig_scheme = 'ed25519'
cs_conf = pylurk.conf.Configuration( )
cs_conf.set_ecdhe_authentication( sig_scheme, conf_dir = '/home/emigdan/gitlab/pytls13/src/pytls13/clt_cs' )
#cs_conf.set_role( 'client' )
cs_conf.set_extention( ext=( 'tls13', 'v1' ) )
## removing unecessy lurk exchange
## we need to complete this depending on the configuration ( for example
## if there is no session resumption, no post handshake, 
#for k in cs_conf.conf[ ( 'tls13', 'v1' ) ][ 'type_authorized'] :
#  if ( clt_conf[ 'role' ] == 'client' and k[0:2] == 's_' ) or\
#     ( clt_conf[ 'role' ] == 'server' and k[0:2] == 'c_' ):
#      cs_conf.conf[ ( 'tls13', 'v1' ) ][ 'type_authorized'].remove( k )
#
cs_conf.conf[ ( 'tls13', 'v1' ) ][ 'debug' ] =  { 
    'trace' : True,  # prints multiple useful information
    'test_vector' : False,
    'test_vector_file' : '/home/emigdan/gitlab/pytls13/src/pytls13/illustrated_tls13.json',
    'test_vector_mode' : 'check', # check / record
  }
cs_conf.conf[ 'connectivity' ] = { 'type': 'stateless_tcp',\
                                       'ip_address' : '127.0.0.1',\
                                       'port': 9999 }

#with pylurk.cs.StatelessTCPCryptoService( cs_conf.conf ) as cs:
#  cs.serve_forever()

with pylurk.cs.get_cs_instance( cs_conf.conf ) as cs:
  cs.serve_forever()


#server = socketserver.TCPServer(('127.0.0.1', 9999), pylurk.cs.StatelessTCPHandler) 
#with socketserver.TCPServer((host, port), MyTCPHandler) as server:
#        # Activate the server; this will keep running until you
#        # interrupt the program with Ctrl-C
#server.serve_forever()
