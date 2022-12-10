#!/usr/bin/python3

import sys 
import argparse
import socketserver
import os.path
import pprint

sys.path.insert(0, '/home/emigdan/gitlab/pylurk.git/src')
import pylurk.cs
import pylurk.conf

conf_dir = '/home/emigdan/gitlab/pytls13/src/pytls13/clt_cs'

cs_list = { 
#  'lib_cs' : { 
#    'connectivity' : { 
#      'type': 'lib_cs', 
#      }   
#    },  
  'illustrated_tls13_stateless_tcp' : { 
    'connectivity' : { 
      'type': 'stateless_tcp',
      'ip' : '127.0.0.1', 
      'port' : 9400
     }   
   },  
  'stateless_tcp' : { 
    'connectivity' : { 
      'type': 'stateless_tcp',
      'ip' : '127.0.0.1', 
      'port' : 9401
     }, 
     'cs' : { 
       ( 'tls13', 'v1' ) : { 
         'publickey' : [ os.path.join( conf_dir, '_Ed25519PublicKey-ed25519-X509.der' ) ],
         'private_key': os.path.join( conf_dir, '_Ed25519PrivateKey-ed25519-pkcs8.der' ) ,
         'sig_scheme': ['ed25519']
       }   
     }   
  }    
}


## adding the key to all servers
for k in cs_list.keys():
  cs_list[ k ][ ( 'tls13', 'v1' ) ] = {
     'public_key' : [os.path.join( conf_dir, '_Ed25519PublicKey-ed25519-X509.der' )],
     'private_key' : os.path.join( conf_dir, '_Ed25519PrivateKey-ed25519-pkcs8.der' ), ## der, pkcs8
      'sig_scheme' : [ 'ed25519' ] }

## adding the debug information
for k in cs_list.keys():
#  print( f" --- {k}" )
#  pprint.pprint( cs_list )
  if k in [ 'illustrated_tls13_stateless_tcp' ] :
    cs_list[ k ][ ( 'tls13', 'v1' ) ][ 'debug' ] = {
      'trace' : True, 
      'test_vector' : {
         'file' :  '/home/emigdan/gitlab/pytls13/src/pytls13/illustrated_tls13.json',
         'mode' : 'record'
      }
    }
print( f"---resulting cs_list configuration" ) 
pprint.pprint( cs_list )

parser = argparse.ArgumentParser(description='Cryptographic Server')
parser.add_argument( '-t', '--type', type=ascii, default='stateless_tcp', \
  nargs='?', help='serveur type')
parser.add_argument( '-i', '--illustrated', default=False,  \
  action='store_const', const=True, help='running illustrated TLS 1.3')
args = parser.parse_args()

if args.type == "'stateless_tcp'":
  if args.illustrated is True:
    cs_conf_template = cs_list[ 'illustrated_tls13_stateless_tcp' ] 
  else: 
    cs_conf_template = cs_list[ 'stateless_tcp' ] 
  cs_conf = pylurk.conf.Configuration( )
  print("-- template CS conf (before merging):" )
  pprint.pprint( cs_conf.conf )
  cs_conf.merge( cs_conf_template )
  print("-- template CS conf (after merging):" )
  pprint.pprint( cs_conf.conf )
  cs_conf.set_role( 'client' )
  cs_conf.set_tls13_authorization_type( )
  cs_conf.set_tls13_cs_signing_key( )
else:
  raise ValueError( f"type MUST be 'stateless_tcp'. Got {args}")
pprint.pprint( f"Provide arguments: {args}" )
print( 'Provided configuration:\n' )
pprint.pprint( cs_list[ k ], width=65, sort_dicts=False )
print( 'Full configuration:\n' )
pprint.pprint( cs_conf.conf,  width=65, sort_dicts=False ) 
print( '\n' )
#with pylurk.cs.StatelessTCPCryptoService( cs_conf.conf ) as cs:
#  cs.serve_forever()
print( f"Listening on port {cs_conf.conf[ 'connectivity'] [ 'port' ]}" )
with pylurk.cs.get_cs_instance( cs_conf.conf ) as cs:
  cs.serve_forever()


#server = socketserver.TCPServer(('127.0.0.1', 9999), pylurk.cs.StatelessTCPHandler) 
#with socketserver.TCPServer((host, port), MyTCPHandler) as server:
#        # Activate the server; this will keep running until you
#        # interrupt the program with Ctrl-C
#server.serve_forever()
