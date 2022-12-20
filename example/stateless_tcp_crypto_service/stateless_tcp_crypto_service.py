#!/usr/bin/python3

import sys 
import argparse
import socketserver
import os.path
import pprint

sys.path.insert(0, '/home/mglt/.local/lib/python3.10/site-packages')
sys.path.insert(0, '/home/mglt/gitlab/pylurk.git/src')
sys.path.insert(0, '/home/mglt/gitlab/pytls13/src')

import pylurk.cs
import pylurk.conf

## directory where the keys of the CS are stored
conf_dir = './keys'
cs_list = { 
  'stateless_tcp' : { 
    'connectivity' : { 
      'type': 'stateless_tcp',
      'ip' : '127.0.0.1', 
      'port' : 9401
     },
     ## logs are redirected to stdout especially when 
     ## the cs is running in the enclave.
     'log' : None,
     ( 'tls13', 'v1' ) : { 
       'public_key' : [ os.path.join( conf_dir, '_Ed25519PublicKey-ed25519-X509.der' ) ],
       'private_key': os.path.join( conf_dir, '_Ed25519PrivateKey-ed25519-pkcs8.der' ) ,
       'sig_scheme': ['ed25519']
     }   
  }    
}

## Building the complete configuration 
cs_conf_template = cs_list[ 'stateless_tcp' ] 
cs_conf = pylurk.conf.Configuration( )
cs_conf.merge( cs_conf_template )
cs_conf.set_role( 'client' )
cs_conf.set_tls13_authorization_type( )
cs_conf.set_tls13_cs_signing_key( )


print( 'Provided configuration:\n' )
pprint.pprint( cs_conf_template, width=65, sort_dicts=False )
print( 'Full configuration:\n' )
pprint.pprint( cs_conf.conf,  width=65, sort_dicts=False ) 
print( f"\nListening on port {cs_conf.conf[ 'connectivity'] [ 'port' ]}" )

## starting the CS
with pylurk.cs.get_cs_instance( cs_conf.conf ) as cs:
  cs.serve_forever()
