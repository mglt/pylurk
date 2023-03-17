#!/usr/bin/python3

import sys 
import argparse
import socketserver
import os.path
import pprint
import subprocess

sys.path.insert(0, '/home/mglt/.local/lib/python3.10/site-packages')
sys.path.insert(0, '/home/mglt/gitlab/pylurk.git/src')
sys.path.insert(0, '/home/mglt/gitlab/pytls13/src')

import pylurk.cs
import pylurk.conf

""" Command Line interface to start the CS 

A configuration template -- that is to say a 
dictionary -- is generated -- from the argument 
provided by th euser -- and then pass to the Configuration(). 

Template can be manually generated. 
The template is expected to provide a single port 
to each configuration.

The template for a CS is expected to look this way:
cs_conf_template = {
'connectivity' : {
   'type': 'tcp',
   'ip' : '127.0.0.1',
   'port' : 9402
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

The reason we define a class is to be able to manage the 
various configuration of the CS with which also includes 
the implementation of illustrated_tls13 as well as the 
instantiation inside a sgx enclave. 
"""     


if __name__ == '__main__' :

  cli = pylurk.conf.CLI( )
  parser = cli.get_parser( env=True )
  args = parser.parse_args()
  print( f" --- Executing: {__file__} with {args}" )
  if args.cert == "'./sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der'":
    raise ValueError( "BAD cert" )
  ## Building the template (in general expected to 
  ## be manually generated )
  cli.init_from_args( args )
  cs_template_conf = cli.get_template( )

  print( f"cs_template_conf: {cs_template_conf}" )
  ## Building the complete configuration 
  cs_conf = pylurk.conf.Configuration( )
  cs_conf.merge( cs_template_conf )
  cs_conf.set_role( 'client' )
  cs_conf.set_tls13_authorization_type( )
  cs_conf.set_tls13_cs_signing_key( )
  
  
  print( 'Configuration Template (from end user arguments ):\n' )
  pprint.pprint( cs_template_conf, width=65, sort_dicts=False )
  print( 'Full configuration:\n' )
  pprint.pprint( cs_conf.conf,  width=65, sort_dicts=False ) 
  print( f"\nListening on port {cs_conf.conf[ 'connectivity'] [ 'port' ]}" )
  
  ## starting the CS
  with pylurk.cs.get_cs_instance( cs_conf.conf ) as cs:
    cs.serve_forever()
