"""
This is a simple scripts that performs a single exchange with the cs. 
The exchange is taken from c_tls_handshake in the test_lurk_tls13.py line 2025
The exchanges between teh TLS engine an dthe CS are not sufficient to perform a TL Shandshake. This is just for testing the ability to run the cs in a TEE (SGX)

To make it work:

```
git clone -b tls13 https://github.com/mglt/pylurk
cd pylurk/example/
python3 tee_test.py 
```

Possible useful resources:
* pylurk: https://github.com/mglt/pylurk
note we are working on the tls13 branch :https://github.com/mglt/pylurk/tree/tls13

* LURK Description : https://github.com/mglt/draft-mglt-lurk-tls13/blob/master/draft-mglt-lurk-tls13.txt
* TLS 1.3 description: https://www.rfc-editor.org/rfc/rfc8446
* Gramine: https://gramineproject.io/
"""

import secrets

## inserting the src in the search path
import sys
sys.path.insert( 0, '../tests/')
sys.path.insert( 0, '../src/')

import pylurk.struct_lurk ## LURK message structure 
  ## used to convert to/from binary to JSON and for testing 
import pylurk.conf ## configuration of the crypto service, with basic manipulation  
import pylurk.cs   ## cryptoservice
import test_utils  ## to test format  

conf = pylurk.conf.Configuration( )
conf.set_ecdhe_authentication( 'ed25519' )
conf.set_role( 'client' )
conf.set_extention( ext=( 'tls13', 'v1' ) )
print( f"c_init_client_hello_session: conf {conf.conf}" )

cs = pylurk.cs.CryptoService( conf=conf.conf )

## Forming the handshake with a client hello
## In this case the TLS Engine provides a empty key_share extension
## so the CS computes the (EC)DHE public key and returns it to the TLS Engine.

empty_ke_entry_list = []
for group in [ 'secp521r1', 'x448' ] :
  empty_ke_entry_list.append( { 'group': group , 'key_exchange' : b''} )
ext51_ch_empty = { 'extension_type': 'key_share', \
                   'extension_data' : { 'client_shares' : empty_ke_entry_list } }
hs_client_hello = {\
  'msg_type': 'client_hello', \
  'data' : {\
    'legacy_version' : b'\x03\x03',
    'random' : secrets.token_bytes( 32 ),
    'legacy_session_id' : secrets.token_bytes( 32 ),
    'cipher_suites' : ['TLS_AES_128_GCM_SHA256', 'TLS_CHACHA20_POLY1305_SHA256'],
    'legacy_compression_methods' : b'\x00',
    'extensions' : [ ext51_ch_empty ] } }

c_init_client_hello_req = { \
  'designation' : 'tls13',
  'version' : 'v1',
  'type' : 'c_init_client_hello',
  'status' : 'request',
  'id' : secrets.randbelow( 2  ** 64 ),
  'payload' : { 
     'session_id' : secrets.token_bytes( 4 ),
     'handshake' : [ hs_client_hello ],
     'freshness' : 'sha256',
     'psk_metadata_list' : [],
     'secret_request' : { 'b' : True, 'e_s' : True, 'e_x' : True , \
                          'h_c' : False, 'h_s' : False, 'a_c' : False, \
                          'a_s' : False, 'x' : False, 'r' : False }
  }
}
## testing the LURK request format
test_utils.test_struct( pylurk.struct_lurk.LURKMessage, c_init_client_hello_req, ext_title='LURK Request' )

## getting response from the CS
## when integrated with a TEE, we expect the serve function to 
## handle the interaction with the TEE
bytes_resp = cs.serve( pylurk.struct_lurk.LURKMessage.build( c_init_client_hello_req ) )
resp = pylurk.struct_lurk.LURKMessage.parse( bytes_resp )

## testing the LURK resp format
test_utils.test_struct( pylurk.struct_lurk.LURKMessage, resp, ext_title='LURK Response' )


