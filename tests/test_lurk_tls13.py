import sys
import traceback
from copy import deepcopy
import json
import pprint

from secrets import token_bytes
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from secrets import randbelow

#from pylurk.extensions.tls13 import Conf, ConfBuilder, SSession,CSession, get_struct_index
#from pylurk.core.lurk import LurkServer
#from pylurk.core.lurk_struct import LURKMessage

## inserting the src in the search path 
import sys
sys.path.insert( 0, '../src/')


from pylurk.struct_lurk import *
from pylurk.tls13.struct_lurk_tls13 import *
from pylurk.tls13.struct_tls13 import *
from pylurk.tls13.lurk_tls13 import CSession, SSession, get_struct_index, TlsHandshake, TicketDB, SessionDB
from pylurk.conf import Configuration
from pylurk.cs import CryptoService

from test_utils import *

## from pylurk.utils.utils import set_title
## cannot import because construct 2.10 does not support Embedded 


""" 
This module contains a number of tests for the LURK extension for TS 1.3:

I. TLS 1.3 LURK extensions structures
The structure are quite low level and the purpose is more to test if the structures we defined with contruct. The test of a (dictionary) against a given structure is performed with the `test_struct` fonction.

II. Global variable for TLS 1.3 structures
Defines TLS 1.3 structure that are useful to test various possible type of handshake.
This section can mostly be seen as a definition of macros to be used later. 

III. TLS 1.3 LURK Extension Payload Format
Tests various possible (valid or expected) Payload format  
  III.1 Payload (S/C) InitCertVerify Req and Resp
  III.2 Payload SInitEarlySecret Req and Resp 
  III.3 Payload SHandAndApp Req and Resp  
  III.4 Payload SNewTicket Req and Resp 

IV. Payload Exchange
Tests the TLS 1.3 LURK Extension serving request Payload. The response payload are returned via the Session object. 
  IV.1 Payload Exchange s_init_cert_verify
  IV.2 Payload Exchange s_new_ticket
  IV.3 Payload Exchange Server Session Resumption: s_init_cert_verify - s_new_ticket s_init_early_secret - s_hand_and_app_secret - s_new_ticket


V. Crypto Engine Exchange
Test the TLS 1.3 Crypto Engine.
  V.1 Server Session Resumption: s_init_cert_verify - s_new_ticket s_init_early_secret - s_hand_and_app_secret - s_new_ticket


"""

## indicates Payload exchanges IV.1 and IV.2 are performed
TLS_SERVER_PAYLOAD_EXCHANGE = False
## indicates Payload exchanges in IV.3 is performed
## as all signature scheme are tested, it takes a lot of time.
TLS_SERVER_PAYLOAD_SESSION_RESUMPTION_LOOP = False

## session resumption with a Crypto Engine for the signature scheme ed25519
TLS_SERVER_LURK_MESSAGE_RESUMPTION = False
## session resumption with a Crypto Engine for all signature schemes
## takes a lot of time
TLS_SERVER_LURK_MESSAGE_RESUMPTION_LOOP = False

TLS_CLIENT_PAYLOAD_EXCHANGE = True
TLS_CLIENT_EXCHANGE = True 

##DEBUG_MODE = False




print( "###########################################" )
print( "## I. TLS 1.3 LURK extensions structures ##" )
print( "###########################################" )

## SecretRequest
secret_request = {"b":True, "e_s":False, "e_x":True, "h_c":False,\
               "h_s":True, "a_c":False, "a_s":True, "x":False, \
               "r":True}
binary, struct = test_struct(SecretRequest, secret_request)

# tag
for i in [ True, False ]:
  tag = { 'last_exchange' : True }
  binary, struct = test_struct( Tag, tag)


## Secret
secret_data = b'secret'
for secret_type in ['b', 'e_s', 'e_x', 'h_c', 'h_s', 'a_c', 'a_s', 'x', 'r']:
  secret = {'secret_type': secret_type, 'secret_data': secret_data}
  test_struct(Secret, secret, ext_title=secret_type)

## Freshness
freshness = 'sha256'
test_struct( Freshness, freshness, ext_title='Freshness')

## Ephemeral (no_secret)
eph_no = { 'method': 'no_secret', 'key': b'' }
for status in [ 'request', 'success' ]: 
  ctx_struct = { '_status' : status }
  test_struct( Ephemeral, eph_no, ext_title='no secret', ctx_struct=ctx_struct )

## Ephemeral (e_generated)
shared_secret = { 'group' : 'secp256r1', 'shared_secret' : token_bytes(32) }
eph_e_req = { 'method': 'e_generated', 'key': shared_secret }
ctx_struct = {'_status' : 'request'}
test_struct( Ephemeral, eph_e_req, ext_title='e_generated', ctx_struct=ctx_struct )

eph_e_resp = { 'method': 'e_generated', 'key': None } # empty in response
ctx_struct = {'_status' : 'success'}
test_struct( Ephemeral, eph_e_resp, ext_title='e_generated', ctx_struct=ctx_struct )


## Ephemeral (cs_generated)
  ## TLS engine requests the generation
eph_cs_req = { 'method': 'cs_generated', 'key': None } 
ctx_struct = {'_status' : 'request'}
test_struct( Ephemeral, eph_cs_req, ext_title="cs_generated", ctx_struct=ctx_struct )
  ## CS generates private/ public part of teh ECDHE
#private_key = ec.generate_private_key( ec.SECP256R1(), default_backend())
private_key = ec.generate_private_key( ec.SECP256R1() )
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()
x = public_numbers.x
y = public_numbers.y
  ## CS returns the public part of teh ECDHE using the KeyShare Entry format
key_exchange = {'legacy_form' : 4, 'x' : x, 'y' : y }
keyshare_entry = { 'group' : 'secp256r1', 'key_exchange' : key_exchange }
  ## CS response
eph_cs_resp = { 'method': 'cs_generated', 'key': keyshare_entry } 
ctx_struct = {'_status' : 'success'}
test_struct( Ephemeral, eph_cs_resp, ext_title="cs_generated", ctx_struct=ctx_struct )

## certificate ( empty )
#no_cert = { 'certificate_type': 'no_certificate', 'certificate_data' : b'' }
#test_struct( LURKTLS13Certificate, no_cert, ext_title = "no_certificate" ) 

## no_certificate
no_cert = { 'cert_type' : 'no_certificate', 'certificate' : b'' }
test_struct( Cert, no_cert, ext_title = "no_certificate" ) 

## uncompressed
certificate_entry = {'cert' : b'certificate_entry', 'extensions':[] }
certificate = { 'certificate_request_context': b'',
                'certificate_list' : [certificate_entry, certificate_entry] }
uncompressed_cert = { 'cert_type' : 'uncompressed',\
                      'certificate' : certificate }
test_struct( Cert, uncompressed_cert, ext_title = "uncompressed" ) 

## finger_print
digest = Hash( SHA256() )
digest.update( certificate_entry[ 'cert' ] )
finger_certificate_entry = { 'finger_print' : digest.finalize()[ : 4 ],\
                             'extensions' : [] }
finger_print_certificate = \
  { 'certificate_request_context': b'',
    'certificate_list'  : [ finger_certificate_entry, finger_certificate_entry ] }  
finger_print_cert = { 'cert_type' : 'finger_print', \
                      'certificate' : finger_print_certificate }

test_struct( Cert, uncompressed_cert, ext_title = "finger_print cert" ) 

compressed_certificate = \
  { 'algorithm' : 'zlib', \
    'uncompressed_length' : 512, \
    'compressed_certificate_message' : b'\x00\x00'} 
compressed_cert = {  'cert_type' : 'zlib', \
                     'certificate' : compressed_certificate } 
test_struct( Cert, compressed_cert, ext_title = "compressed cert" ) 


## certificate ( finger_print )
#cert_entry = {'cert' : b'certificate_entry', 'extensions':[] }
  ## TLS certificate structure 
hs_cert = { 'msg_type' : 'certificate', 
            'data' : certificate }
#digest = Hash( SHA256(), backend=default_backend())
#digest = Hash( SHA256() )
#digest.update( Handshake.build( hs_cert, _certificate_type='X509' ))
#cert_finger = {'certificate_type': 'finger_print', 'certificate_data': digest.finalize()[:4]}
#test_struct( LURKTLS13Certificate, cert_finger, ext_title = "finger_print" ) 

## certificate ( uncompressed) 
#cert_uncompressed = {'certificate_type': 'uncompressed', 
#                     'certificate_data': hs_cert[ 'data' ] }
#ctx_struct = { '_certificate_type' : 'X509' }
#test_struct( Certificate, hs_cert[ 'data' ],\
#             ext_title = "certificate", ctx_struct=ctx_struct ) 
#test_struct( LURKTLS13Certificate, cert_uncompressed,\
#             ext_title = "uncompressed", ctx_struct=ctx_struct ) 

## psk_id
psk_id = { 'identity': b'key_id', 'obfuscated_ticket_age': b'\x00\x01\x02\x03'}
test_struct( PskIdentity, psk_id ) 



print( "####################################################" )
print( "## II. Global variable for TLS 1.3 structures    ##" )
print( "####################################################" )


## supported_signature_algorithms (all signatures)
sig_list = [
  'rsa_pkcs1_sha256',
  'rsa_pkcs1_sha384',
  'ecdsa_secp256r1_sha256',
  'ecdsa_secp384r1_sha384',
  'ed25519', 'ed448'
  ]
ext13 = {'extension_type': 'signature_algorithms', \
       'extension_data' : { 'supported_signature_algorithms' : sig_list} }
## psk_key_exchange_mode (all modes)
ext45 = {'extension_type': 'psk_key_exchange_modes', \
         'extension_data' : {'ke_modes' : ['psk_ke', 'psk_dhe_ke']} }
##post-handshake authentication
ext49 = {'extension_type': 'post_handshake_auth', \
       'extension_data' : {} }
## supported groups (all groups)
ext10 = {'extension_type': 'supported_groups', \
       'extension_data' : {'named_group_list' : ['secp256r1', 'secp384r1',\
                                                   'x25519', 'x448' ]} }

## key_share
private_key = ec.generate_private_key( ec.SECP256R1() )
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()
x = public_numbers.x
y = public_numbers.y
secp256r1_key = { 'legacy_form' : 4, 'x' : x, 'y' : y }
ke_entry_secp256r1 = {'group': 'secp256r1', 'key_exchange' : secp256r1_key}

private_key = ec.generate_private_key( ec.SECP384R1() )
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()
x = public_numbers.x
y = public_numbers.y
secp384r1_key = { 'legacy_form' : 4, 'x' : x, 'y' : y }
ke_entry_secp384r1 = {'group': 'secp384r1', 'key_exchange' : secp384r1_key}

private_key = ec.generate_private_key( ec.SECP521R1() )
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()
x = public_numbers.x
y = public_numbers.y
secp521r1_key = { 'legacy_form' : 4, 'x' : x, 'y' : y }
ke_entry_secp512r1 = {'group': 'secp521r1', 'key_exchange' : secp521r1_key}

private_key = X25519PrivateKey.generate()
public_key = private_key.public_key()
x25519_key = public_key.public_bytes(
          encoding=serialization.Encoding.Raw,
          format=serialization.PublicFormat.Raw)
ke_entry_x25519 = {'group': 'x25519', 'key_exchange' : x25519_key}
private_key = X448PrivateKey.generate()
public_key = private_key.public_key()
x448_key = public_key.public_bytes(
          encoding=serialization.Encoding.Raw,
          format=serialization.PublicFormat.Raw)
ke_entry_x448 = {'group': 'x448', 'key_exchange' : x448_key}

ke_entries = [ke_entry_secp256r1,
              ke_entry_secp384r1,
              ke_entry_secp512r1,
              ke_entry_x25519,
              ke_entry_x448 ]

## ext51 for the clienthello
ext51_ch = {'extension_type': 'key_share', \
            'extension_data' : {'client_shares' : ke_entries} }
##  ext51_sh for the server hello with x448 for ECDHE being selected
ext51_sh = {'extension_type': 'key_share', \
            'extension_data' : {'server_share' : ke_entries[ -1 ] } }
## lurk specific format when the ECDHE is generated by the CS on the TLS server
ext51_sh_empty = {'extension_type': 'key_share', \
                  'extension_data' : { 'server_share': {'group': 'x448', 'key_exchange': b'' } } }


## lurk specific format when the ECDHE is generated by the CS on the TLS client
empty_ke_entries = []
for entry in ke_entries :
  empty_entry = { 'group': entry[ 'group' ] , 'key_exchange' : b''}
  empty_ke_entries.append( empty_entry ) 
  test_struct( EmptyKeyShareEntry, empty_entry ) 

ext51_ch_empty = { 'extension_type': 'key_share', \
                   'extension_data' : { 'client_shares' : empty_ke_entries } }

test_struct( PartialKeyShareClientHello, { 'client_shares' : empty_ke_entries }  )
test_struct( PartialKeyShareClientHello, { 'client_shares' : ke_entries }  )
mixed_ke_entries = deepcopy( empty_ke_entries )
mixed_ke_entries.extend( ke_entries )
print( f"mixed entries : {mixed_ke_entries} " )
test_struct( PartialKeyShareClientHello, { 'client_shares' : mixed_ke_entries }  )

pche_bytes = PartialCHExtension.build( ext51_ch_empty, _msg_type='client_hello' )
print( f"ext51_ch_empty (bytes) : {pche_bytes}" )
pche_cont = PartialCHExtension.parse( pche_bytes, _msg_type='client_hello' )
print( f"ext51_ch_empty : {pche_cont}" )

test_struct( PartialCHExtension, ext51_ch_empty, ctx_struct= { '_msg_type' : 'client_hello'  } )

## psk_extension
psk_id = { 'identity' : b'\x00\x00', \
           'obfuscated_ticket_age' : b'\x00\x01\x02\x03' }
psk_binder = {'binder' : b'\xff\xff\xff\xff'}
offered_psks= { 'identities' : [psk_id, psk_id], \
                'binders' : [psk_binder, psk_binder]}
ext41_ch = { 'extension_type': 'pre_shared_key', \
             'extension_data' : offered_psks }

offered_psks_with_no_binders = { 'identities' : [psk_id, psk_id] }
test_struct( OfferedPsksWithNoBinders, offered_psks_with_no_binders )

ext41_ch_no_binders = { 'extension_type': 'pre_shared_key', \
                        'extension_data' : { 'identities' : [psk_id, psk_id] } }
test_struct( PartialCHExtension, ext41_ch_no_binders,  ctx_struct={ '_msg_type' : 'client_hello' } )


ext41_sh =  { 'extension_type': 'pre_shared_key', \
              'extension_data' : 0 }

hs_client_hello = {\
  'msg_type': 'client_hello', \
  'data' : {\
    'legacy_version' : b'\x03\x03',
    'random' : token_bytes( 32 ),
    'legacy_session_id' : token_bytes( 32 ),
    'cipher_suites' : ['TLS_AES_128_GCM_SHA256', 'TLS_CHACHA20_POLY1305_SHA256'],
    'legacy_compression_methods' : b'\x00',
    'extensions' : [ ext13, ext45, ext49, ext10, ext51_ch ] } }

hs_client_hello[ 'data' ][ 'extensions' ] = \
   [ ext13, ext45, ext49, ext10, ext51_ch ]
hs_server_hello = {\
  'msg_type': 'server_hello', 
  'data' : {
    'legacy_version' : b'\x03\x03',
    'random' : token_bytes( 32 ),
    'cipher_suite' :'TLS_AES_128_GCM_SHA256',
    'legacy_compression_method' : b'\x00',
    'extensions' : [ ext49, ext10 ] } } 

hs_encrypted_extensions = {
  'msg_type' : 'encrypted_extensions',
  'data' : { 'extensions' :  [ ext49, ext13, ext45 ] } }
hs_certificate_request = {
  'msg_type' : 'certificate_request',
  'data' : { 'certificate_request_context' :  b'\x00\x01',
             'extensions' : [ ext49, ext13, ext45 ] } }
hs_finished = {
  'msg_type' : 'finished',
  'data' : {'verify_data' : token_bytes( 32 )}}

hs_certificate_verify = {
  'msg_type' : 'certificate_verify',
  'data' : { 'algorithm' : 'ed25519',
             'signature' : b'\x00\x01\x02' }}

cert_entry = {'cert' : b'\x00\x01\x02\x03',\
              'extensions':[] }
hs_certificate = {
  'msg_type' : 'certificate',
  'data' : { 'certificate_request_context' : b'\x00\x01',
             'certificate_list' : [ cert_entry, cert_entry, cert_entry ] }
}



print( "#####################################################" )
print( "## III.1 Payload (S/C) InitCertVerify Req and Resp ##" )
print( "#####################################################" )

## SInitCertVerifyRequest

def s_init_cert_verify_handshake_list( ephemeral_mode:str ) -> list:
  """ returns a list of possible TLS handshake messages 

  The list contains the possible TLS messages for s_init_cert_verify
  """

  hs_client_hello = {\
  'msg_type': 'client_hello', \
  'data' : {\
    'legacy_version' : b'\x03\x03',
    'random' : token_bytes( 32 ),
    'legacy_session_id' : token_bytes( 32 ),
    'cipher_suites' : ['TLS_AES_128_GCM_SHA256', 'TLS_CHACHA20_POLY1305_SHA256'],
    'legacy_compression_methods' : b'\x00',
    'extensions' : [ ext13, ext45, ext49, ext10, ext51_ch ] } }

  hs_client_hello[ 'data' ][ 'extensions' ] = \
     [ ext13, ext45, ext49, ext10, ext51_ch ]

  ext51_sh_empty = {'extension_type': 'key_share', \
                    'extension_data' : { 'server_share': {'group': 'x448', \
                                         'key_exchange': b'' } } }
  private_key = X448PrivateKey.generate()
  public_key = private_key.public_key()
  x448_key = public_key.public_bytes(
          encoding=serialization.Encoding.Raw,
          format=serialization.PublicFormat.Raw)
  ke_entry_x448 = {'group': 'x448', 'key_exchange' : x448_key}

  ext51_sh = {'extension_type': 'key_share', \
              'extension_data' : \
                {'server_share' : {'group': 'x448', 'key_exchange' : x448_key} } } 

  hs_server_hello = {\
  'msg_type': 'server_hello', 
  'data' : {
    'legacy_version' : b'\x03\x03',
    'random' : token_bytes( 32 ),
    'cipher_suite' :'TLS_AES_128_GCM_SHA256',
    'legacy_compression_method' : b'\x00',
    'extensions' : [ ] } }  

  
  hs_encrypted_extensions = {
    'msg_type' : 'encrypted_extensions',
    'data' : { 'extensions' :  [ ext49, ext13, ext45 ] } }
  hs_certificate_request = {
    'msg_type' : 'certificate_request',
    'data' : { 'certificate_request_context' :  b'\x00\x01',
             'extensions' : [ ext49, ext13, ext45 ] } }
  
  ## taking a local copy to operate changes.
  lhs_server_hello = deepcopy( hs_server_hello )
  if ephemeral_mode == 'cs_generated': # generated by cs
#    lhs_server_hello[ 'data' ][ 'extensions' ].append( ext51_sh_empty )
    lhs_server_hello[ 'data' ][ 'extensions' ] = [ ext51_sh_empty ]
  else: 
#    lhs_server_hello[ 'data' ][ 'extensions' ].append( ext51_sh )
    lhs_server_hello[ 'data' ][ 'extensions' ] = [ ext51_sh ]

  hs = [ hs_client_hello, lhs_server_hello, hs_encrypted_extensions,\
         hs_certificate_request ]
  hs_list = [ hs, deepcopy( hs )[:-1] ]
  for handshake in hs_list:
    ks = hs[ 1 ][ 'data' ][ 'extensions' ][ 0 ] [ 'extension_data' ] [  'server_share' ] [ 'key_exchange'  ]
    print( f"\n--- s_init_cert_verify_request_list : ks : {ks} / {ephemeral_mode}\n" )
    if ks != b'' and ephemeral_mode == 'cs_generated' :
      print(  f"ext51_sh_empty : {ext51_sh_empty}")
      raise ValueError()

  return hs_list 

#def s_init_cert_verify_request_list( sig_algo: str ='ed25519', conf=None, last_exchange=None ):
def s_init_cert_verify_request_list( sig_algo: str ='ed25519', \
                                   tls13_conf=None, last_exchange=None ):
 

  if tls13_conf == None:
    finger_print_entry_list = [ { 'finger_print' : token_bytes( 4 ), 'extensions' : [] } ]
    cert_entry_list = [ { 'cert' : b'public bytes', 'extensions' : [] } ]
#    lhs_certificate = deepcopy( hs_certificate )
  else: ## conf overwrites the parameters
    cert_entry_list = tls13_conf[ '_cert_entry_list' ]
    finger_print_entry_list = tls13_conf[ '_finger_print_entry_list' ]
    
  uncompressed_cert = \
    { 'cert_type' : 'uncompressed', 
      'certificate' : { 'certificate_request_context': b'', 
                         'certificate_list' : cert_entry_list } }
  finger_print_cert = \
    { 'cert_type' : 'finger_print', 
      'certificate' : { 'certificate_request_context': b'', 
                         'certificate_list' : finger_print_entry_list } }
      
#    lhs_certificate = deepcopy( { 'msg_type' : 'certificate', 
#                                  'data' : uncompressed_cert[ 'certificate' ] } )
  print( f"finger_print_cert : {finger_print_cert}" )  
  if last_exchange == None:
    last_exchange_list = [ True, False ]
  else:
    last_exchange_list = [ last_exchange ]

  list_req = []
  eph_cs_req = { 'method': 'cs_generated', 'key': None }
  shared_secret = { 'group' : 'secp256r1', 'shared_secret' : token_bytes(32) }
  eph_e_req = { 'method': 'e_generated', 'key': shared_secret }
  eph_list = [ eph_cs_req, eph_e_req ]
  for last_exchange in last_exchange_list:
    if last_exchange == False:
      session_id = token_bytes( 4 )
    else:
      session_id = b''
    for ephemeral in eph_list:
      method = ephemeral[ 'method' ]
      for handshake in s_init_cert_verify_handshake_list( method ):
        ks = handshake[ 1 ][ 'data' ][ 'extensions' ][ 0 ] [ 'extension_data' ] [  'server_share' ] [ 'key_exchange'  ]
        print( f"\n--- s_init_cert_verify_request_list : ks : {ks} / {method}\n" )
        if ks != b'' and ephemeral[ 'method' ] == 'cs_generated' :
          raise ValueError()
        for cert in [ finger_print_cert, uncompressed_cert ]:
          init_cert_verify_req = {\
            'tag' : { 'last_exchange' : last_exchange }, 
            'session_id' : session_id, 
            'freshness' : 'sha256',
            'ephemeral' : ephemeral, 
            'handshake' : handshake, 
            'certificate' : cert,
            'secret_request' : \
              { "b":False, "e_s":False, "e_x":False, "h_c":True,\
                "h_s":True, "a_c":True, "a_s":True, "x":True, "r":False },
            'sig_algo' : sig_algo }
          ks = init_cert_verify_req[ 'handshake' ][ 1 ][ 'data' ][ 'extensions' ][ 0 ] [ 'extension_data' ] [  'server_share' ] [ 'key_exchange'  ]
          print( f"-+- s_init_cert_verify_session : ks : {ks} / {init_cert_verify_req[ 'ephemeral' ]}\n" )
         ## checking 'cs_generated' is sent with empty server_share 
          if ks != b'' and init_cert_verify_req[ 'ephemeral' ][ 'method' ] == 'cs_generated' :
            raise ValueError()
          list_req.append( init_cert_verify_req )
  return list_req

def s_init_cert_verify_request_title( req:dict ) -> str:
  """ returns request string description 

  The intent is to print arguments that qualifies req
  """

  tag = req[ 'tag' ][ 'last_exchange' ]
  eph = req[ 'ephemeral' ][ 'method' ]
  try: 
    cert = req[ 'certificate' ]['cert_type'] 
  except KeyError:
    cert = req[ 'client_certificate' ]['cert_type']
  return "last_exchange [%s] - %s - cert_type [%s]"%( tag, eph, cert )

def s_init_cert_verify_test( payload, status ):
  """ tests if payload format matches  (s/c) init_cert_verify request/response """

  ctx_struct = { '_type' : 's_init_cert_verify', '_status' : status }
  if status == 'request':
    ext_title = s_init_cert_verify_request_title( payload )
    SInitCertVerifyRequest.build( payload, **ctx_struct )
  elif status == 'success':
    ext_title = init_cert_verify_response_title( payload )
    SInitCertVerifyResponse.build( payload, **ctx_struct )
#  ctx_struct = { '_type' : _type, '_certificate_type' : 'X509',\
#                 '_status' : status }
  else:
    raise ValueError( f"unexpected status {status}. Expecting 'request' or 'success'" )
  test_struct( TLS13Payload, payload, ctx_struct=ctx_struct, \
               ext_title=ext_title, print_data_struct=True, print_binary=True) 

if TLS_SERVER_PAYLOAD_EXCHANGE is True :
  ## testing various configurations of (s/c) init_cert_verify request/responses
  for req in s_init_cert_verify_request_list( ):
    #  ext_title = s_init_cert_verify_request_title( req )
    s_init_cert_verify_test( req, 'request' )


## SInitCertVerifyResponse

def init_cert_verify_response_list( sig_algo: str ='ed25519' ):
  """ returns the list of possible response of s_init_cert_verify """

  eph_list = [ eph_cs_resp, eph_e_resp ]

  list_resp = []
  for last_exchange in [ True, False ]:
    if last_exchange is False:
      session_id = token_bytes( 4 )
    else:
      session_id = None
    for ephemeral in eph_list :
      list_resp.append( {\
        'tag' : { 'last_exchange' : last_exchange }, 
        'session_id' : session_id, 
        'ephemeral' : ephemeral, 
        'secret_list' : [ \
          {'secret_type': 'h_c', 'secret_data': b'hand_client_secret' }, 
          {'secret_type': 'h_s', 'secret_data': b'hand_server_secret' },
          {'secret_type': 'a_c', 'secret_data': b'app_client_secret' },
          {'secret_type': 'a_s', 'secret_data': b'app_server_secret' } ],
       'signature' : b'signature' } )
  return list_resp

def init_cert_verify_response_title( resp:dict ) -> str:
  """ returns request string description """

  print( f" +++ {resp}" )
  tag = resp[ 'tag' ][ 'last_exchange' ]
  eph = resp[ 'ephemeral' ][ 'method' ]
  try: 
    eph = resp[ 'ephemeral' ][ 'method' ]
    return "last_exchange [%s] - %s"%( tag, eph)
  except KeyError:
    return f"last_exchange [{tag}] "


if TLS_SERVER_PAYLOAD_EXCHANGE is True :
  for resp in init_cert_verify_response_list( sig_algo='ed25519' ):
    s_init_cert_verify_test( resp, 'success' )


















print( "###################################################" )
print( "## III.2 Payload SInitEarlySecret Req and Resp   ##" )
print( "###################################################" )

## SInitEarlySecretRequest

def s_init_early_secret_handshake_list( psk_id=None ) -> list:
  """ returns a list of possible handshake messages """
  ## pre_shared_key
  if psk_id != None:
    lext41_ch = { 'extension_type': 'pre_shared_key', \
                  'extension_data' : { 'identities' : [psk_id, psk_id], \
                                       'binders' : [psk_binder, psk_binder] } }
  else: 
    lext41_ch = deepcopy( ext41_ch )
  
  lhs_client_hello = deepcopy( hs_client_hello )
  lhs_client_hello[ 'data' ][ 'extensions' ] = \
    [ ext13, ext45, ext49, ext10, ext51_ch, lext41_ch ]
  return [ lhs_client_hello ]
 
def s_init_early_secret_request_list( psk_id=None):
  """ list of s_init_early_secret requests """
  req_list = []
  for handshake in s_init_early_secret_handshake_list( psk_id=psk_id ):
    req_list.append( { \
      'session_id' : token_bytes( 4 ), 
      'freshness' : 'sha256', 
      'selected_identity' : 0,
      'handshake' : [ handshake ], 
      'secret_request' : { "b":True, "e_s":False, "e_x":True, "h_c":False,\
                           "h_s":False, "a_c":False, "a_s":False, "x":False, \
                           "r":False} } )
  return req_list

def s_init_early_secret_test( payload, status ):
  """ returns request string description """ 
  ctx_struct = { '_type' : 's_init_early_secret', '_status' : status }
  if status == 'request' :
    print( f"--- payload: {payload} " )
    SInitEarlySecretRequest.build( payload, **ctx_struct )
  elif status == 'success' :
    SInitEarlySecretResponse.build( payload, **ctx_struct )
  else:
    raise ValueError( f"unexpected status {status}. Expecting 'request' or 'success'" )
  test_struct( TLS13Payload, payload, ctx_struct=ctx_struct,\
               print_data_struct=False, print_binary=False) 
  
if TLS_SERVER_PAYLOAD_EXCHANGE is True :
  for req in s_init_early_secret_request_list( ):
    s_init_early_secret_test( req, 'request' )

## SInitEarlySecretResponse

s_init_early_secret_resp = { \
  'session_id' : token_bytes( 4 ), 
  'secret_list' : [ {'secret_type': 'b', 'secret_data': b'binder_key' }, 
                    {'secret_type': 'e_s', 'secret_data': b'early_secret' },
                    {'secret_type': 'e_x', 'secret_data': b'early_exporter' } ] }
ctx_struct = { '_type' : 's_init_early_secret' } 
test_struct( SInitEarlySecretResponse, s_init_early_secret_resp,\
             ctx_struct=ctx_struct )

if TLS_SERVER_PAYLOAD_EXCHANGE is True :
  s_init_early_secret_test( s_init_early_secret_resp, 'success' )

print( "############################################" )
print( "## III.3 Payload SHandAndApp Req and Resp ##" )
print( "############################################" )

#### SHandAndAppRequest

def s_hand_and_app_handshake_list( ephemeral_mode ) -> list:
  """ returns a list of possible handshake messages """

  hs_server_hello = {\
  'msg_type': 'server_hello', 
  'data' : {
    'legacy_version' : b'\x03\x03',
    'random' : token_bytes( 32 ),
    'cipher_suite' :'TLS_AES_128_GCM_SHA256',
    'legacy_compression_method' : b'\x00',
    'extensions' : [] } }

  ##post-handshake authentication
  ext49 = { 'extension_type': 'post_handshake_auth', \
            'extension_data' : {} }
  ## supported groups (all groups)
  ext10 = { 'extension_type': 'supported_groups', \
            'extension_data' : {'named_group_list' : ['secp256r1', 'secp384r1',\
                                                     'x25519', 'x448' ]} }

  ext41_sh =  { 'extension_type': 'pre_shared_key', \
                'extension_data' : 0 }

  lhs_server_hello = deepcopy( hs_server_hello )
#  hs_server_hello[ 'data' ][ 'extensions' ] = [ ext45, ext49, ext10, ext41_sh ]
  lhs_server_hello[ 'data' ][ 'extensions' ] = [ ext49, ext10, ext41_sh ]
  if ephemeral_mode == 'cs_generated':
    ## lurk specific format when the ECDHE is generated by the CS on the TLS server
    ext51_sh_empty = {'extension_type': 'key_share', \
                      'extension_data' : { 'server_share': {'group': 'x448', \
                                                            'key_exchange': b'' } } }
    lhs_server_hello[ 'data' ][ 'extensions' ].append( ext51_sh_empty )
  elif ephemeral_mode == 'e_generated' : 
    private_key = X448PrivateKey.generate()
    public_key = private_key.public_key()
    x448_key = public_key.public_bytes(
          encoding=serialization.Encoding.Raw,
          format=serialization.PublicFormat.Raw)
    ke_entry_x448 = {'group': 'x448', 'key_exchange' : x448_key}
    ext51_sh = {'extension_type': 'key_share', \
                'extension_data' : {'server_share' : ke_entry_x448 } } 
    lhs_server_hello[ 'data' ][ 'extensions' ].append( ext51_sh )
  ## we do not have key_share extension with PSK without ecdhe mode

  hs = [ lhs_server_hello, hs_encrypted_extensions, hs_certificate_request ]
  return [ hs, deepcopy( hs )[ :-1 ] ]


def s_hand_and_app_secret_request_list( ):
  """ returns a list of s_hand_and_app_secret requests"""

  req_list = []
  for last_exchange in [ True, False ]:
    for ephemeral in [ eph_no, eph_e_req, eph_cs_req ]:
      method  = ephemeral[ 'method' ]
      for handshake in s_hand_and_app_handshake_list( method ):
        req_list.append( {\
          'tag' : { 'last_exchange' : last_exchange }, 
          'session_id' : token_bytes( 4 ), 
          'ephemeral' : ephemeral, 
          'handshake' : handshake, 
          'secret_request' : { "b":False, "e_s":False, "e_x":False, "h_c":True,\
                               "h_s":True, "a_c":True, "a_s":True, "x":True, \
                               "r":False } } )
  return req_list

def s_hand_and_app_secret_title( req ):
  tag = req[ 'tag' ][ 'last_exchange' ]
  try: 
    eph = req[ 'ephemeral' ][ 'method' ]
  except KeyError:
    raise ValueError( f" --- resp: {resp}" )
  return "last_exchange [%s] - %s"%( tag, eph )


def s_hand_and_app_secret_test( payload, status ):
  ctx_struct = { '_type' : 's_hand_and_app_secret', '_status' : status } 
  ext_title = s_hand_and_app_secret_title( payload ) 
  test_struct( TLS13Payload, payload, ctx_struct=ctx_struct, \
               ext_title=ext_title, print_data_struct=False, print_binary=False) 

if TLS_SERVER_PAYLOAD_EXCHANGE is True :
  for req in s_hand_and_app_secret_request_list():
    s_hand_and_app_secret_test( req, 'request' )
## SHandAndAppResponse
  for last_exchange in [ True, False ]:
    for ephemeral in [ eph_no, eph_cs_resp ]:
      s_hand_and_app_resp = {\
        'tag' : { 'last_exchange' : last_exchange }, 
        'session_id' : token_bytes (4 ), 
        'ephemeral' : ephemeral, 
        'secret_list' : [\
          { 'secret_type': 'h_c', 'secret_data': b'hand_client_secret' }, 
          { 'secret_type': 'h_s', 'secret_data': b'hand_server_secret' },
          { 'secret_type': 'a_c', 'secret_data': b'app_client_secret' },
          { 'secret_type': 'a_s', 'secret_data': b'app_server_secret' } ] }
      ctx_struct = { '_type' : 's_hand_and_app_secret', '_status' : 'request' } 
      test_struct( SHandAndAppResponse, s_hand_and_app_resp,\
                   ctx_struct=ctx_struct )
      s_hand_and_app_secret_test( s_hand_and_app_resp, 'success' )

print( "###########################################" )
print( "## III.4 Payload SNewTicket Req and Resp ##" )
print( "###########################################" )

## SNewTicketRequest

def s_new_ticket_handshake_list() -> list:
  """ returns a list of possible handshake messages """
  hs_finished = {
   'msg_type' : 'finished',
   'data' : {'verify_data' : token_bytes( 32 )}}

  hs_certificate_verify = {
   'msg_type' : 'certificate_verify',
   'data' : { 'algorithm' : 'ed25519',
             'signature' : b'\x00\x01\x02' }}

  return [ [ hs_finished ],\
           [ hs_certificate_verify, hs_finished ] ]


def s_new_ticket_request_list( ):
  list_req = []
  for last_exchange in [ True, False ]:
    ## finger_Print requires some configuration 
    ## so we remov ethat case here as we use generic messages
    for cert in [ no_cert, uncompressed_cert ]:
      for handshake in s_new_ticket_handshake_list():
        ## no cert is incompatbible certfificate_very
        if len( handshake ) == 2 and cert == no_cert :
          continue
        if len( handshake ) == 1 and cert != no_cert :
          continue
        list_req.append( {\
          'tag' : { 'last_exchange' : last_exchange }, 
          'session_id'   : token_bytes( 4 ), 
          'handshake' :  handshake,
          'certificate'   : cert,
          'ticket_nbr'   : 2,
          'secret_request' : { "b":False, "e_s":False, "e_x":False, "h_c":False,\
                                 "h_s":False, "a_c":False, "a_s":False, "x":False, \
                                 "r":True } } )
  return list_req

def s_new_ticket_request_title( req:dict ) -> str:
  """ returns the title associated to the request """
  tag = req[ 'tag' ][ 'last_exchange' ]
  cert = req[ 'certificate' ]['cert_type'] 
  return "last_exchange [%s] - cert_type [%s]"%( tag, cert )

def s_new_ticket_test( payload, status ):
  if status == 'request':
    ctx_struct = { '_type' : 's_new_ticket', '_status' : 'request', \
                   '_cipher' : 'TLS_AES_128_GCM_SHA256' } 
    ext_title = s_new_ticket_request_title( payload )
    SNewTicketRequest.build( payload, **ctx_struct )
    test_struct( TLS13Payload, payload, ctx_struct=ctx_struct,\
                 ext_title=ext_title, print_data_struct=False, print_binary=False) 

  elif status == 'success' :
    ctx_struct = { '_type' : 's_new_ticket', '_status' : 'success' } 
    SNewTicketResponse.build( payload, **ctx_struct )
    ext_title = s_new_ticket_response_title( payload )
    test_struct( TLS13Payload, payload, ctx_struct=ctx_struct, \
                 ext_title=ext_title, print_data_struct=False, print_binary=False) 
  else:
    raise ValueError( f"Unexpected status {status}. Expecting 'request'/'success'" )

if TLS_SERVER_PAYLOAD_EXCHANGE is True :
  for req in s_new_ticket_request_list( ):
    s_new_ticket_test( req, 'request' )
  

## SNewTicketResponse
new_ticket = { \
  'ticket_lifetime':5,\
  'ticket_age_add':6,\
  'ticket_nonce':b'\x07', \
  'ticket':b'\x00\x01\x02\x03',\
  'extensions':[]\
}

def s_new_ticket_response_title( req:dict ) -> str:
  """ returns the title associated to the request """
  tag = req[ 'tag' ][ 'last_exchange' ]
  return "last_exchange [%s]"%tag

for last_exchange in [ True, False ]:
  s_new_ticket_resp = {
    'tag' : { 'last_exchange' : last_exchange }, 
    'session_id' : token_bytes( 4 ), 
    'secret_list' : [\
      {'secret_type': 'h_c', 'secret_data': b'hand_client_secret' }, 
      {'secret_type': 'h_s', 'secret_data': b'hand_server_secret' },
      {'secret_type': 'a_c', 'secret_data': b'app_client_secret' },
      {'secret_type': 'a_s', 'secret_data': b'app_server_secret' } ],
    'ticket_list' : [ new_ticket, new_ticket ]}
  ctx_struct = { '_type' : 's_new_ticket' } 
  test_struct( SNewTicketResponse, s_new_ticket_resp,\
               ctx_struct=ctx_struct )
  s_new_ticket_test( s_new_ticket_resp, 'success' )


print( "####################################################" )
print( "## III.5 Payload CInitClientFinished Req and Resp ##" )
print( "####################################################" )


def c_init_client_finished_handshake_list( ephemeral_mode:str ) -> list:
  """ returns a list of possible TLS handshake messages 

  The list contains the possible TLS messages for c_init_client_finished. """
  hs_list = []
  cert_type_list = []
  # 49: 'post_handshake_auth'
  # 41: 'pre_shared_key'
  # 45: 'psk_key_exchange_modes'
  # 51 : 'key share'
  if ephemeral_mode == 'no_secret' :
    lhs_client_hello = deepcopy( hs_client_hello )
    lhs_server_hello = deepcopy( hs_server_hello )
    lhs_client_hello[ 'data' ][ 'extensions' ] = [ ext49, ext45, ext41_ch]
    lhs_server_hello[ 'data' ][ 'extensions' ] = [ ext45, ext41_sh]
    hs_list.append( [ lhs_client_hello, lhs_server_hello, \
                      hs_encrypted_extensions, hs_finished ] )  
    server_cert = False
    client_cert = False
    cert_type_list.append( [ server_cert, client_cert ] )
  elif ephemeral_mode == 'e_generated':
    lhs_client_hello = deepcopy( hs_client_hello )
    lhs_server_hello = deepcopy( hs_server_hello )
    lhs_client_hello[ 'data' ][ 'extensions' ] = [ ext49, ext45, ext41_ch, ext51_ch]
    lhs_server_hello[ 'data' ][ 'extensions' ] = [ ext45, ext41_sh, ext51_ch]
    hs_list.append( [ lhs_client_hello, lhs_server_hello, \
                      hs_encrypted_extensions, hs_finished ] )  
    server_cert = False
    client_cert = False
    cert_type_list.append( [ server_cert, client_cert ] )
    ## ecdhe post / no cert_request
    lhs2_client_hello = deepcopy( hs_client_hello )
    lhs2_server_hello = deepcopy( hs_server_hello )
    lhs2_client_hello[ 'data' ][ 'extensions' ] = [ ext49, ext51_ch ]    
    lhs2_server_hello[ 'data' ][ 'extensions' ] = [ ext51_sh ]  
    hs_list.append( [ lhs2_client_hello, lhs2_server_hello, \
                      hs_encrypted_extensions, certificate_verify, \
                      hs_finished, hs_finished ] )  
    server_cert = True
    client_cert = False
    cert_type_list.append( [ server_cert, client_cert ] )
    ## ecdhe post / cert_request
    lhs3_client_hello = deepcopy( lhs2_client_hello )
    lhs3_server_hello = deepcopy( lhs2_server_hello )
    hs_list.append( [ lhs3_client_hello, lhs3_server_hello, \
                      hs_encrypted_extensions, hs_certificate_request, \
                      hs_certificate_verify, hs_finished ] )  
    server_cert = True
    client_cert = True
    cert_type_list.append( [ server_cert, client_cert ] )
    ## ecdhe no post / cert_request
    lhs4_client_hello = deepcopy( lhs3_client_hello )
    lhs4_server_hello = deepcopy( lhs3_server_hello )
    lhs4_client_hello[ 'data' ][ 'extensions' ] = [ ext51_ch ]    
    hs_list.append( [ lhs4_client_hello, lhs4_server_hello, \
                      hs_encrypted_extensions, hs_certificate_request, \
                      hs_certificate_verify, hs_finished  ] )  
    server_cert = True
    client_cert = True
    cert_type_list.append( [ server_cert, client_cert ] )
  return hs_list, cert_type_list 

def c_init_client_finished_request_list( sig_algo: str ='ed25519', \
                                   tls13_conf=None, last_exchange=None ):
 
  if tls13_conf == None:
    finger_print_entry_list = [ { 'finger_print' : token_bytes( 4 ), \
                                  'extensions' : [] } ]
    cert_entry_list = [ { 'cert' : b'public bytes', 'extensions' : [] } ]
#    lhs_certificate = deepcopy( hs_certificate )
  else: ## conf overwrites the parameters
    cert_entry_list = tls13_conf[ '_cert_entry_list' ]
    finger_print_entry_list = tls13_conf[ '_finger_print_entry_list' ]
    
  uncompressed_cert = \
    { 'cert_type' : 'uncompressed', 
      'certificate' : { 'certificate_request_context': b'', 
                         'certificate_list' : cert_entry_list } }
  finger_print_cert = \
    { 'cert_type' : 'finger_print', 
      'certificate' : { 'certificate_request_context': b'', 
                         'certificate_list' : finger_print_entry_list } }
      
  if last_exchange == None:
    last_exchange_list = [ True, False ]
  else:
    last_exchange_list = [ last_exchange ]

  list_req = []
  eph_method_list = [ 'no_secret', 'e_generated' ]
  for last_exchange in last_exchange_list:
    if last_exchange == False:
      session_id = token_bytes( 4 )
    else:
      session_id = b''
    for method in eph_method_list:
      if method == 'no_secret' :
        eph = eph_no 
      elif method == 'e_generated' :
        eph = eph_e_req
      hs_list, cert_type_list = c_init_client_finished_handshake_list( eph )
      for index in range( len( hs_list ) ) :
        handshake = hs_list[ index ]
        for cert in [ finger_print_cert, uncompressed_cert ]:
          if cert_type_list[ index ][ 0 ] is True:
            server_cert = cert
          if cert_type_list[ index ][ 1 ] is True:
            client_cert = cert
          c_init_client_finished_req = {\
            'tag' : { 'last_exchange' : last_exchange }, 
            'session_id' : session_id, 
            'handshake' : handshake, 
            'server_certificate' : server_cert,
            'client_certificate' : client_cert,
            'freshness' : 'sha256',
            'ephemeral' : ephemeral, 
            'psk' : b'' }
          list_req.append( c_init_client_finished_req )
  return list_req

def c_init_client_finished_request_title( req:dict ) -> str:
  """ returns request string description 

  The intent is to print arguments that qualifies req
  """

  tag = req[ 'tag' ][ 'last_exchange' ]
  eph = req[ 'ephemeral' ][ 'method' ]
  s_cert = req[ 'server_certificate' ]['cert_type'] 
  c_cert = req[ 'client_certificate' ]['cert_type'] 
  return f"last_exchange [{tag}] - {eph} - server_cert [{s_cert}] - client_cert [{c_cert}]"

def c_init_client_finished_test( payload, status ):
  """ tests if payload format matches  (s/c) c_init_client_finished request/response """
  _type = 'c_init_client_finished'

  ctx_struct = { '_type' : _type, '_status' : status }
  if status == 'request':
    ext_title = c_init_client_finished_request_title( payload )
    test_struct( CInitClientFinishedRequest, payload, ctx_struct=ctx_struct, \
               ext_title=ext_title, print_data_struct=False, print_binary=False) 
    
  elif status == 'success':
    ext_title = c_init_client_finished_response_title( payload )
    test_struct( CInitClientFinishedResponse, payload, ctx_struct=ctx_struct, \
               ext_title=ext_title, print_data_struct=False, print_binary=False) 
  else: 
    raise ValueError( f"Unexpected status {status}. Expecting 'request' / 'success'" )
#  ctx_struct = { '_type' : _type, '_certificate_type' : 'X509',\
#                 '_status' : status }
  print( f"{status} - {payload}" )
  test_struct( TLS13Payload, payload, ctx_struct=ctx_struct, \
               ext_title=ext_title, print_data_struct=True, print_binary=True) 

if TLS_SERVER_PAYLOAD_EXCHANGE is True :
  for req in c_init_client_finished_request_list( ):
    c_init_client_finished_test( req, 'request' )


## SInitCertVerifyResponse

def c_init_client_finished_response_list( sig_algo: str ='ed25519' ):
  """ returns the list of possible response of c_init_client_finished """

  eph_list = [ eph_e_resp ]

  list_resp = []
  for last_exchange in [ True, False ]:
    if last_exchange is False:
      session_id = token_bytes( 4 )
    else:
      session_id = None
    list_resp.append( {\
      'tag' : { 'last_exchange' : last_exchange }, 
      'session_id' : session_id, 
     'signature' : b'signature' } )
  return list_resp

def c_init_client_finished_response_title( resp:dict ) -> str:
  """ returns request string description """

  tag = resp[ 'tag' ][ 'last_exchange' ]
  return f"last_exchange [{tag}] "

if TLS_SERVER_PAYLOAD_EXCHANGE is True :
  for resp in c_init_client_finished_response_list( sig_algo='ed25519' ):
      c_init_client_finished_test( resp, 'success' )

print( "##############################################" )
print( "## III.6 Payload CPostHandAuth Req and Resp ##" )
print( "##############################################" )

def c_post_hand_auth_request_list( ):
  req_list = []
  for last_exchange in [ True, False ]:
    for cert in [ finger_print_cert, uncompressed_cert ]:
      req_list.append( {\
        'tag' : { 'last_exchange' : last_exchange }, 
        'session_id' : token_bytes( 4 ), 
        'handshake' : [ hs_certificate_request ], 
        'certificate' : cert } )
  return req_list

def c_post_hand_auth_response_list( ):
  resp_list = []
  for last_exchange in [ True, False ]:
    resp_list.append( { \
      'tag' : { 'last_exchange' : last_exchange },
      'session_id' : token_bytes( 4 ),
      'signature' : b'\x00\x00\x00' } )
  return resp_list

def c_post_hand_auth_title( req:dict ) -> str:
  """ returns the title associated to the request """
  tag = req[ 'tag' ][ 'last_exchange' ]
  try: 
    cert = req[ 'certificate' ]['cert_type'] 
    title = f"last_exchange [{tag}] - cert_type [{cert}]"
  except KeyError:
    title = f"last_exchange [{tag}]"
  return title

def c_post_hand_auth_test( payload, status ):
    ctx_struct = { '_type' : 'c_post_hand_auth', '_status' : status } 
    ext_title = c_post_hand_auth_title( payload )
    print( f"{payload}" )
    if status == 'request':
      test_struct( CPostHandAuthRequest, payload, ctx_struct=ctx_struct,\
                   ext_title=ext_title, print_data_struct=False, \
                   print_binary=False) 
    elif status == 'success' :
      test_struct( CPostHandAuthResponse, payload, ctx_struct=ctx_struct,\
                   ext_title=ext_title, print_data_struct=False, \
                   print_binary=False) 
    else: 
      test_struct( CPostHandAuthResponse, payload, ctx_struct=ctx_struct,\
                   ext_title=ext_title, print_data_struct=False, \
                   print_binary=False) 
      
    test_struct( TLS13Payload, payload, ctx_struct=ctx_struct,\
                 ext_title=ext_title, print_data_struct=False, \
                 print_binary=False) 

if TLS_SERVER_PAYLOAD_EXCHANGE is True :
  for payload in c_post_hand_auth_request_list( ):
    c_post_hand_auth_test( payload, 'request' )

  for payload in c_post_hand_auth_response_list( ):
    c_post_hand_auth_test( payload, 'success' )


print( "##################################################" )
print( "## III.7 Payload  CInitClientHello Req and Resp ##" )
print( "##################################################" )

def c_init_client_hello_handshake_list( ):

  hs_client_hello = {\
  'msg_type': 'client_hello', \
  'data' : {\
    'legacy_version' : b'\x03\x03',
    'random' : token_bytes( 32 ),
    'legacy_session_id' : token_bytes( 32 ),
    'cipher_suites' : ['TLS_AES_128_GCM_SHA256', 'TLS_CHACHA20_POLY1305_SHA256'],
    'legacy_compression_methods' : b'\x00',
    'extensions' : [ ] } }
  
  ext41_ch_no_binders = { 'extension_type': 'pre_shared_key', \
                          'extension_data' : { 'identities' : [psk_id, psk_id] } }
  ext45 = {'extension_type': 'psk_key_exchange_modes', \
           'extension_data' : {'ke_modes' : ['psk_ke', 'psk_dhe_ke']} }

  empty_ke_entries = []
  for entry in ke_entries :
    empty_entry = { 'group': entry[ 'group' ] , 'key_exchange' : b''}
    empty_ke_entries.append( empty_entry ) 
    test_struct( EmptyKeyShareEntry, empty_entry ) 
  ext51_ch_empty = { 'extension_type': 'key_share', \
                   'extension_data' : { 'client_shares' : empty_ke_entries } }
  # 49: 'post_handshake_auth'
  # 41: 'pre_shared_key'
  # 45: 'psk_key_exchange_modes'
  # 51 : 'key share'
  h_list = [] 
  ## only ecdhe
  lhs_client_hello = deepcopy( hs_client_hello )
  lhs_client_hello[ 'data' ][ 'extensions' ] = [ ext51_ch_empty ]

  h = TlsHandshake( 'client' ) 
  h.msg_list = [ lhs_client_hello ]
  if h.is_psk_proposed() is True:
    raise ValueError( f"Expecting Non PSK handshake {h.msg_list}" )
  if h.is_ks_proposed() is False:
    raise ValueError( f"Expecting KS handshake {h.msg_list}" )

#  h_list.append( [ lhs_client_hello ] )
  ## psk with ecdhe 
  lhs2_client_hello = deepcopy( hs_client_hello )
  lhs2_client_hello[ 'data' ][ 'extensions' ] = [ ext45, ext51_ch_empty, ext41_ch_no_binders ]

  h = TlsHandshake( 'client' ) 
  h.msg_list = [ lhs2_client_hello ] 
  if h.is_psk_proposed() is False:
    raise ValueError( f"Expecting PSK handshake {h.msg_list}" )
  if h.is_ks_proposed() is False:
    raise ValueError( f"Expecting KS handshake {h.msg_list}" )

  h_list.append( [ lhs2_client_hello ] )
  ## psk no ecdhe 
  lhs3_client_hello = deepcopy( hs_client_hello )
  lhs3_client_hello[ 'data' ][ 'extensions' ] = [ ext45, ext41_ch_no_binders ]

  h = TlsHandshake( 'client' ) 
  h.msg_list = [ lhs3_client_hello ]
  if h.is_psk_proposed() is False:
    raise ValueError( f"Expecting PSK handshake {h.msg_list}" )
  if h.is_ks_proposed() is True:
    raise ValueError( f"Expecting KS handshake {h.msg_list}" )

  h_list.append( [ lhs3_client_hello ] )
  return h_list 

#if TLS_SERVER_PAYLOAD_EXCHANGE is True :
for partial_ch_list in c_init_client_hello_handshake_list( ):
  test_struct( HSPartialClientHello, partial_ch_list[ 0 ], ctx_struct={}, \
             ext_title="", print_data_struct=False, print_binary=False) 
  test_struct( HandshakeList, partial_ch_list, ctx_struct={ '_type' : 'c_init_client_hello' }, \
             ext_title="", print_data_struct=False, print_binary=False) 
  

def c_init_client_hello_request_list( ):
  req_list = []
  for handshake in c_init_client_hello_handshake_list( ):
    ## Extension is used for Lurk and TLS  
    ## pre_share_key_len = len( Extension.build( ext41_ch ) )
    #pre_share_key_len = len( OfferedPsks.build( ext41_ch[ 'extension_data' ] ) ) + 2
##   ext_list = [ e[ 'extension_type' ] for e in handshake[0][ 'data' ][ 'extensions' ] ]
    h = TlsHandshake( 'client' ) 
    h.msg_list = handshake
    if 'binders' in h.msg_list[ 0 ][ 'data' ][ 'extensions' ][ -1 ]\
                 [ 'extension_data' ].keys() :
      raise ValueError( f"unexpected binders {h}" )
    print( h.msg_list )
    if h.is_psk_proposed() is True :
      psk_id_list = h.msg_list[ 0 ][ 'data' ][ 'extensions' ][ -1 ]\
                              [ 'extension_data' ][ 'identities' ]
      ## only psk provided "explicitly" that is with metadata are provided
      ## If no metadata is provided, than CS will look for a ticket.
      psk_metadata_list = []
      for psk in psk_id_list:
        psk_metadata_list.append( { 'identity_index' : psk_id_list.index( psk ),\
                               'tls_hash' : 'sha256',\
                               'psk_type' : 'resumption', \
                               'psk_bytes' : b'psk_bytes' } )
      PskIdentityMetadata.build( psk_metadata_list[ 0 ] ) 
    else:
      psk_metadata_list = [ ]
    req_list.append(\
      { 'session_id' : token_bytes( 4 ),
        'handshake' : handshake, 
        'freshness' : 'sha256',
        'psk_metadata_list' : psk_metadata_list, 
        'secret_request' : { 'b' : True, 'e_s' : True, 'e_x' : True , \
                             'h_c' : False, 'h_s' : False, 'a_c' : False, \
                             'a_s' : False, 'x' : False, 'r' : False }
      } )
  return deepcopy( req_list )


def c_init_client_hello_request_title( req:dict ) -> str:
  """ returns request string description 

  The intent is to print arguments that qualifies req
  """
  return ""  
  return f"psk_index_list [{req[ 'psk_index_list' ]}]"



def c_init_client_hello_test( payload, status ):
  """ tests if payload format matches  (s/c) c_init_client_finished request/response """
  _type = 'c_init_client_finished'

  ctx_struct = { '_type' : 'c_init_client_hello', '_status' : status }
  if status == 'request':
    print( f"--- req: {payload}" )
    ext_title = c_init_client_hello_request_title( payload )
    HandshakeList.build( payload[ 'handshake' ], _type= 'c_init_client_hello' )
    CInitClientHelloRequest.build( payload )
    test_struct( CInitClientHelloRequest, payload, ctx_struct={}, \
               ext_title=ext_title, print_data_struct=False, print_binary=False) 
    test_struct( TLS13Payload, payload, ctx_struct=ctx_struct, \
               ext_title=ext_title, print_data_struct=False, print_binary=False) 
    
  elif status == 'success':
    print( f"+++ {payload}" )
    ext_title = c_init_client_hello_response_title( payload )
    test_struct( CInitClientHelloResponse, payload, ctx_struct=ctx_struct, \
               ext_title=ext_title, print_data_struct=False, print_binary=False) 
    test_struct( TLS13Payload, payload, ctx_struct=ctx_struct, \
               ext_title=ext_title, print_data_struct=False, print_binary=False) 
  else: 
    raise ValueError( f"Unexpected status {status}. Expecting 'request' / 'success'" )
#  ctx_struct = { '_type' : _type, '_certificate_type' : 'X509',\
#                 '_status' : status }
  print( f"{status} - {payload}" )
  test_struct( TLS13Payload, payload, ctx_struct=ctx_struct, \
               ext_title=ext_title, print_data_struct=True, print_binary=True) 

for req in c_init_client_hello_request_list( ):
  c_init_client_hello_test( req, 'request' )

def c_init_client_hello_response_list( ):
  binder_key = {  'secret_type' : 'b',  'secret_data' : b'\x00\x00' }
  e_x = {  'secret_type' : 'e_x',  'secret_data' : b'\x00\x00' }
  return [ { 'session_id' : token_bytes( 4 ), 
             'ephemeral_list' : [ eph_cs_resp, eph_cs_resp ],
             'binder_key_list' : [ binder_key ],
             'secret_list' : [ e_x ] } ]

def c_init_client_hello_response_title( req:dict ) -> str:
  print( req)
  eph_list_len = len( req[ 'ephemeral_list' ] )
  try: 
    secret_list_len = len( req[ 'secret_list' ] )
  except TypeError :
    secret_list_len = 0 # secret_list is None
  return f"eph_list_len {eph_list_len} - secret_list_len {secret_list_len}" 

for req in c_init_client_hello_response_list( ):
  print( f"ooo - {req}" )
  c_init_client_hello_test( req, 'success' )


    



print( "###############################################" )
print( "## IV.1 Payload Exchange s_init_cert_verify  ##" )
print( "################################################" )



## Testing s_init_cert_verify 

sig_scheme_list = [\
  'rsa_pkcs1_sha256', 
  'rsa_pkcs1_sha384', 
  'rsa_pkcs1_sha512', 
  'ecdsa_secp256r1_sha256', 
  'ecdsa_secp384r1_sha384', 
  'ecdsa_secp521r1_sha512', 
  'rsa_pss_rsae_sha256', 
  'rsa_pss_rsae_sha384', 
  'rsa_pss_rsae_sha512', 
  'ed25519', 
  'ed448', 
  'rsa_pss_pss_sha256', 
  'rsa_pss_pss_sha384', 
  'rsa_pss_pss_sha512' ]



def configure(sig_scheme:str, role:str ='server') -> dict:
  """ return the configuration associated to sig_algo """
##  conf_builder = ConfBuilder()
##  conf_builder.generate_keys( sig_algo, key_format='X509' )
##  conf = Conf( conf=conf_builder.export() )
##  conf.conf[ 'role' ] = role
##  if sig_algo not in conf.msg( 'keys' )[ 'sig_algo' ]:
##    raise Exception( " conf :%s"%\
##      conf.msg( 'keys' )[ 'sig_algo' ] + \
##      " does not contain %s"%sig_algo) 
##  return conf
  conf = Configuration( )
  conf.set_ecdhe_authentication( sig_scheme )
  conf.set_role( role )
  conf.set_extention( ext=( 'tls13', 'v1' ) ) 
  return conf.conf[ ( 'tls13', 'v1' ) ]

def s_init_cert_verify_session():
  """tests init_cert_verify_session exchange """
  for sig_scheme in sig_scheme_list: 
    conf = configure( sig_scheme, role= 'server' ) 
#def s_init_cert_verify_request_list( sig_algo: str ='ed25519', role='server', \
#                                   tls13_conf=None, last_exchange=None ):
#    print( f"\ns_init_cert_verify_session: conf {conf}\n" )
    for req in s_init_cert_verify_request_list( sig_scheme, \
                 tls13_conf=conf, last_exchange=None ):
      ## BUG: In some cases, server_share is not b'' while method is set to 'cs_generated'
      ##################
      ks = req[ 'handshake' ][ 1 ][ 'data' ][ 'extensions' ][ 0 ] [ 'extension_data' ] [  'server_share' ] [ 'key_exchange'  ]
      print( f"--- s_init_cert_verify_session : ks : {ks} / {req[ 'ephemeral' ]}\n" )
      if ks != b'' and req[ 'ephemeral' ][ 'method' ] == 'cs_generated' :
        req[ 'handshake' ][ 1 ][ 'data' ][ 'extensions' ][ 0 ] [ 'extension_data' ]      [  'server_share' ] [ 'key_exchange'  ] = b''
#        raise ValueError()
      session = SSession( conf ) 
      s_init_cert_verify_test( req, 'request' )
      resp = session.serve( req, 's_init_cert_verify', 'request')
      s_init_cert_verify_test( resp, 'success' )
      
if TLS_SERVER_PAYLOAD_EXCHANGE == True:
  s_init_cert_verify_session()

print( "##########################################" )
print( "## IV.2 Payload Exchange s_new_ticket  ##" )
print( "#########################################" )

def s_new_ticket_session():
  """ test ticket_session generation and exchange 

    tickets are built after the init_cert_verify exchange
  """
  ctx_req = { '_type' : 's_new_ticket', '_status' : 'request', \
              '_cipher' : 'TLS_AES_128_GCM_SHA256' } 
#  ctx_req = { '_type' : 's_new_ticket', '_status' : 'request', \
#              '_certificate_type' : 'X509', '_cipher' : 'TLS_AES_128_GCM_SHA256' } 
  ctx_resp = { '_type' : 's_new_ticket', '_status' : 'success' } 
  sig_scheme = 'ed25519'
  conf = configure( sig_scheme, role= 'server' ) 
#  conf = configure( sig_algo ) 
  for req in s_new_ticket_request_list():
    ## initializing the session with a init_cert_verify
    s_init_cert_verify_req = s_init_cert_verify_request_list( sig_scheme, \
                               tls13_conf=conf, last_exchange=False )[ 0 ]
##    s_init_cert_verify_req = s_init_cert_verify_request_list( sig_algo, conf=conf )[0]
##    s_init_cert_verify_req[ 'tag' ]['last_exchange' ] = False
    session = SSession( conf )
    s_init_cert_verify_req_resp = session.serve( s_init_cert_verify_req, 's_init_cert_verify', 'request')
    req[ 'session_id' ] = s_init_cert_verify_req_resp[ 'session_id' ]
    ext_title = s_new_ticket_request_title( req )
#    ctx_req = { '_type' : 's_new_ticket', '_status' : 'request', \
#                '_certificate_type' : 'X509', '_cipher' : 'TLS_AES_128_GCM_SHA256' } 
    ctx_req = { '_type' : 's_new_ticket', '_status' : 'request', \
                '_cipher' : 'TLS_AES_128_GCM_SHA256' } 
    test_struct( TLS13Payload, req, ctx_struct=ctx_req, ext_title=ext_title ) 
    resp = session.serve( req, 's_new_ticket', 'request')
    test_struct( TLS13Payload, req, ctx_struct=ctx_req, ext_title=ext_title ) 
      
    
if TLS_SERVER_PAYLOAD_EXCHANGE == True:
  s_new_ticket_session()

print( "#############################################################" )
print( "## IV.3 Payload Exchange Server Session Resumption:        ##" )
print( "## s_init_cert_verify - s_new_ticket s_init_early_secret - ##" ) 
print( "## s_hand_and_app_secret - s_new_ticket                    ##" )
print( "#############################################################" )


def session_resumption( conf, s_init_cert_verify_req, \
                        s_new_ticket_session_req, \
                        s_init_early_secret_req, \
                        s_hand_and_app_secret_req, \
                        s_new_ticket_session_req2   ):
  """ test session resumption 

    a first session is performed to create the new session tickets.
    session resumption is then performed using these new session tickets.
   
    necessary requests are provided as templates.
  """

  ## s_init_cert_verify_req 
  s_init_cert_verify_req[ 'tag' ]['last_exchange' ] = False
  s_init_cert_verify_test( s_init_cert_verify_req, 'request' )
  session = SSession( conf )
  ###
  ks = s_init_cert_verify_req[ 'handshake' ][ 1 ][ 'data' ][ 'extensions' ][ 0 ] [ 'extension_data' ] [  'server_share' ] [ 'key_exchange'  ]
  method = s_init_cert_verify_req[ 'ephemeral' ][ 'method' ]
  print( f"SInitCertVerifyReq : ks : {ks} / {method}" )
  print( f"SInitCertVerifyReq : handshake : {s_init_cert_verify_req[ 'handshake' ]}" )
  if ks not in [ None, b'' ] and method == 'cs_generated' :
    raise ValueError( 'error detected 3' )  
  ###
  s_init_cert_verify_resp = session.serve( s_init_cert_verify_req, 's_init_cert_verify', 'request')
  s_init_cert_verify_test( s_init_cert_verify_resp, 'success' )

  ## s_new_ticket_session
  s_new_ticket_session_req[ 'session_id' ] = s_init_cert_verify_resp[ 'session_id' ]
##  s_new_ticket_print( s_new_ticket_session_req, 'request' )

  s_new_ticket_session_resp = session.serve( s_new_ticket_session_req, 's_new_ticket', 'request')
  s_new_ticket_test( s_new_ticket_session_resp, 'success' )

  ## s_init_early_secret_req 
  session = SSession( conf )
  psk_id = { 'identity' : s_new_ticket_session_resp[ 'ticket_list' ][ 0 ]['ticket' ], \
             'obfuscated_ticket_age' : token_bytes( 4) } 
  psk_binder = {'binder' : b'\xff\xff\xff\xff'}
  offered_psks= { 'identities' : [psk_id, psk_id], \
                  'binders' : [psk_binder, psk_binder]}
  client_hello_exts = s_init_early_secret_req[ 'handshake' ][ 0 ][ 'data' ][ 'extensions' ] 
  i = get_struct_index( client_hello_exts, 'extension_type', 'pre_shared_key' )
  s_init_early_secret_req[ 'handshake' ][ 0 ][ 'data' ][ 'extensions' ][ i ][ 'extension_data' ] = offered_psks
  print( f"-o-o-o s_init_early_secret_req: {s_init_early_secret_req}" )
  s_init_early_secret_test( s_init_early_secret_req, 'request' )
  s_init_early_secret_resp = session.serve( s_init_early_secret_req,\
                                            's_init_early_secret', 'request')
  s_init_early_secret_test( s_init_early_secret_resp, 'success' )

  ## s_hand_and_app_secret
  s_hand_and_app_secret_req[ 'session_id' ] = s_init_early_secret_resp[ 'session_id' ]
#  print( f"--- s_hand_and_app_secret_req: {s_hand_and_app_secret_req}" )
  s_hand_and_app_secret_test( s_hand_and_app_secret_req, 'request' )
  ######################
  print( f"--- s_hand_and_app_secret_req: {s_hand_and_app_secret_req}" )
  method = s_hand_and_app_secret_req[ 'ephemeral' ][ 'method' ]
  if method == 'cs_generated':
    ext_list = s_hand_and_app_secret_req[ 'handshake' ][ 0 ][ 'data' ][ 'extensions' ]
    ext_type_list = [ e[ 'extension_type'] for e in ext_list ]
    if 'key_share' in ext_type_list:
      ks_index = ext_type_list.index( 'key_share' ) 
      ks = s_hand_and_app_secret_req[ 'handshake' ][ 0 ][ 'data' ][ 'extensions' ][ ks_index ] [ 'extension_data' ] [  'server_share' ] [ 'key_exchange'  ]
      if ks not in [ None, b'' ] :
        s_hand_and_app_secret_req[ 'handshake' ][ 0 ][ 'data' ][ 'extensions' ][ ks_index ] [ 'extension_data' ] [  'server_share' ] [ 'key_exchange'  ] = b''
  ######################
  print( f"--- s_hand_and_app_secret_req: {s_hand_and_app_secret_req}" )
  s_hand_and_app_secret_resp =  session.serve( s_hand_and_app_secret_req,\
                                               's_hand_and_app_secret', 'request')
  s_hand_and_app_secret_test( s_hand_and_app_secret_resp, 'success' )

##if TLS_SERVER_PAYLOAD_EXCHANGE == True:
## testing a single session resumption
## sig_algo = 'ed25519'
## conf = configure( sig_algo )
## s_init_cert_verify_req = s_init_cert_verify_request_list( sig_algo, conf=conf, last_exchange=False )[0]
## s_new_ticket_session_req = s_new_ticket_request_list( )[ 0 ] 
## s_init_early_secret_req = s_init_early_secret_request_list()[ 0 ]
## s_hand_and_app_secret_req = s_hand_and_app_secret_request_list( )[0]
## s_new_ticket_session_req2 = s_new_ticket_request_list( )[ 0 ] 
## session_resumption( conf,  s_init_cert_verify_req, \
##                    s_new_ticket_session_req, \
##                    s_init_early_secret_req, \
##                    s_hand_and_app_secret_req, \
##                    s_new_ticket_session_req2   )
##

## sig_algo_list = [ 'rsa_pkcs1_sha256' ]

if TLS_SERVER_PAYLOAD_SESSION_RESUMPTION_LOOP == True:
  for sig_scheme in sig_scheme_list:
    conf = configure( sig_scheme=sig_scheme, role='server' )
    for s_init_cert_verify_req in  s_init_cert_verify_request_list( sig_scheme,\
                                     tls13_conf=conf, last_exchange=False ):
      for s_new_ticket_session_req in  s_new_ticket_request_list():
        for s_init_early_secret_req in s_init_early_secret_request_list():
          for s_hand_and_app_secret_req in s_hand_and_app_secret_request_list():
            print( f" A --- s_hand_and_app_secret_req: {s_hand_and_app_secret_req}" )
            ######################
            ks = s_init_cert_verify_req[ 'handshake' ][ 1 ][ 'data' ][ 'extensions' ][ 0 ] [ 'extension_data' ] [  'server_share' ] [ 'key_exchange'  ]
            method = s_init_cert_verify_req[ 'ephemeral' ][ 'method' ]
            print( f"SInitCertVerifyReq : ks : {ks} / {method}" )
            print( f"SInitCertVerifyReq : handshake : {s_init_cert_verify_req[ 'handshake' ]}" )
            if ks not in [ None, b'' ] and method == 'cs_generated' :
##              raise ValueError( 'error detected 7' ) 
              s_init_cert_verify_req[ 'handshake' ][ 1 ][ 'data' ][ 'extensions' ][ 0 ] [ 'extension_data' ] [ 'server_share' ] [ 'key_exchange' ] = b''
            ######################
              
            for s_new_ticket_session_req2 in s_new_ticket_request_list():
              ### A--- does not have the shared key but B does 
##              print( f" B --- s_hand_and_app_secret_req: {s_hand_and_app_secret_req}" )
##              try: 
##                ks = s_hand_and_app_secret_req[ 'handshake' ][ 0 ][ 'data' ][ 'extensions' ][ 0 ] [ 'extension_data' ] [  'server_share' ] [ 'key_exchange'  ]
##                method = s_hand_and_app_secret_req[ 'ephemeral' ][ 'method' ]
##                if ks not in [ None, b'' ] and method == 'cs_generated' :
##                  s_hand_and_app_secret_req[ 'handshake' ][ 0 ][ 'data' ][ 'extensions' ][ 0 ] [ 'extension_data' ] [  'server_share' ] [ 'key_exchange'  ] = b''
##              except KeyError:
##                pass
              ######################
              ks = s_init_cert_verify_req[ 'handshake' ][ 1 ][ 'data' ][ 'extensions' ][ 0 ] [ 'extension_data' ] [  'server_share' ] [ 'key_exchange'  ]
              method = s_init_cert_verify_req[ 'ephemeral' ][ 'method' ]
              print( f"SInitCertVerifyReq : ks : {ks} / {method}" )
              print( f"SInitCertVerifyReq : handshake : {s_init_cert_verify_req[ 'handshake' ]}" )
              ### for some reasons we have an error here 
              ### s_new_ticket_request_list seems to transform s_init_cert_verify_req
              ## we do correct the format here to pass the texts
              if ks not in [ None, b'' ] and method == 'cs_generated' :
                s_init_cert_verify_req[ 'handshake' ][ 1 ][ 'data' ][ 'extensions' ][ 0 ] [ 'extension_data' ] [  'server_share' ] [ 'key_exchange'  ] = b''
##                raise ValueError( 'error detected 4' ) 
              ######################
              session_resumption( conf, s_init_cert_verify_req, \
                                  s_new_ticket_session_req, \
                                  s_init_early_secret_req, \
                                  s_hand_and_app_secret_req, \
                                  s_new_ticket_session_req2   )

print( "###############################################" )
print( "## IV.4 Payload Exchange c_init_client_finished  ##" )
print( "################################################" )

def c_init_client_finished_session():
  """tests init_cert_verify_session exchange """
  for sig_scheme in sig_scheme_list: 
    conf = configure( sig_scheme, role= 'client' ) 
    print( f"c_init_client_finished_session: conf {conf}" )
#    for req in s_init_cert_verify_request_list( sig_scheme, role='client', \
    for req in c_init_client_finished_request_list( sig_scheme, \
                 tls13_conf=conf, last_exchange=None ):
      session = CSession( conf ) 
      c_init_client_finished_test( req, 'request' )
      resp = session.serve( req, 'c_init_client_finished', 'request')
      c_init_client_finished_test( resp, 'success' )


if TLS_CLIENT_PAYLOAD_EXCHANGE == True:
  c_init_client_finished_session()

print( "######################################################################" )
print( "## IV.5 Payload Exchange c_init_client_finished + c_post_hand_auth  ##" )
print( "######################################################################" )

def c_post_hand_auth_session():
  """tests init_cert_verify_session exchange """
  for sig_scheme in sig_scheme_list: 
    conf = configure( sig_scheme, role= 'client' ) 
    print( f"c_init_client_finished_session: conf {conf}" )
    for req in c_init_client_finished_request_list( sig_scheme, \
                 tls13_conf=conf, last_exchange=None ):
      session = CSession( conf ) 
      c_init_client_finished_test( req, 'request' )
      resp = session.serve( req, 'c_init_client_finished', 'request')
      c_init_client_finished_test( resp, 'success' )
      if resp[ 'tag' ][ 'last_exchange' ] == False:
        session_id = resp[ 'session_id' ]
        for post_hand_auth_req in c_post_hand_auth_request_list( ):
          post_hand_auth_req[ 'session_id' ] = session_id
          post_hand_auth_req[ 'sig_algo' ] = sig_scheme
          if post_hand_auth_req[ 'certificate' ][ 'cert_type' ] == 'finger_print':
            print( post_hand_auth_req[ 'certificate' ] )
            post_hand_auth_req[ 'certificate' ][ 'certificate_list' ] = conf[ '_finger_print_entry_list' ]           
            continue
          post_hand_auth_resp = session.serve( post_hand_auth_req, \
                                               'c_post_hand_auth', 'request') 
          c_post_hand_auth_test( post_hand_auth_resp, 'success' )

if TLS_CLIENT_PAYLOAD_EXCHANGE == True:
  c_post_hand_auth_session()

print( "################################################" )
print( "## IV.5 Payload Exchange c_init_client_hello  ##" )
print( "################################################" )

def c_init_client_hello_session( conf, req ):

  ## I do no get why we do have binders.
  if 'binders' in req[ 'handshake'][ 0 ][ 'data' ][ 'extensions' ][ -1 ]\
               [ 'extension_data' ].keys() :
    del req[ 'handshake'][ 0 ][ 'data' ][ 'extensions' ][ -1 ]\
                [ 'extension_data' ][ 'binders' ]
##    raise ValueError( f"unexpected binders {req}" )
  session = CSession( conf, session_db=SessionDB(), ticket_db=TicketDB() ) 
  print( f"ooo - {req}" )
  c_init_client_hello_test( req, 'request' )
  resp = session.serve( req, 'c_init_client_hello', 'request')
  print( f"ooo - {resp}" )
  c_init_client_hello_test( resp, 'success' )
  return session, resp

if TLS_CLIENT_PAYLOAD_EXCHANGE == True:
  for sig_scheme in sig_scheme_list: 
    conf = configure( sig_scheme, role= 'client' ) 
    print( f"c_init_client_hello_session: conf {conf}" )
    for req in c_init_client_hello_request_list( ) :
      c_init_client_hello_session( conf, req )


print( "#################################################################" )
print( "## IV.6 Payload  Exchange c_init_client_hello - c_server_hello ##" )
print( "##                                    - c_client_finished      ##" )
print( "#################################################################" )

def c_server_hello_handshake( client_hello ):
  """ returns the serverhello message corresponding to the clienthello """
  # 49: 'post_handshake_auth'
  # 41: 'pre_shared_key'
  # 45: 'psk_key_exchange_modes'
  # 51 : 'key share'
  ch_ext_list = [ e[ 'extension_type' ] for e in client_hello[ 'data' ][ 'extensions' ] ]
  sh_ext_list = []
  if 'key_share' in ch_ext_list :
    sh_ext_list.append( {'extension_type': 'key_share', \
                         'extension_data' : {'server_share' : ke_entry_x448 } } ) 
  if 'pre_shared_key' in ch_ext_list :
    sh_ext_list.append( { 'extension_type': 'pre_shared_key', \
                          'extension_data' : 0 } )
  sh = { 'msg_type': 'server_hello', 
         'data' : {
           'legacy_version' : b'\x03\x03',
           'random' : token_bytes( 32 ),
           'cipher_suite' :'TLS_AES_128_GCM_SHA256',
           'legacy_compression_method' : b'\x00',
           'extensions' : sh_ext_list } }
  return sh

def c_handshake( conf, c_init_client_hello_request ):

  ## I do no get why we do have binders.
  if 'binders' in req[ 'handshake'][ 0 ][ 'data' ][ 'extensions' ][ -1 ]\
               [ 'extension_data' ].keys() :
    del req[ 'handshake'][ 0 ][ 'data' ][ 'extensions' ][ -1 ]\
                [ 'extension_data' ][ 'binders' ]
  c_init_client_hello_test( c_init_client_hello_request, 'request' )
  session, resp = c_init_client_hello_session( conf, c_init_client_hello_request )
  print( f"-- session.ephemeral.resp: {session.ephemeral.resp}" ) 
  print( f"-- session.ephemeral.private_key_list: {session.ephemeral.private_key_list}" )
  ## we do not keep track of the keys generated by E, so we skip that case
  if None in session.ephemeral.private_key_list :
    return None 
  ## building server_hello ( expected to be on the server side)
  ch = c_init_client_hello_request[ 'handshake' ][ 0 ]
  sh = c_server_hello_handshake( ch )
  ## determining the ephemeral
  sh_ext_list = [ e[ 'extension_type' ] for e in sh[ 'data' ][ 'extensions' ] ]
  ## From configuration determine the ephemeral
  ## when key share is present it is always generated by the CS
  ## so ephemeral is of mode cs_generated when key_share is present 
  ## and no_secret otherwise
  if 'key_share' in sh_ext_list :
    eph = eph_cs_req
  else:
    eph = eph_no 
  session_id = resp[ 'session_id' ]
  c_server_hello_request = \
    { 'session_id' : session_id,
      'handshake' : [ sh ], 
      'ephemeral' : eph }
  ## in our case PSK are never hosted by the CS
  ## so when eph i sset to eph_no we directly go to 
  ## c_client_finished
  psk_in_cs = False
  print( f"eph : {eph} ")
  if eph[ 'method' ] in [ 'cs_generated' ] or psk_in_cs is True :
    ## checking the format of the request
    ext_title = "CServerHelloRequest"
    test_struct( CServerHelloRequest, c_server_hello_request, \
                 ctx_struct={}, ext_title=ext_title, \
                 print_data_struct=False, print_binary=False) 
    ctx_struct = { '_type' : 'c_server_hello', '_status' : 'request' }
    test_struct( TLS13Payload, c_server_hello_request,\
                 ctx_struct=ctx_struct, ext_title=ext_title, \
                 print_data_struct=False, print_binary=False)
    ## getting the response
    resp = session.serve( c_server_hello_request, 'c_server_hello', 'request')
    
    ## checking the format of the response
    test_struct( CServerHelloResponse, resp, ctx_struct={}, \
                 ext_title=ext_title, print_data_struct=False,\
                 print_binary=False) 
    ctx_struct = { '_type' : 'c_server_hello', '_status' : 'success' }
    test_struct( TLS13Payload, resp, ctx_struct=ctx_struct, \
                 ext_title=ext_title, print_data_struct=False, \
                 print_binary=False)
    handshake = []
  else :
    handshake = [ sh ]
  ## a - deriving keys with handshake secrets
  ## b - decryptiong the encrypted messages
  ## c.1 - application secrets for the application data.
  ## c.2 - when authentication is requested the CS authenticates the client

  ## Possible choices of handshakes
  ## handshake.extend( [ hs_encrypted_extensions, hs_finished ] )  
  handshake.extend( [ hs_encrypted_extensions, hs_certificate_request, hs_certificate_verify, hs_finished ] )  
  ## uncompressed
  certificate_entry = {'cert' : b'certificate_entry', 'extensions':[] }
  certificate = { 'certificate_request_context': b'',
                  'certificate_list' : [certificate_entry, certificate_entry] }
  uncompressed_cert = { 'cert_type' : 'uncompressed',\
                        'certificate' : certificate }
  server_cert = uncompressed_cert
  client_cert = uncompressed_cert
  c_client_finished_request = \
    { 'tag' : { 'last_exchange' : False }, 
      'session_id' : session_id, 
      'handshake' : handshake, 
      'server_certificate' : server_cert,
      'client_certificate' : client_cert }
  ## checking the format of the request
  ext_title = "CClientFinishedRequest"
  test_struct( CClientFinishedRequest, c_client_finished_request, \
               ctx_struct={}, ext_title=ext_title, \
               print_data_struct=False, print_binary=False ) 
  ctx_struct = { '_type' : 'c_client_finished', '_status' : 'request' }
  test_struct( TLS13Payload, c_client_finished_request,\
               ctx_struct=ctx_struct, ext_title=ext_title, \
               print_data_struct=False, print_binary=False )
  resp = session.serve( c_client_finished_request, 'c_client_finished', 'request')
  test_struct( CClientFinishedResponse, resp, \
               ctx_struct={}, ext_title=ext_title, \
               print_data_struct=False, print_binary=False ) 
  ctx_struct = { '_type' : 'c_client_finished', '_status' : 'success' }
  test_struct( TLS13Payload, resp,\
               ctx_struct=ctx_struct, ext_title=ext_title, \
               print_data_struct=False, print_binary=False )
  ## register only occurs when last_Exchange has not be set to True
  if resp[ 'tag' ][ 'last_exchange' ] is False:
    new_ticket = { \
      'ticket_lifetime':5,\
      'ticket_age_add':6,\
      'ticket_nonce':b'\x07', \
      'ticket':b'\x00\x01\x02\x03',\
      'extensions':[]\
    }
    c_register_req_payload = \
      { 'tag' : { 'last_exchange' : True }, 
        'session_id' : session_id, 
        'ticket_list' : [ new_ticket ] }

    ext_title = "CRegisterTicketsRequest"
    test_struct( CRegisterTicketsRequest, c_register_req_payload, \
                 ctx_struct={}, ext_title=ext_title, \
                 print_data_struct=False, print_binary=False ) 
    ctx_struct = { '_type' : 'c_register_tickets', '_status' : 'request' }
    test_struct( TLS13Payload, c_register_req_payload,\
                 ctx_struct=ctx_struct, ext_title=ext_title, \
                 print_data_struct=False, print_binary=False )
    resp = session.serve( c_register_req_payload, 'c_register_tickets', 'request')
    test_struct( CRegisterTicketsResponse, resp, \
                 ctx_struct={}, ext_title=ext_title, \
                 print_data_struct=False, print_binary=False ) 
    ctx_struct = { '_type' : 'c_register_tickets', '_status' : 'success' }
    test_struct( TLS13Payload, resp,\
                 ctx_struct=ctx_struct, ext_title=ext_title, \
                 print_data_struct=False, print_binary=False )

#  bytes_resp = cs.serve( LURKMessage.build( lurk_c_register_req ) )
#  resp = LURKMessage.parse( bytes_resp )
#  test_struct( LURKMessage, resp,\
#               ctx_struct=ctx_struct, ext_title="toto", \
#               print_data_struct=False, print_binary=False)



print( f"-- c_init_client_hello_request_list( ) [{len(c_init_client_hello_request_list( ))}]:  {c_init_client_hello_request_list( ) }" )
if TLS_CLIENT_PAYLOAD_EXCHANGE == True:
  for sig_scheme in sig_scheme_list: 
    conf = configure( sig_scheme, role= 'client' ) 
    print( f"c_init_client_hello_session: conf {conf}" )
    for req in c_init_client_hello_request_list( ) :
      c_handshake( conf, req )



print( "#############################################################" )
print( "## V.1 LURK Exchange Server Session Resumption:            ##" )
print( "## s_init_cert_verify - s_new_ticket s_init_early_secret - ##" ) 
print( "## s_hand_and_app_secret - s_new_ticket                    ##" )
print( "#############################################################" )

### Testing LURK messages including the header

def lurk_client_new_session_ticket( server, s_new_ticket_session_req ):
  """ Simulates a ticket request between a LURK client and a crypto service

  Such exchange is expected to happen after the LURK client handled an 
  ECDHE authentication between the TLS client and the TLS server. 

  Args:
    server : the crypto engine
    s_new_ticket_session_req : the ticket request
  Returns:
    ticket_list: the list of tickets
  """

  lurk_s_new_ticket_session_req = \
  { 'designation' : 'tls13',
    'version' : 'v1',
    'type' : 's_new_ticket', 
    'status' : 'request', 
    'id' : randbelow( 2  ** 64 ),
    'payload' : s_new_ticket_session_req }
  test_struct( LURKMessage, lurk_s_new_ticket_session_req )
  resp = server.serve( LURKMessage.build( lurk_s_new_ticket_session_req )) 
  lurk_s_new_ticket_session_resp = LURKMessage.parse( resp )
  test_struct ( LURKMessage, lurk_s_new_ticket_session_resp)
  try:
    return lurk_s_new_ticket_session_resp[ 'payload' ][ 'ticket_list' ]
  except KeyError:
    raise ValueError( f"expecting s_new_ticket_response. recieved instead"\
                f"{lurk_s_new_ticket_session_resp}" ) 

def lurk_client_ecdhe( server, s_init_cert_verify_req:dict, 
                       s_new_ticket_session_req:dict=None ):
  """ simulates a ECDHE authentication between a LURK client and a crypto service 

  Simulates, from a LURK client point of view, a TLS server that 
  serves initial ECDHE and optionaly provide tickets

  """
  ## s_init_cert_verify_req 
  s_init_cert_verify_req[ 'tag' ]['last_exchange' ] = False
  lurk_s_init_cert_verify_req = \
  { 'designation' : 'tls13',
    'version' : 'v1',
    'type' : 's_init_cert_verify', 
    'status' : 'request', 
    'id' : randbelow( 2  ** 64 ),
    'payload' : s_init_cert_verify_req }
  test_struct ( LURKMessage, lurk_s_init_cert_verify_req )
   
  resp = server.serve( LURKMessage.build( lurk_s_init_cert_verify_req ))
  lurk_s_init_cert_verify_resp = LURKMessage.parse( resp )
  test_struct ( LURKMessage, lurk_s_init_cert_verify_resp )

  if s_new_ticket_session_req != None:
    print( f"--- {lurk_s_init_cert_verify_resp}" )
    s_new_ticket_session_req[ 'session_id' ] = lurk_s_init_cert_verify_resp[ 'payload' ][ 'session_id' ]
    return lurk_client_new_session_ticket( server, s_new_ticket_session_req )



def lurk_client_session_resumption( server, identity, \
      s_init_early_secret_req:dict, s_hand_and_app_secret_req:dict,\
      s_new_ticket_session_req:dict=None ):
  """ simulates a a resumed TLS session 

  """
  ## updating the client_hello with psk identity structure 
  psk_identity = { 'identity' : identity, \
                   'obfuscated_ticket_age' : token_bytes( 4) } 
  psk_binder = {'binder' : b'\xff\xff\xff\xff'}
  offered_psks= { 'identities' : [psk_identity, psk_identity], \
                  'binders' : [psk_binder, psk_binder]}
  client_hello_exts = s_init_early_secret_req[ 'handshake' ][ 0 ][ 'data' ][ 'extensions' ] 
  i = get_struct_index( client_hello_exts, 'extension_type', 'pre_shared_key' )
  s_init_early_secret_req[ 'handshake' ][ 0 ][ 'data' ][ 'extensions' ][ i ][ 'extension_data' ] = offered_psks 
 
  lurk_s_init_early_secret_req = \
  { 'designation' : 'tls13',
    'version' : 'v1',
    'type' : 's_init_early_secret', 
    'status' : 'request', 
    'id' : randbelow( 2  ** 64 ),
    'payload' : s_init_early_secret_req }
  test_struct ( LURKMessage, lurk_s_init_early_secret_req )
  resp = server.serve( LURKMessage.build( lurk_s_init_early_secret_req ))
  lurk_s_init_early_secret_resp = LURKMessage.parse( resp )
  test_struct ( LURKMessage, lurk_s_init_early_secret_resp )

  if lurk_s_init_early_secret_resp[ 'status' ] != 'success':
    print( lurk_s_init_early_secret_resp )
    raise ValueError( f"Error response while expecting SInitEarlySecretResponse" )

  session_id = lurk_s_init_early_secret_resp[ 'payload' ][ 'session_id' ]

  s_hand_and_app_secret_req[ 'session_id' ] = session_id
 
  lurk_s_hand_and_app_secret_req = \
  { 'designation' : 'tls13',
    'version' : 'v1',
    'type' : 's_hand_and_app_secret', 
    'status' : 'request', 
    'id' : randbelow( 2  ** 64 ),
    'payload' : s_hand_and_app_secret_req }
  test_struct ( LURKMessage, lurk_s_hand_and_app_secret_req )
  resp = server.serve( LURKMessage.build( lurk_s_hand_and_app_secret_req ))
  lurk_s_hand_and_app_secret_resp = LURKMessage.parse( resp )
  test_struct ( LURKMessage, lurk_s_hand_and_app_secret_resp )
  if lurk_s_hand_and_app_secret_resp[ 'status' ] != 'success':
    print( lurk_s_hand_and_app_secret_resp )
    raise ValueError( f"Error response while expecting SHandAndAppResponse" )

  if s_new_ticket_session_req != None:
    s_new_ticket_session_req[ 'session_id' ] = session_id
    return lurk_client_new_session_ticket( server, s_new_ticket_session_req )


if TLS_SERVER_LURK_MESSAGE_RESUMPTION == True:
  sig_scheme = 'ed25519'
  conf = Configuration( )
  conf.set_ecdhe_authentication( sig_scheme )
  conf.set_role( 'server' )
  conf.set_extention( ( 'tls13', 'v1' )  ) 
##  tls13_conf = configure(sig_scheme=sig_scheme, role='server')
  server = CryptoService( conf=conf.conf )
  s_init_cert_verify_req = s_init_cert_verify_request_list( sig_scheme, tls13_conf=conf.conf[ ( 'tls13', 'v1' ) ], last_exchange=False )[0]
  s_new_ticket_session_req = s_new_ticket_request_list( )[ 0 ] 
  s_init_early_secret_req = s_init_early_secret_request_list()[ 0 ]
  s_hand_and_app_secret_req = s_hand_and_app_secret_request_list( )[0]
  s_new_ticket_session_req2 = s_new_ticket_request_list( )[ 0 ] 
  
  ticket_list = lurk_client_ecdhe( server, s_init_cert_verify_req, s_new_ticket_session_req)
  identity = ticket_list[ 0 ][ 'ticket' ]
  lurk_client_session_resumption( server, identity, s_init_early_secret_req, s_hand_and_app_secret_req, s_new_ticket_session_req2 )

if TLS_SERVER_LURK_MESSAGE_RESUMPTION_LOOP == True:

  for sig_scheme in sig_scheme_list:
##    conf = configure( sig_scheme=sig_scheme, role='server' )
    conf = Configuration( )
    conf.set_ecdhe_authentication( sig_scheme )
    conf.set_role( 'server' )
    conf.set_extention( ( 'tls13', 'v1' )  ) 
    server = CryptoService( conf=conf.conf )
    
    for s_init_cert_verify_req in s_init_cert_verify_request_list( sig_scheme, tls13_conf=conf.conf[ ( 'tls13', 'v1' ) ], last_exchange=False ):
#      s_init_cert_verify_request_list( sig_scheme, tls13_conf=tls13_conf, last_exchange=False ):
      for s_new_ticket_session_req in  s_new_ticket_request_list():
        for s_init_early_secret_req in s_init_early_secret_request_list():
          for s_hand_and_app_secret_req in s_hand_and_app_secret_request_list():
            for s_new_ticket_session_req2 in s_new_ticket_request_list():
              ticket_list = lurk_client_ecdhe( server, s_init_cert_verify_req, s_new_ticket_session_req)
              identity = ticket_list[ 0 ][ 'ticket' ]
              lurk_client_session_resumption( server, identity, s_init_early_secret_req, s_hand_and_app_secret_req, s_new_ticket_session_req2 )
              
print( "##############################################################" )
print( "## V.2 LURK Exchange Server Session Resumption:             ##" )
print( "## c_init_client_hello - c_server_hello - c_client_finished ##" ) 
print( "## c_register_tickets                                       ##" )
print( "##############################################################" )


def c_tls_client_handshake( conf, c_init_client_hello_req_payload ):

  cs = CryptoService( conf=conf )
    
  ## I do no get why we do have binders.
  if 'binders' in req[ 'handshake'][ 0 ][ 'data' ][ 'extensions' ][ -1 ]\
               [ 'extension_data' ].keys() :
    del req[ 'handshake'][ 0 ][ 'data' ][ 'extensions' ][ -1 ]\
                [ 'extension_data' ][ 'binders' ]
  c_init_client_hello_test( c_init_client_hello_req_payload, 'request' )
  lurk_c_init_client_hello_req = \
  { 'designation' : 'tls13',
    'version' : 'v1',
    'type' : 'c_init_client_hello', 
    'status' : 'request', 
    'id' : randbelow( 2  ** 64 ),
    'payload' : c_init_client_hello_req_payload }

#  session, resp = c_init_client_hello_session( conf, c_init_client_hello_request )
#  print( f"-- session.ephemeral.resp: {session.ephemeral.resp}" ) 
#  print( f"-- session.ephemeral.private_key_list: {session.ephemeral.private_key_list}" )
  bytes_resp = cs.serve( LURKMessage.build( lurk_c_init_client_hello_req ) )
  resp = LURKMessage.parse( bytes_resp )
  print( f"--- c_init_client_hello: {resp}" )
  ## we do not keep track of the keys generated by E, so we skip that case
  ## we do not access the session object as we used to do before
  #  if None in session.ephemeral.private_key_list :
  #    return None
  eph_list = resp[ 'payload' ][ 'ephemeral_list' ]
  if len( eph_list ) == 0:
    return None
  eph = eph_list[ 0 ] 
  if eph[ 'method'  ] == 'e_generated' :
    return None
  ## building server_hello ( expected to be on the server side)
  ch = c_init_client_hello_req_payload[ 'handshake' ][ 0 ]
  sh = c_server_hello_handshake( ch )
  ## determining the ephemeral
  sh_ext_list = [ e[ 'extension_type' ] for e in sh[ 'data' ][ 'extensions' ] ]
  ## From configuration determine the ephemeral
  ## when key share is present it is always generated by the CS
  ## so ephemeral is of mode cs_generated when key_share is present 
  ## and no_secret otherwise
  if 'key_share' in sh_ext_list :
    eph = eph_cs_req
  else:
    eph = eph_no 
  session_id = resp[ 'payload' ][ 'session_id' ]
  c_server_hello_req_payload = \
    { 'session_id' : session_id,
      'handshake' : [ sh ], 
      'ephemeral' : eph }
  ## in our case PSK are never hosted by the CS
  ## so when eph i sset to eph_no we directly go to 
  ## c_client_finished
  psk_in_cs = False
  print( f"eph : {eph} ")
  if eph[ 'method' ] in [ 'cs_generated' ] or psk_in_cs is True :
    ## checking the format of the request
    ext_title = "CServerHelloRequest"
    test_struct( CServerHelloRequest, c_server_hello_req_payload, \
                 ctx_struct={}, ext_title=ext_title, \
                 print_data_struct=False, print_binary=False) 
    ctx_struct = { '_type' : 'c_server_hello', '_status' : 'request' }
    test_struct( TLS13Payload, c_server_hello_req_payload,\
                 ctx_struct=ctx_struct, ext_title=ext_title, \
                 print_data_struct=False, print_binary=False)
    ## getting the response
    ## resp = session.serve( c_server_hello_request, 'c_server_hello', 'request')
    lurk_c_server_hello_req = \
    { 'designation' : 'tls13',
      'version' : 'v1',
      'type' : 'c_server_hello', 
      'status' : 'request', 
      'id' : randbelow( 2  ** 64 ),
      'payload' : c_server_hello_req_payload }
    
    bytes_resp = cs.serve( LURKMessage.build( lurk_c_server_hello_req ) )
    resp = LURKMessage.parse( bytes_resp )
    
    ## checking the format of the response
    test_struct( CServerHelloResponse, resp[ 'payload' ], ctx_struct={}, \
                 ext_title=ext_title, print_data_struct=False,\
                 print_binary=False) 
    ctx_struct = { '_type' : 'c_server_hello', '_status' : 'success' }
    test_struct( TLS13Payload, resp[ 'payload' ], ctx_struct=ctx_struct, \
                 ext_title=ext_title, print_data_struct=False, \
                 print_binary=False)
    handshake = []
  else :
    handshake = [ sh ]
  ## a - deriving keys with handshake secrets
  ## b - decryptiong the encrypted messages
  ## c.1 - application secrets for the application data.
  ## c.2 - when authentication is requested the CS authenticates the client

  ## Possible choices of handshakes
  ## handshake.extend( [ hs_encrypted_extensions, hs_finished ] )  
  handshake.extend( [ hs_encrypted_extensions, hs_certificate_request, hs_certificate_verify, hs_finished ] )  
  ## uncompressed
  certificate_entry = {'cert' : b'certificate_entry', 'extensions':[] }
  certificate = { 'certificate_request_context': b'',
                  'certificate_list' : [certificate_entry, certificate_entry] }
  uncompressed_cert = { 'cert_type' : 'uncompressed',\
                        'certificate' : certificate }
  server_cert = uncompressed_cert
  client_cert = uncompressed_cert
  c_client_finished_req_payload = \
    { 'tag' : { 'last_exchange' : False }, 
      'session_id' : session_id, 
      'handshake' : handshake, 
      'server_certificate' : server_cert,
      'client_certificate' : client_cert }


  ## checking the format of the request
  ext_title = "CClientFinishedRequest"
  test_struct( CClientFinishedRequest, c_client_finished_req_payload, \
               ctx_struct={}, ext_title=ext_title, \
               print_data_struct=False, print_binary=False) 
  ctx_struct = { '_type' : 'c_client_finished', '_status' : 'request' }
  test_struct( TLS13Payload, c_client_finished_req_payload,\
               ctx_struct=ctx_struct, ext_title=ext_title, \
               print_data_struct=False, print_binary=False)
  lurk_c_client_finished_req = \
    { 'designation' : 'tls13',
      'version' : 'v1',
      'type' : 'c_client_finished', 
      'status' : 'request', 
      'id' : randbelow( 2  ** 64 ),
      'payload' : c_client_finished_req_payload }
    

  bytes_resp = cs.serve( LURKMessage.build( lurk_c_client_finished_req ) )
  resp = LURKMessage.parse( bytes_resp )
# resp = session.serve( c_client_finished_request, 'c_client_finished', 'request')
  print( f" -- lurk_c_client_finished_resp: {resp}" ) 
  test_struct( CClientFinishedResponse, resp[ 'payload' ], \
               ctx_struct={}, ext_title=ext_title, \
               print_data_struct=False, print_binary=False) 
  ctx_struct = { '_type' : 'c_client_finished', '_status' : 'success' }
  test_struct( TLS13Payload, resp[ 'payload' ],\
               ctx_struct=ctx_struct, ext_title=ext_title, \
               print_data_struct=False, print_binary=False)

  if resp[ 'payload' ][ 'tag' ][ 'last_exchange' ] is False:
    new_ticket = { \
      'ticket_lifetime':5,\
      'ticket_age_add':6,\
      'ticket_nonce':b'\x07', \
      'ticket':b'\x00\x01\x02\x03',\
      'extensions':[]\
    }
    c_register_req_payload = \
      { 'tag' : { 'last_exchange' : True }, 
        'session_id' : session_id, 
        'ticket_list' : [ new_ticket ] }

    lurk_c_register_req = \
      { 'designation' : 'tls13',
        'version' : 'v1',
        'type' : 'c_register_tickets', 
        'status' : 'request', 
        'id' : randbelow( 2  ** 64 ),
        'payload' :  c_register_req_payload }
      
    bytes_resp = cs.serve( LURKMessage.build( lurk_c_register_req ) )
    resp = LURKMessage.parse( bytes_resp )
    test_struct( LURKMessage, resp,\
                 ctx_struct=ctx_struct, ext_title="toto", \
                 print_data_struct=False, print_binary=False)

if TLS_CLIENT_EXCHANGE is True: 
  for sig_scheme in sig_scheme_list: 
    conf = Configuration( )
    conf.set_ecdhe_authentication( sig_scheme )
    conf.set_role( 'client' )
    conf.set_extention( ext=( 'tls13', 'v1' ) ) 
    print( f"c_init_client_hello_session: conf {conf}" )
    for req in c_init_client_hello_request_list( ) :
      c_tls_client_handshake( conf.conf, req )
print( "EOF" )

