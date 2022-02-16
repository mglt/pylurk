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

from struct_lurk import *
from struct_lurk_tls13 import *
from struct_tls13 import *
from lurk_tls13 import CSession, SSession, get_struct_index
from test_utils import *
from conf import Configuration
from lurk import CryptoService
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
SERVER_PAYLOAD_EXCHANGE = True
## indicates Payload exchanges in IV.3 is performed
## as all signature scheme are tested, it takes a lot of time.
SERVER_PAYLOAD_SESSION_RESUMPTION_LOOP = False

## session resumption with a Crypto Engine for the signature sheme ed25519
SERVER_LURK_MESSAGE_RESUMPTION = True 
## session resumption with a Crypto Engine for all signature shemes
## takes a lot of time
SERVER_LURK_MESSAGE_RESUMPTION_LOOP = False


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
eph_no = { 'ephemeral_method': 'no_secret', 'key': b'' }
for status in [ 'request', 'success' ]: 
  ctx_struct = { '_status' : status }
  test_struct( Ephemeral, eph_no, ext_title='no secret', ctx_struct=ctx_struct )

## Ephemeral (e_generated)
shared_secret = { 'group' : 'secp256r1', 'shared_secret' : token_bytes(32) }
eph_e_req = { 'ephemeral_method': 'e_generated', 'key': shared_secret }
ctx_struct = {'_status' : 'request'}
test_struct( Ephemeral, eph_e_req, ext_title='e_generated', ctx_struct=ctx_struct )

eph_e_resp = { 'ephemeral_method': 'e_generated', 'key': None } # empty in response
ctx_struct = {'_status' : 'success'}
test_struct( Ephemeral, eph_e_resp, ext_title='e_generated', ctx_struct=ctx_struct )


## Ephemeral (cs_generated)
  ## TLS engine requests the generation
eph_cs_req = { 'ephemeral_method': 'cs_generated', 'key': None } 
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
eph_cs_resp = { 'ephemeral_method': 'cs_generated', 'key': keyshare_entry } 
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
## lurk specific format when the ECDHE is generated by the CS
ext51_sh_empty = {'extension_type': 'key_share', \
                'extension_data' : { 'server_share': {'group': 'x448', 'key_exchange': b'' } } }

## psk_extension
psk_id = { 'identity' : b'\x00\x00', \
           'obfuscated_ticket_age' : b'\x00\x01\x02\x03' }
psk_binder = {'binder' : b'\xff\xff\xff\xff'}
offered_psks= { 'identities' : [psk_id, psk_id], \
                'binders' : [psk_binder, psk_binder]}
ext41_ch = { 'extension_type': 'pre_shared_key', \
             'extension_data' : offered_psks }

ext41_sh =  { 'extension_type': 'pre_shared_key', \
              'extension_data' : 0 }

hs_client_hello = {\
  'msg_type': 'client_hello', \
  'data' : {\
    'legacy_version' : b'\x03\x03',
    'random' : token_bytes( 32 ),
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

  The list contains the possible TLS messages for s_init_cert_verify or c_init_client_finished. """
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

  return hs_list 

#def s_init_cert_verify_request_list( sig_algo: str ='ed25519', conf=None, last_exchange=None ):
def s_init_cert_verify_request_list( sig_algo: str ='ed25519', \
                                   tls13_conf=None, last_exchange=None ):
 

  if tls13_conf == None:
    role_list = [ 'server' ]
    finger_print_entry_list = [ { 'finger_print' : token_bytes( 4 ), 'extensions' : [] } ]
    cert_entry_list = [ { 'cert' : b'public bytes', 'extensions' : [] } ]
#    lhs_certificate = deepcopy( hs_certificate )
  else: ## conf overwrites the parameters
    role_list = tls13_conf[ 'role' ]
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
  for role in role_list:
    if role == 'server':
      eph_list = [ eph_cs_req, eph_e_req ]
    elif role == 'client':
      eph_list = [ eph_e_req ]
    for last_exchange in last_exchange_list:
      if last_exchange == False:
        session_id = token_bytes( 4 )
      else:
        session_id = b''
      for ephemeral in eph_list:
        ephemeral_method = ephemeral[ 'ephemeral_method' ]
        for handshake in s_init_cert_verify_handshake_list( ephemeral_method ):
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
            list_req.append( init_cert_verify_req )
  return list_req

def s_init_cert_verify_request_title( req:dict ) -> str:
  """ returns request string description 

  The intent is to print arguments that qualifies req
  """

  tag = req[ 'tag' ][ 'last_exchange' ]
  eph = req[ 'ephemeral' ][ 'ephemeral_method' ]
  try: 
    cert = req[ 'certificate' ]['cert_type'] 
  except KeyError:
    cert = req[ 'client_certificate' ]['cert_type']
  return "last_exchange [%s] - %s - cert_type [%s]"%( tag, eph, cert )

def s_init_cert_verify_test( payload, status ):
  """ tests if payload format matches  (s/c) init_cert_verify request/response """

  if status == 'request':
    ext_title = s_init_cert_verify_request_title( payload )
  elif status == 'success':
    ext_title = init_cert_verify_response_title( payload )
#  ctx_struct = { '_type' : _type, '_certificate_type' : 'X509',\
#                 '_status' : status }
  print( f"{role} - {status} - {payload}" )
  ctx_struct = { '_type' : 's_init_cert_verify', '_status' : status }
  test_struct( TLS13Payload, payload, ctx_struct=ctx_struct, \
               ext_title=ext_title, print_data_struct=True, print_binary=True) 


## testing various configurations of (s/c) init_cert_verify request/responses
for req in s_init_cert_verify_request_list( ):
 #  ext_title = s_init_cert_verify_request_title( req )
  s_init_cert_verify_test( req, 'request' )


## SInitCertVerifyResponse

def init_cert_verify_response_list( sig_algo: str ='ed25519', role='server'):
  """ returns the list of possible response of (s/c)_init_cert_verify """

  if role == 'server':
    eph_list = [ eph_cs_resp, eph_e_resp ]
  elif role == 'client':
    eph_list = [ eph_e_resp ]

  list_resp = []
  for last_exchange in [ True, False ]:
    if last_exchange is False:
      session_id = token_bytes( 4 )
    else:
      session_id = None
    if role == 'server':
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
    elif role == 'client' :
      list_resp.append( {\
        'tag' : { 'last_exchange' : last_exchange }, 
        'session_id' : session_id, 
       'signature' : b'signature' } )
  return list_resp

def init_cert_verify_response_title( resp:dict ) -> str:
  """ returns request string description """

  tag = resp[ 'tag' ][ 'last_exchange' ]
  try: 
    eph = resp[ 'ephemeral' ][ 'ephemeral_method' ]
    return "last_exchange [%s] - %s"%( tag, eph)
  except KeyError:
    return f"last_exchange [{tag}] "

for role in [ 'server', 'client' ]:
  for resp in init_cert_verify_response_list( sig_algo='ed25519', role='server'):
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
  test_struct( TLS13Payload, payload, ctx_struct=ctx_struct,\
               print_data_struct=False, print_binary=False) 
  

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

s_init_early_secret_test( s_init_early_secret_resp, 'success' )

print( "############################################" )
print( "## III.3 Payload SHandAndApp Req and Resp ##" )
print( "############################################" )

#### SHandAndAppRequest

def s_hand_and_app_handshake_list( ephemeral_mode ) -> list:
  """ returns a list of possible handshake messages """

  lhs_server_hello = deepcopy( hs_server_hello )
#  hs_server_hello[ 'data' ][ 'extensions' ] = [ ext45, ext49, ext10, ext41_sh ]
  lhs_server_hello[ 'data' ][ 'extensions' ] = [ ext49, ext10, ext41_sh ]
  if ephemeral_mode == 'cs_generated':
    lhs_server_hello[ 'data' ][ 'extensions' ].append( ext51_sh_empty )
  elif ephemeral_mode == 'e_generated' : 
    lhs_server_hello[ 'data' ][ 'extensions' ].append( ext51_sh )
  ## we do not have key_share extension with PSK without ecdhe mode

  hs = [ lhs_server_hello, hs_encrypted_extensions, hs_certificate_request ]
  return [ hs, deepcopy( hs )[ :-1 ] ]


def s_hand_and_app_secret_request_list( ):
  """ returns a list of s_hand_and_app_secret requests"""

  req_list = []
  for last_exchange in [ True, False ]:
    for ephemeral in [ eph_no, eph_e_req, eph_cs_req ]:
      ephemeral_method  = ephemeral[ 'ephemeral_method' ]
      for handshake in s_hand_and_app_handshake_list( ephemeral_method ):
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
  tag = resp[ 'tag' ][ 'last_exchange' ]
  eph = resp[ 'ephemeral' ][ 'ephemeral_method' ]
  return "last_exchange [%s] - %s"%( tag, eph )


def s_hand_and_app_secret_test( payload, status ):
  ctx_struct = { '_type' : 's_hand_and_app_secret', '_status' : status } 
  ext_title = s_hand_and_app_secret_title( payload ) 
  test_struct( TLS13Payload, payload, ctx_struct=ctx_struct, \
               ext_title=ext_title, print_data_struct=False, print_binary=False) 

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
    test_struct( TLS13Payload, payload, ctx_struct=ctx_struct,\
                 ext_title=ext_title, print_data_struct=False, print_binary=False) 

  elif status == 'success' :
    ctx_struct = { '_type' : 's_new_ticket', '_status' : 'success' } 
    ext_title = s_new_ticket_response_title( payload )
    test_struct( TLS13Payload, payload, ctx_struct=ctx_struct, \
                 ext_title=ext_title, print_data_struct=False, print_binary=False) 

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
  ## taking a local copy to operate changes.
  lhs_server_hello = deepcopy( hs_server_hello )
  if ephemeral_mode == 'cs_generated': # generated by cs
#    lhs_server_hello[ 'data' ][ 'extensions' ].append( ext51_sh_empty )
    lhs_server_hello[ 'data' ][ 'extensions' ] = [ ext51_sh_empty ]
  else: 
#    lhs_server_hello[ 'data' ][ 'extensions' ].append( ext51_sh )
    lhs_server_hello[ 'data' ][ 'extensions' ] = [ ext51_sh ]

  hs_list = [ [ hs_client_hello, lhs_server_hello, hs_encrypted_extensions,\
                hs_certificate_request, hs_certificate_verify,  hs_finished ] ]
  return hs_list 

#def s_init_cert_verify_request_list( sig_algo: str ='ed25519', conf=None, last_exchange=None ):
def c_init_client_finished_request_list( sig_algo: str ='ed25519', \
                                   tls13_conf=None, last_exchange=None ):
 

  if tls13_conf == None:
    role_list = [ 'server' ]
    finger_print_entry_list = [ { 'finger_print' : token_bytes( 4 ), 'extensions' : [] } ]
    cert_entry_list = [ { 'cert' : b'public bytes', 'extensions' : [] } ]
#    lhs_certificate = deepcopy( hs_certificate )
  else: ## conf overwrites the parameters
    role_list = tls13_conf[ 'role' ]
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
  for role in role_list:
    eph_list = [ eph_e_req ]
    for last_exchange in last_exchange_list:
      if last_exchange == False:
        session_id = token_bytes( 4 )
      else:
        session_id = b''
      for ephemeral in eph_list:
        ephemeral_method = ephemeral[ 'ephemeral_method' ]
        for handshake in c_init_client_finished_handshake_list( ephemeral_method ):
          for cert in [ finger_print_cert, uncompressed_cert ]:
            c_init_client_finished_req = {\
              'tag' : { 'last_exchange' : last_exchange }, 
              'session_id' : session_id, 
              'freshness' : 'sha256',
              'ephemeral' : ephemeral, 
              'handshake' : handshake, 
              'server_certificate' : cert,
              'client_certificate' : cert }
            list_req.append( c_init_client_finished_req )
  return list_req

def c_init_client_finished_request_title( req:dict ) -> str:
  """ returns request string description 

  The intent is to print arguments that qualifies req
  """

  tag = req[ 'tag' ][ 'last_exchange' ]
  eph = req[ 'ephemeral' ][ 'ephemeral_method' ]
  try: 
    cert = req[ 'certificate' ]['cert_type'] 
  except KeyError:
    cert = req[ 'client_certificate' ]['cert_type']
  return "last_exchange [%s] - %s - cert_type [%s]"%( tag, eph, cert )

def c_init_client_finished_test( payload, status ):
  """ tests if payload format matches  (s/c) c_init_client_finished request/response """
  _type = 'c_init_client_finished'

  if status == 'request':
    ext_title = c_init_client_finished_request_title( payload )
  elif status == 'success':
    ext_title = c_init_client_finished_response_title( payload )
#  ctx_struct = { '_type' : _type, '_certificate_type' : 'X509',\
#                 '_status' : status }
  print( f"{role} - {status} - {payload}" )
  ctx_struct = { '_type' : _type, '_status' : status }
  test_struct( TLS13Payload, payload, ctx_struct=ctx_struct, \
               ext_title=ext_title, print_data_struct=True, print_binary=True) 


## testing various configurations of (s/c) init_cert_verify request/responses
for req in c_init_client_finished_request_list( ):
 #  ext_title = s_init_cert_verify_request_title( req )
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
  try: 
    eph = resp[ 'ephemeral' ][ 'ephemeral_method' ]
    return "last_exchange [%s] - %s"%( tag, eph)
  except KeyError:
    return f"last_exchange [{tag}] "

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
        'certificate' : cert,
        'sig_algo' : 'ed25519' } )
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
#    print( f"payload: {payload}" )
#    CPostHandAuthRequest.build( payload )
#    test_struct( CPostHandAuthRequest, payload, ctx_struct=ctx_struct,\
#                 ext_title=ext_title, print_data_struct=False, \
#                 print_binary=False) 
    test_struct( TLS13Payload, payload, ctx_struct=ctx_struct,\
                 ext_title=ext_title, print_data_struct=False, \
                 print_binary=False) 


for payload in c_post_hand_auth_request_list( ):
  c_post_hand_auth_test( payload, 'request' )

for payload in c_post_hand_auth_response_list( ):
  c_post_hand_auth_test( payload, 'success' )


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
    print( f"s_init_cert_verify_session: conf {conf}" )
    for req in s_init_cert_verify_request_list( sig_scheme, \
                 tls13_conf=conf, last_exchange=None ):
      session = SSession( conf ) 
      s_init_cert_verify_test( req, 'request' )
      resp = session.serve( req, 's_init_cert_verify', 'request')
      s_init_cert_verify_test( resp, 'success' )
      
if SERVER_PAYLOAD_EXCHANGE == True:
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
      
    
if SERVER_PAYLOAD_EXCHANGE == True:
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
  s_init_early_secret_test( s_init_early_secret_req, 'request' )
  s_init_early_secret_resp = session.serve( s_init_early_secret_req,\
                                            's_init_early_secret', 'request')
  s_init_early_secret_test( s_init_early_secret_resp, 'success' )

  ## s_hand_and_app_secret
  s_hand_and_app_secret_req[ 'session_id' ] = s_init_early_secret_resp[ 'session_id' ]
  s_hand_and_app_secret_test( s_hand_and_app_secret_req, 'request' )
  s_hand_and_app_secret_resp =  session.serve( s_hand_and_app_secret_req,\
                                               's_hand_and_app_secret', 'request')
  s_hand_and_app_secret_test( s_hand_and_app_secret_resp, 'success' )

##if SERVER_PAYLOAD_EXCHANGE == True:
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

if SERVER_PAYLOAD_SESSION_RESUMPTION_LOOP == True:
  for sig_scheme in sig_scheme_list:
    conf = configure( sig_scheme=sig_scheme, role='server' )
    for s_init_cert_verify_req in  s_init_cert_verify_request_list( sig_scheme,\
                                     tls13_conf=conf, last_exchange=False ):
      for s_new_ticket_session_req in  s_new_ticket_request_list():
        for s_init_early_secret_req in s_init_early_secret_request_list():
          for s_hand_and_app_secret_req in s_hand_and_app_secret_request_list():
            for s_new_ticket_session_req2 in s_new_ticket_request_list():
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


if SERVER_PAYLOAD_EXCHANGE == True:
  c_init_client_finished_session()

print( "##################################################################" )
print( "## IV.5 Payload Exchange c_init_client_finished + c_post_hand_auth  ##" )
print( "##################################################################" )

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

if SERVER_PAYLOAD_EXCHANGE == True:
  c_post_hand_auth_session()


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


if SERVER_LURK_MESSAGE_RESUMPTION == True:
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

if SERVER_LURK_MESSAGE_RESUMPTION_LOOP == True:

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
              

print( "EOF" )


## Testing messages on the TLS Client

## CInitClientFinishedRequest
conf = configure('ed25519', role='client')
for req in c_init_client_finished_request_list( conf=conf):
  ext_title = s_init_cert_verify_request_title( req )
#  ctx_struct = { '_type' : 'c_init_client_finished', '_certificate_type' : 'X509' }
  ctx_struct = { '_type' : 'c_init_client_finished' }

## CInitClientFinishedResponse
for resp in init_cert_verify_response_list( role='server'):
##  ext_title = init_cert_verify_response_title( resp )
##  print("::: resp: %s"%resp )
##  ctx_struct = { '_type' : 's_init_cert_verify' } 
##  test_struct( SInitCertVerifyResponse, resp,\
##               ctx_struct=ctx_struct )
  init_cert_verify_print( resp, 'success', role='server' )




