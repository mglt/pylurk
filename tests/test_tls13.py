import sys
import traceback
from copy import deepcopy
import json

from secrets import token_bytes
from cryptography.hazmat.primitives.hashes import Hash, SHA256

## inserting the src in the search path
import sys
sys.path.insert( 0, '../src/')

from pylurk.tls13.struct_tls13 import *
from test_utils import *

## signature_algorithms
sig_list = [
  'rsa_pkcs1_sha256', 
  'rsa_pkcs1_sha384',
  'ecdsa_secp256r1_sha256', 
  'ecdsa_secp384r1_sha384',
  'ed25519', 'ed448'
  ]

sig_scheme_list = { 'supported_signature_algorithms' : sig_list}
test_struct(SignatureSchemeList, sig_scheme_list)

ext13 = {'extension_type': 'signature_algorithms', \
         'extension_data' : sig_scheme_list }
test_struct(Extension, ext13)

## psk_key_exchange_modes
psk_modes = {'ke_modes' : ['psk_ke', 'psk_dhe_ke']}
test_struct( PskKeyExchangeModes, psk_modes)

ext45 = {'extension_type': 'psk_key_exchange_modes', \
         'extension_data' : psk_modes }
test_struct(Extension, ext45)

## pre_shared_key
psk_id = {'identity' : b'\x00\x00', \
          'obfuscated_ticket_age' : b'\x00\x01\x02\x03' }
psk_binder = {'binder' : b'\xff\xff\xff\xff'}
offered_psks= { 'identities' : [psk_id, psk_id], \
                'binders' : [psk_binder, psk_binder]}
test_struct(OfferedPsks, offered_psks)

ext41_ch = { 'extension_type': 'pre_shared_key', \
             'extension_data' : offered_psks }
test_struct(Extension, ext41_ch, ctx_struct={'_msg_type' : 'client_hello' } )

ext41_sh =  { 'extension_type': 'pre_shared_key', \
              'extension_data' : 0 }
test_struct(Extension, ext41_sh, ctx_struct={'_msg_type' : 'server_hello' } )

## post-handshake authentication
ext49 = {'extension_type': 'post_handshake_auth', \
         'extension_data' : {} }
test_struct(Extension, ext49)

## supported_group

grp = {'named_group_list' : ['secp256r1', 'secp384r1', 'x25519', 'x448' ]}

test_struct(NamedGroupList, grp)

ext10 = {'extension_type': 'supported_groups', \
         'extension_data' : grp }
test_struct(Extension, ext10)

## key_share
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

private_key = ec.generate_private_key( ec.SECP256R1(), default_backend())
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()

x = public_numbers.x
y = public_numbers.y

print("Public Numbers: %s"%public_numbers)
print("  - x: %s"%x)
print("  - x: %s"%(x).to_bytes(32, byteorder='big'))
print("  - y: %s"%y)
print("  - y: %s"%(y).to_bytes(32, byteorder='big'))

secp256r1_key = { 'legacy_form' : 4, 'x' : x, 'y' : y }
ke_entry_secp256r1 = {'group': 'secp256r1', 'key_exchange' : secp256r1_key}

private_key = ec.generate_private_key( ec.SECP384R1(), default_backend())
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()

x = public_numbers.x
y = public_numbers.y

print("Public Numbers: %s"%public_numbers)
print("  - x: %s"%x)
print("  - x: %s"%(x).to_bytes(48, byteorder='big'))
print("  - y: %s"%y)
print("  - y: %s"%(y).to_bytes(48, byteorder='big'))

secp384r1_key = { 'legacy_form' : 4, 'x' : x, 'y' : y }
ke_entry_secp384r1 = {'group': 'secp384r1', 'key_exchange' : secp384r1_key}

private_key = ec.generate_private_key( ec.SECP521R1(), default_backend())
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()

x = public_numbers.x
y = public_numbers.y

print("Public Numbers: %s"%public_numbers)
print("  - x: %s"%x)
print("  - x: %s"%(x).to_bytes(66, byteorder='big'))
print("  - y: %s"%y)
print("  - y: %s"%(y).to_bytes(66, byteorder='big'))
secp521r1_key = { 'legacy_form' : 4, 'x' : x, 'y' : y }
ke_entry_secp512r1 = {'group': 'secp521r1', 'key_exchange' : secp521r1_key}


from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

private_key = X25519PrivateKey.generate()
public_key = private_key.public_key()
x25519_key = public_key.public_bytes(
          encoding=serialization.Encoding.Raw,
          format=serialization.PublicFormat.Raw)
ke_entry_x25519 = {'group': 'x25519', 'key_exchange' : x25519_key}

from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

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

ks_ch = {'client_shares' : ke_entries}
test_struct(KeyShareClientHello, ks_ch)

ks_hr = {'selected_group' : 'x448' }
test_struct(KeyShareHelloRetryRequest, ks_hr)

for ke_entry in ke_entries:
  ks_sh = {'server_share' : ke_entry }
  test_struct(KeyShareServerHello, ks_sh)

empty_ke_entry = {'group': 'x448', 'key_exchange': b'' }
test_struct( EmptyKeyShareEntry, empty_ke_entry )  

ks_sh_empty = { 'server_share': empty_ke_entry }
test_struct( KeyShareServerHelloEmpty, ks_sh_empty )


ext51_ch = {'extension_type': 'key_share', \
            'extension_data' : ks_ch }
ctx_struct = {'_msg_type' : 'client_hello'}
test_struct(Extension, ext51_ch, ctx_struct=ctx_struct)

ext51_hr = {'extension_type': 'key_share', \
            'extension_data' : ks_hr }
ctx_struct = {'_msg_type' : 'server_hello'}
test_struct(Extension, ext51_hr, ctx_struct=ctx_struct)

ext51_sh = {'extension_type': 'key_share', \
            'extension_data' : ks_sh }
ctx_struct = {'_msg_type' : 'server_hello'}
test_struct(Extension, ext51_sh, ctx_struct=ctx_struct)

ext51_sh_empty = {'extension_type': 'key_share', \
                  'extension_data' : ks_sh_empty }
ctx_struct = {'_msg_type' : 'server_hello'}
test_struct(Extension, ext51_sh_empty, ctx_struct=ctx_struct)


## III TLS messages
## Some Extensions have different structures depending on the msg_type
## parameter. As a result, it is preferred to test the message via the
##  Handshake structure. 

## client_hello
random = token_bytes( 32 )
client_hello = {\
  'legacy_version' : b'\x03\x03',
  'random' : random,
  'cipher_suites' : ['TLS_AES_128_GCM_SHA256', 'TLS_CHACHA20_POLY1305_SHA256'],
  'legacy_compression_methods' : b'\x00',
  'extensions' : [ext49]
  }
test_struct(ClientHello, client_hello)

client_hello['extensions'].append(ext51_ch)
ctx_struct = {'msg_type': 'client_hello'}
#test_struct(ClientHello, client_hello, ctx_struct=ctx_struct)

hs_client_hello = {'msg_type': 'client_hello', 'data' : client_hello}
test_struct(Handshake, hs_client_hello)

## server_hello

server_hello = {
  'legacy_version' : b'\x03\x03',
  'random' : random,
  'cipher_suite' :'TLS_AES_128_GCM_SHA256',
  'legacy_compression_method' : b'\x00',
  'extensions' : [ext49, ext51_sh]
  }
hs_server_hello = {'msg_type': 'server_hello', 'data' : server_hello}
## unexplained error with check
test_struct(Handshake, hs_server_hello)

# end_of_early_data
hs_end_of_early_data = {
  'msg_type' : 'end_of_early_data', 
  'data' : {}}
test_struct(Handshake, hs_end_of_early_data)

##encrypted_extensions
hs_encrypted_extensions = {
  'msg_type' : 'encrypted_extensions', 
  'data' : { 'extensions' :  [ ext49, ext13, ext45 ] }
}
test_struct(Handshake, hs_encrypted_extensions)

## certificate_request

hs_certificate_request = {
  'msg_type' : 'certificate_request', 
  'data' : { 'certificate_request_context' :  b'\x00\x01',
             'extensions' : [ ext49, ext13, ext45 ] }

}
test_struct(Handshake, hs_certificate_request)


## certificate
cert_entry = {'cert' : b'\x00\x01\x02\x03',\
              'extensions':[] }
cert = { 'certificate_request_context' : b'\x00\x01', 
         'certificate_list' : [ cert_entry, cert_entry, cert_entry ] }
ctx_struct = { '_certificate_type' : 'X509' }
test_struct(Certificate, cert, ctx_struct=ctx_struct)

hs_certificate = {
  'msg_type' : 'certificate', 
  'data' : { 'certificate_request_context' : b'\x00\x01', 
             'certificate_list' : [ cert_entry, cert_entry, cert_entry ] }
}
ctx_struct = { '_certificate_type' : 'X509' }
test_struct(Handshake, hs_certificate, ctx_struct=ctx_struct)


## certificate_verify
hs_certificate_verify = {
  'msg_type' : 'certificate_verify',
  'data' : { 'algorithm' : 'ed25519', 
             'signature' : b'\x00\x01\x02' }
}
test_struct(Handshake, hs_certificate_verify)

## finished
hs_finished = {
  'msg_type' : 'finished', 
  'data' : {'verify_data' : token_bytes( 32 )}
}
ctx_struct = { '_cipher' : 'TLS_AES_128_GCM_SHA256' }
test_struct(Handshake, hs_finished, ctx_struct=ctx_struct)

## NewSessionTicket
new_session_ticket = { \
  'ticket_lifetime':5,\
  'ticket_age_add':6,\
  'ticket_nonce':b'\x07', \
  'ticket':b'\x00\x01\x02\x03',\
  'extensions':[]\
}

hs_new_session_ticket = {'msg_type' : 'new_session_ticket', 
                         'data' : new_session_ticket }
test_struct(Handshake, hs_new_session_ticket)


## key_update
hs_key_update = {
  'msg_type' : 'key_update', 
  'data' : {'request_update' : 'update_requested' }
}
test_struct(Handshake, hs_key_update)
  
