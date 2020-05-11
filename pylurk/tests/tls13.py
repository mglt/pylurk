import sys
import traceback
from copy import deepcopy

from  pylurk.extensions.tls13_lurk_struct import *
from  pylurk.extensions.tls13_tls13_struct import *
from secrets import token_bytes

from pylurk.extensions.tls13 import Conf, ConfBuilder, Session


## from pylurk.utils.utils import set_title
## cannot import because construct 2.10 does not support Embedded 

## TODO:
# import from utils.py instead of copying the fucntion

def title(title):
    """ print title in a square box

    To enhance the readability of the tests, this function prints in the
    terminal teh string title in a square box.

    Args:
        title (str): the string
    """
    space = "    "
    title = space + title + space
    h_line = '+'
    for character in title:
        h_line += '-'
    h_line += '+\n'
    print('\n' + h_line + '|' + title + '|\n' + h_line )

def compare( data_struct1, data_struct2):
  """ compares two data structures """
  if isinstance( data_struct1, (dict, Container) ) and\
     isinstance( data_struct2, (dict, Container) ) :
    ## removing unsignificant variable for container, i.e. used for teh
    ## purpose of data processing
    data_keys = []
    for data_struct in [ data_struct1, data_struct2]:
      keys = list(data_struct.keys())
      if isinstance(data_struct, Container):
        for k in keys[:]:
          if k[0] == '_' or k == 'reserved':
            keys.remove(k)
      data_keys.append(set(keys))
    ## comparing keys
    if not data_keys[0] == data_keys[1]:
      k1 = data_keys[0]
      k2 = data_keys[1]
      raise Exception(\
        "\n    - k1: %s"%k1 + "\n    - k2: %s"%k2 +\
        "\n    - keys in k1 not in k2: %s"%k1.difference(k2) +\
        "\n    - keys in k2 not in k1 :%s"%k2.difference(k1) +\
        "\n    - data_struct1: %s"%data_struct1 +\
        "\n    - data_struct2: %s"%data_struct2 )
    for k in data_keys[1] :
      compare(data_struct1[k], data_struct2[k])
  elif isinstance( data_struct1, (list, set, ListContainer)) and\
     isinstance( data_struct2, (list, set, ListContainer)) :
    for i in range(len(data_struct1)):
      if ( None in data_struct1 and None not in data_struct2): 
        data_struct1.remove(None)
      if ( None in data_struct2 and None not in data_struct1):
        data_struct2.remove(None)
      
    if len(data_struct1) == len(data_struct2):
      for i in range(len(data_struct1)):
         compare(data_struct1[i], data_struct2[i])
    else:
      raise Exception( \
        "\n    - data_struct1 [%s] : %s"%(type(data_struct1), data_struct1) +\
        "\n    - data_struct2 [%s] : %s"%(type(data_struct2), data_struct2) )
  elif isinstance( data_struct1, (str, EnumIntegerString)) and\
     isinstance( data_struct2, (str, EnumIntegerString)) :
    if str(data_struct1) != (data_struct2):
      raise Exception( \
        "\n    - data_struct1 [%s] : %s"%(type(data_struct1), data_struct1) +\
        "\n    - data_struct2 [%s] : %s"%(type(data_struct2), data_struct2) )
  else:
    if data_struct1 != data_struct2:
      print("%s +++ %s"%(type(data_struct1), type(data_struct2)))
      raise Exception( \
        "\n    - data_struct1 [%s] : %s"%(type(data_struct1), data_struct1) +\
        "\n    - data_struct2 [%s] : %s"%(type(data_struct2), data_struct2) )
        

def test_struct( struct, data_struct, ctx_struct={}, \
                 ext_title='', no_title=False, \
                 io_check=True ):
  """ test structures """

  binary = struct.build(data_struct, **ctx_struct)
  data = struct.parse(binary, **ctx_struct)
 
  if not no_title: 
    try:
      name = data._name
    except(AttributeError):
      name = ''
    title("Testing %s [%s]  structure"%(name, ext_title))

  print("struct: %s"%data_struct)
  print("bytes: %s"%binary)
  print("struct: %s"%data)
  if io_check:
    try:
      compare(data_struct, data)
    except AssertionError as e:
      _, _, tb = sys.exc_info()
      traceback.print_tb(tb) # Fixed format
      tb_info = traceback.extract_tb(tb)
      filename, line, func, text = tb_info[-1]
      print('An error occurred on line {} in statement {}'.format(line, text))
      print(e)
      exit(1)
  return binary, data






########################
## TLS 1.3 structures ##
########################

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

print("Public Numbers: %s"%public_numbers)
x = public_numbers.x
y = public_numbers.y
print("  - x: %s"%x)
print("  - x: %s"%(x).to_bytes(32, byteorder='big'))
print("  - y: %s"%y)
print("  - y: %s"%(y).to_bytes(32, byteorder='big'))
secp256r1_key = { 'legacy_form' : 4, 'x' : x, 'y' : y }
ke_entry_secp256r1 = {'group': 'secp256r1', 'key_exchange' : secp256r1_key}

private_key = ec.generate_private_key( ec.SECP384R1(), default_backend())
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()

print("Public Numbers: %s"%public_numbers)
x = public_numbers.x
y = public_numbers.y
print("  - x: %s"%x)
print("  - x: %s"%(x).to_bytes(48, byteorder='big'))
print("  - y: %s"%y)
print("  - y: %s"%(y).to_bytes(48, byteorder='big'))
secp384r1_key = { 'legacy_form' : 4, 'x' : x, 'y' : y }
ke_entry_secp384r1 = {'group': 'secp384r1', 'key_exchange' : secp384r1_key}

private_key = ec.generate_private_key( ec.SECP521R1(), default_backend())
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()

print("Public Numbers: %s"%public_numbers)
x = public_numbers.x
y = public_numbers.y
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

## pre_shared_key
psk_id = {'identity' : b'\x00\x00', \
          'obfuscated_ticket_age' : b'\x00\x01\x02\x03' }
psk_binder = {'binder' : b'\xff\xff\xff\xff'}
offered_psk = { 'identities' : [psk_id, psk_id], \
        'binders' : [psk_binder, psk_binder]}

test_struct(OfferedPsks, offered_psk)

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
  
############################################
## LURK extensions for TLS 1.3 structures ##
############################################

## KeyRequest
data_struct = {"b":True, "e_s":False, "e_x":True, "h_c":False,\
               "h_s":True, "a_c":False, "a_s":True, "x":False, \
               "r":True}
binary, struct = test_struct(KeyRequest, data_struct)

## Secret
secret_data = b'secret'
for secret_type in ['b', 'e_s', 'e_x', 'h_c', 'h_s', 'a_c', 'a_s', 'x', 'r']:
  data_struct = {'secret_type': secret_type, 'secret_data': secret_data}
  test_struct(Secret, data_struct, ext_title=secret_type)

## Extensions

shared_secret = { 'group' : 'secp256r1', 'shared_secret' : token_bytes(32) }

eph_req_ss = { 'extension_type': 'ephemeral',\
               'extension_data': { 'ephemeral_method': 'shared_secret',\
                                'key': shared_secret } }
ctx_struct = {'_status' : 'request'}
ext_title = eph_req_ss['extension_type'] + eph_req_ss['extension_data']['ephemeral_method']
test_struct(LURK13Extension, eph_req_ss, ext_title=ext_title, ctx_struct=ctx_struct)

eph_req_sg = { 'extension_type': 'ephemeral',\
               'extension_data': { 'ephemeral_method': 'secret_generated',
                                   'key': b'' } }
ctx_struct = {'_status' : 'request'}
ext_title = eph_req_sg['extension_type'] + eph_req_sg['extension_data']['ephemeral_method']
test_struct(LURK13Extension, eph_req_sg, ext_title=ext_title, ctx_struct=ctx_struct)


private_key = ec.generate_private_key( ec.SECP256R1(), default_backend())
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()
x = public_numbers.x
y = public_numbers.y
key_exchange = {'legacy_form' : 4, 'x' : x, 'y' : y }
keyshare_entry = { 'group' : 'secp256r1', 'key_exchange' : key_exchange }

eph_resp = { 'extension_type': 'ephemeral',\
               'extension_data': { 'ephemeral_method': 'secret_generated',\
                                'key': keyshare_entry } }
ctx_struct = {'_status' : 'success'}
ext_title = eph_req_ss['extension_type'] + eph_req_ss['extension_data']['ephemeral_method']
test_struct(LURK13Extension, eph_resp, ext_title=ext_title, ctx_struct=ctx_struct)



psk = { 'extension_type': 'psk_id', \
        'extension_data': { 'identity': b'key_identity',\
                            'obfuscated_ticket_age': b'\x00\x01\x02\x03'} }


secret = {'secret_type': 'x', 'secret_data': b'secret'}




frsh = { 'extension_type': 'freshness', 'extension_data': 'sha256'}
sess = { 'extension_type': 'session_id',\
         'extension_data': b'\x00\x01\x02\x03' }


all_ext = [ psk, frsh, sess ]

for ext in all_ext:
  test_struct(LURK13Extension, ext, ext_title=ext['extension_type'])

## SessionID
session_id = {'session_id': b'\x00\x01\x02\x03' }
test_struct(SessionID, session_id)

## SecretRequest
key_req = {"b":True, "e_s":False, "e_x":True, "h_c":False,\
            "h_s":True, "a_c":False, "a_s":True, "x":False, \
            "r":True}

##handshake_ctx = {'msg' : hs_client_hello }
handshake_ctx = [ hs_client_hello ]
##handshake_ctx = [ hs_server_hello ]
ctx_struct = {'_type':'s_init_early_secret'}
sec_req = {'key_request': key_req, \
           'handshake_context': handshake_ctx, \
           'extension_list': all_ext }
binary, struct = test_struct(SecretRequest, sec_req, ctx_struct=ctx_struct)

## SecretResponse
a_c = {'secret_type': 'a_c', 'secret_data': b'secret_ac'}
a_s = {'secret_type': 'a_s', 'secret_data': b'secret_as'}
sec_resp = {'secret_list' : [a_c, a_s], 'extension_list': all_ext}
test_struct(SecretResponse, sec_resp)

## SignatureRequest
key = { 'key_id_type' : 'sha256_32', 'key_id' : b'\x00\x01\x02\x03' }
cert_32 = { 'certificate_type' : 'sha256_32',\
            'certificate_data' : b'\x00\x01\x02\x03' }

cert_entry = {'cert' : b'\x00\x01\x02\x03',\
              'extensions':[] }
cert_tls = {'certificate_request_context' : b'\x00\x01', \
        'certificate_list' : [cert_entry, cert_entry]}
cert_x509 = { 'certificate_type' : 'X509', \
              'certificate_data' : cert_tls}

for cert in [cert_32, cert_x509]:
##  sig_req = {'key_id': key, \
##             'sig_algo' : 'rsa_pkcs1_sha256' ,\
##             'certificate' : cert }
  sig_req = { 'sig_algo' : 'rsa_pkcs1_sha256' }
  ## cannot validate ( I suspect the pointer to certificate_type that
  ## generate the error
  test_struct(SigningRequest, sig_req)

## SignatureResponse
sig_resp = { 'signature' :  b'\x00\x01\x02\x03' }
test_struct(SigningResponse, sig_resp)

exts = [ psk, frsh, sess, eph_req_ss, eph_req_sg ]

##  TLS Server: EarlySecret
sec_req = {'key_request': key_req, \
           'handshake_context': [ hs_client_hello ], \
           'extension_list': exts }
ctx_struct = {'_type': 's_init_early_secret'}
s_init_early_sec_req = {'secret_request' : sec_req }
test_struct(InitEarlySecretRequest, s_init_early_sec_req, ctx_struct=ctx_struct)

s_init_early_sec_resp = {'secret_response' : sec_resp}
test_struct(InitEarlySecretResponse, s_init_early_sec_resp)

## 
ctx_struct = {'_type': 's_init_early_secret', '_status' : 'request'}
test_struct(LURKTLS13Payload, s_init_early_sec_req, ctx_struct=ctx_struct)

ctx_struct = {'_type': 's_init_early_secret', '_status' : 'success'}
test_struct(LURKTLS13Payload, s_init_early_sec_resp, ctx_struct=ctx_struct)

## TLS server: InitCertVerify

hs_all = [ hs_client_hello, \
           hs_server_hello, \
           hs_encrypted_extensions, 
           hs_certificate_request]
hs_opt = [ hs_client_hello, \
           hs_server_hello, \
           hs_encrypted_extensions] 

for hs_ctx in [hs_all, hs_opt]: 
  sec_req = {'key_request': key_req, \
             'handshake_context': hs_ctx, \
             'extension_list': all_ext }
  ctx_struct = {'_type': 's_init_cert_verify'}
  s_init_cert_verify_req = {'secret_request':sec_req, \
                            'signing_request':sig_req }
  test_struct(InitCertVerifyRequest, s_init_cert_verify_req, \
              ctx_struct=ctx_struct)

s_init_cert_verify_resp = {'secret_response' : sec_resp, \
                        'signing_response' : sig_resp }
test_struct(InitCertVerifyResponse, s_init_cert_verify_resp)

##
for hs_ctx in [hs_all, hs_opt]: 
  sec_req = {'key_request': key_req, \
             'handshake_context': hs_ctx, \
             'extension_list': all_ext }
  ctx_struct = {'_type': 's_init_cert_verify'}
  s_init_cert_verify_req = {'secret_request':sec_req, \
                            'signing_request':sig_req }
  ctx_struct = {'_type': 's_init_cert_verify', '_status' : 'request'}
  test_struct(LURKTLS13Payload, s_init_cert_verify_req, ctx_struct=ctx_struct)

ctx_struct = {'_type': 's_init_cert_verify', '_status' : 'success'}
test_struct(LURKTLS13Payload, s_init_cert_verify_resp, ctx_struct=ctx_struct)

## TLS Server: HandshakeRequest

hs_all = [ hs_server_hello, \
           hs_encrypted_extensions, 
           hs_certificate_request]
hs_opt = [ hs_server_hello, \
           hs_encrypted_extensions] 

for hs_ctx in [hs_all, hs_opt]:
  sec_req = {'key_request': key_req, \
             'handshake_context': hs_ctx, \
             'extension_list': all_ext }
  for s_id in [ True, False]:
    ctx_struct = {'_session_id_agreed' : s_id, '_type': 's_hand_and_app_secret'}
    s_hand_req = { 'secret_request':sec_req }
    if s_id is True:
      s_hand_req['session_id'] = b'\x00\x01\x02\x03'
    else:
      s_hand_req['session_id'] = None
    test_struct(HandAndAppRequest, s_hand_req, ctx_struct=ctx_struct)

for s_id in [ True, False]:
  ctx_struct = {'_session_id_agreed' : s_id}
  s_hand_resp = {'secret_response' : sec_resp }
  if s_id is True:
    s_hand_resp['session_id'] = b'\x00\x01\x02\x03'
  else:
    s_hand_resp['session_id'] = None
  test_struct(HandAndAppResponse, s_hand_resp, ctx_struct=ctx_struct)

for hs_ctx in [hs_all, hs_opt]:
  sec_req = {'key_request': key_req, \
             'handshake_context': hs_ctx, \
             'extension_list': all_ext }
  for s_id in [ True, False]:
    ctx_struct = {'_type': 's_hand_and_app_secret', 
                  '_status' : 'request', 
                  '_session_id_agreed' : s_id }
    s_hand_req = { 'secret_request':sec_req }
    if s_id is True:
      s_hand_req['session_id'] = b'\x00\x01\x02\x03'
    else:
      s_hand_req['session_id'] = None
    test_struct(LURKTLS13Payload, s_hand_req, ctx_struct=ctx_struct)

for s_id in [ True, False]:
  ctx_struct = {'_type': 's_hand_and_app_secret', 
                '_status' : 'success',
                '_session_id_agreed' : s_id, }
  s_hand_resp = {'secret_response' : sec_resp }
  if s_id is True:
    s_hand_resp['session_id'] = b'\x00\x01\x02\x03'
  else:
    s_hand_resp['session_id'] = None
  test_struct(LURKTLS13Payload, s_hand_resp, ctx_struct=ctx_struct)


## TLS Server: NewTicket

new_ticket = { \
  'ticket_lifetime':5,\
  'ticket_age_add':6,\
  'ticket_nonce':b'\x07', \
  'ticket':b'\x00\x01\x02\x03',\
  'extensions':[]\
}

s_new_ticket_req = {\
  'session_id':b'\x00\x01\x02\x03', \
  'ticket_nbr':6,\
  'key_request':key_req, 
  'handshake_context':b'\xff\xff\xff\xff'\
}
test_struct(NewTicketRequest, s_new_ticket_req)

s_new_ticket_resp = {\
  'session_id':b'\x00\x01\x02\x03', \
  'ticket_list': [ new_ticket,  new_ticket]
}

test_struct(NewTicketResponse, s_new_ticket_resp)

ctx_struct = {'_type': 's_new_ticket', '_status' : 'request'}
test_struct(LURKTLS13Payload, s_new_ticket_req, ctx_struct=ctx_struct)

ctx_struct = {'_type': 's_new_ticket', '_status' : 'success'}
test_struct(LURKTLS13Payload, s_new_ticket_resp, ctx_struct=ctx_struct)




## Testing s_init_cert_verify 

sig_algos = [ 'rsa_pkcs1_sha256', 
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



def configure(sig_algo):
  conf_builder = ConfBuilder()
  conf_builder.generate_keys( sig_algo, key_format='X509' )
  conf = Conf( conf=conf_builder.export() )
  if sig_algo not in conf.msg( 's_init_cert_verify' )[ 'sig_algo' ]:
    raise Exception( " conf :%s"%\
      conf.msg( 's_init_cert_verify' )[ 'sig_algo' ] + \
      " does not contain %s"%sig_algo) 
  return conf





def hs_list( mtype, ephemeral_mode='secret_generated' ):
  ## supported_signature_algorithms
  ext13 ## all signatures are supported
  ## psk_key_exchange_mode
  ext45 ## all modes are supported
  ##post-handshake authentication
  ext49
  ## supported groups
  ext10 ## all groups are supported
  ## key_share
  ext51_ch # all entries are proposed
  ext51_sh # selects x448 for ECDHE
  ext51_sh_empty ## empty key_share

  ch_ext_list = [ ext13, ext45, ext49, ext10, ext51_ch ]
  hs_client_hello[ 'data' ][ 'extensions' ] = ch_ext_list
  
  sh_ext_list = [ ext49, ext10 ]
  if ephemeral_mode == 'secret_generated':
    sh_ext_list.append( ext51_sh_empty )
  else: 
    sh_ext_list.append( ext51_sh )

  hs_server_hello[ 'data' ][ 'extensions' ] = sh_ext_list
  if mtype == 's_init_cert_verify':
    hs = [ hs_client_hello, \
           hs_server_hello, \
           hs_encrypted_extensions,\
           hs_certificate_request ]

    hs_list = [ hs, deepcopy( hs )[:-1] ]

  return hs_list 

def req_list( mtype, sig_algo ):
  if mtype == 's_init_cert_verify':
    key_req = {"b":False, "e_s":False, "e_x":False, "h_c":True,\
             "h_s":True, "a_c":True, "a_s":True, "x":False, \
             "r":False}
    eph = { 'shared_secret': \
              { 'extension_type': 'ephemeral',\
                'extension_data': \
                  { 'ephemeral_method': 'shared_secret',\
                    'key': shared_secret } }, 
            'secret_generated':\
              {  'extension_type': 'ephemeral',\
                 'extension_data': \
                   { 'ephemeral_method': 'secret_generated',
                     'key': b'' } } }
    frsh = { 'extension_type': 'freshness', 'extension_data': 'sha256'}
    s_id = { 'extension_type': 'session_id', 'extension_data': b'\x00\x01\x02\x03' }
  
    req_list = []
    for eph_mode in [ 'secret_generated', 'shared_secret' ]:
      hs_ctx_list  = hs_list(mtype, ephemeral_mode=eph_mode )
      lurk_ext_list = [ frsh, s_id ]
      lurk_ext_list.append( eph[ eph_mode ] )
      for hs_ctx in hs_ctx_list:
        sec_req = {'key_request': key_req, \
                   'handshake_context': hs_ctx, \
                   'extension_list': lurk_ext_list }
        req_list.append( {'secret_request':sec_req, \
                          'signing_request': { 'sig_algo' : sig_algo } } )
  return req_list

def test_session( mtype ):
  ctx_req = {'_type': mtype, '_status' : 'request'}
  ctx_resp = {'_type': mtype, '_status' : 'success'}
  for sig_algo in sig_algos: 
    conf = configure( sig_algo ) 
    session = Session( conf ) 
    for req in req_list( mtype, sig_algo ):
      test_struct(LURKTLS13Payload, req, ctx_struct=ctx_req )
      resp = session.serve( req, mtype, 'request')
      print("::: resp: %s"%resp )
      test_struct(SigningResponse, resp[ 'signing_response' ] )
      for s in resp[ 'secret_response' ][ 'secret_list' ]:
        test_struct(Secret, s)
#      ctx_struct = {'_status' : 'success'}
      for e in resp[ 'secret_response' ][ 'extension_list' ]:
        test_struct(LURK13Extension, e, ctx_struct=ctx_resp)
      test_struct(LURKTLS13Payload, resp, ctx_struct=ctx_resp )
      
test_session( 's_init_cert_verify' )

