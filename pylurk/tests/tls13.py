import sys
import traceback
from copy import deepcopy
#import binascii
#from binascii import hexlify
import json
import bytes

from  pylurk.extensions.tls13_lurk_struct import *
from  pylurk.extensions.tls13_tls13_struct import *
from secrets import token_bytes
from cryptography.hazmat.primitives.hashes import Hash, SHA256

from pylurk.extensions.tls13 import Conf, ConfBuilder, SSession,CSession, get_struct_index
from pylurk.core.lurk import LurkServer
from pylurk.core.lurk_struct import LURKMessage

## from pylurk.utils.utils import set_title
## cannot import because construct 2.10 does not support Embedded 

## TODO:
# import from utils.py instead of copying the fucntion

## TLS 1.3 structures
TLS13_STRUCTURE = True
## payload exchange on TLS server
LURK_SERVER_PAYLOAD_EXCHANGE = True
## payload exchange on TLS server (most possibilities)
LURK_SERVER_PAYLOAD_SESSION_RESUMPTION_LOOP = True
## lurk exchange on TLS server
LURK_SERVER_SESSION_RESUMPTION = True
## lurk exchange on TLS server (most possibilities)
LURK_SERVER_SESSION_RESUMPTION_LOOP = True


DEBUG_MODE = False



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
      if data_struct1 in  [ None, b'' ] and data_struct2 in [ None, b'' ]:
        pass
      else:
         raise Exception( \
           "\n    - data_struct1 [%s] : %s"%(type(data_struct1), data_struct1) +\
           "\n    - data_struct2 [%s] : %s"%(type(data_struct2), data_struct2) )
   
from _io import BytesIO

def obj2json( data:dict ) -> dict:
  """ converts a bytes or bytearray value to string """ 
  json_data = deepcopy( data ) 
  if isinstance( json_data, BytesIO ) :
    json_data = json_data.read()
  if isinstance( json_data, bytes ) or\
     isinstance( json_data, bytearray ) : #or\
#     isinstance( json_data, BytesIO) :
    json_data = json_data.hex( '-' )
  elif isinstance( json_data, dict ):
    for k in json_data.keys():
##      if isinstance( json_data[ k ], BytesIO ):
##        del json_data[ k ]
##      else:
        json_data[ k ] = obj2json( json_data[ k ] )
  elif isinstance( json_data, list ):
    for i in range( len( json_data ) ):
      json_data[ i ] = obj2json( json_data[ i ] )
  else:
    c = json_data.__class__.__name__
##    if c == 'BytesIO':
##      print( "class: %s, object: %s, type: %s"%(c, json_data.read(), type( json_data ) ) )
       
  return json_data


def test_struct( struct, data_struct, ctx_struct={}, \
                 ext_title='', no_title=False, \
                 io_check=True, print_data_struct=DEBUG_MODE, \
                 print_binary=False, print_data=False ):
  """ test structures """

  binary = struct.build(data_struct, **ctx_struct)
  data = struct.parse(binary, **ctx_struct)
 
  if not no_title: 
    try:
      name = data._name
    except(AttributeError):
      name = ''
    title("%s [%s]  structure"%(name, ext_title))

  if print_data_struct == True:
    print("struct: %s"%json.dumps( obj2json( data_struct ), indent=2) )
  if print_binary == True:
    print("bytes: %s"%binary.hex( '-' ) )
  if print_data == True:
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

if TLS13_STRUCTURE == True:
  test_struct(SignatureSchemeList, sig_scheme_list)

ext13 = {'extension_type': 'signature_algorithms', \
         'extension_data' : sig_scheme_list }

if TLS13_STRUCTURE == True:
  test_struct(Extension, ext13)

## psk_key_exchange_modes
psk_modes = {'ke_modes' : ['psk_ke', 'psk_dhe_ke']}

if TLS13_STRUCTURE == True:
  test_struct( PskKeyExchangeModes, psk_modes)

ext45 = {'extension_type': 'psk_key_exchange_modes', \
         'extension_data' : psk_modes }

if TLS13_STRUCTURE == True:
  test_struct(Extension, ext45)

## pre_shared_key
psk_id = {'identity' : b'\x00\x00', \
          'obfuscated_ticket_age' : b'\x00\x01\x02\x03' }
psk_binder = {'binder' : b'\xff\xff\xff\xff'}

offered_psks= { 'identities' : [psk_id, psk_id], \
                'binders' : [psk_binder, psk_binder]}

if TLS13_STRUCTURE == True:
  test_struct(OfferedPsks, offered_psks)

ext41_ch = { 'extension_type': 'pre_shared_key', \
             'extension_data' : offered_psks }

if TLS13_STRUCTURE == True:
  test_struct(Extension, ext41_ch, ctx_struct={'_msg_type' : 'client_hello' } )

ext41_sh =  { 'extension_type': 'pre_shared_key', \
              'extension_data' : 0 }

if TLS13_STRUCTURE == True:
  test_struct(Extension, ext41_sh, ctx_struct={'_msg_type' : 'server_hello' } )



## post-handshake authentication
ext49 = {'extension_type': 'post_handshake_auth', \
         'extension_data' : {} }

if TLS13_STRUCTURE == True:
  test_struct(Extension, ext49)

## supported_group

grp = {'named_group_list' : ['secp256r1', 'secp384r1', 'x25519', 'x448' ]}

if TLS13_STRUCTURE == True:
  test_struct(NamedGroupList, grp)

ext10 = {'extension_type': 'supported_groups', \
         'extension_data' : grp }
if TLS13_STRUCTURE == True:
  test_struct(Extension, ext10)

## key_share
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

private_key = ec.generate_private_key( ec.SECP256R1(), default_backend())
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()

x = public_numbers.x
y = public_numbers.y

if TLS13_STRUCTURE == True:
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

if TLS13_STRUCTURE == True:
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

if TLS13_STRUCTURE == True:
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

if TLS13_STRUCTURE == True:
  test_struct(KeyShareClientHello, ks_ch)

ks_hr = {'selected_group' : 'x448' }
if TLS13_STRUCTURE == True:
  test_struct(KeyShareHelloRetryRequest, ks_hr)

for ke_entry in ke_entries:
  ks_sh = {'server_share' : ke_entry }
  if TLS13_STRUCTURE == True:
    test_struct(KeyShareServerHello, ks_sh)

empty_ke_entry = {'group': 'x448', 'key_exchange': b'' }
if TLS13_STRUCTURE == True:
  test_struct( EmptyKeyShareEntry, empty_ke_entry )  

ks_sh_empty = { 'server_share': empty_ke_entry }
if TLS13_STRUCTURE == True:
  test_struct( KeyShareServerHelloEmpty, ks_sh_empty )


ext51_ch = {'extension_type': 'key_share', \
            'extension_data' : ks_ch }
ctx_struct = {'_msg_type' : 'client_hello'}

if TLS13_STRUCTURE == True:
  test_struct(Extension, ext51_ch, ctx_struct=ctx_struct)

ext51_hr = {'extension_type': 'key_share', \
            'extension_data' : ks_hr }
ctx_struct = {'_msg_type' : 'server_hello'}

if TLS13_STRUCTURE == True:
  test_struct(Extension, ext51_hr, ctx_struct=ctx_struct)

ext51_sh = {'extension_type': 'key_share', \
            'extension_data' : ks_sh }

ctx_struct = {'_msg_type' : 'server_hello'}

if TLS13_STRUCTURE == True:
  test_struct(Extension, ext51_sh, ctx_struct=ctx_struct)

ext51_sh_empty = {'extension_type': 'key_share', \
                  'extension_data' : ks_sh_empty }

ctx_struct = {'_msg_type' : 'server_hello'}

if TLS13_STRUCTURE == True:
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
  
print( "############################################" )
print( "## LURK extensions for TLS 1.3 structures ##" )
print( "############################################" )

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

## Ephemeral (secret_provided)
shared_secret = { 'group' : 'secp256r1', 'shared_secret' : token_bytes(32) }
eph_provided = { 'ephemeral_method': 'secret_provided', 'key': shared_secret }
ctx_struct = {'_status' : 'request'}
test_struct( Ephemeral, eph_provided, ext_title='secret_provided', ctx_struct=ctx_struct )

## Ephemeral (secret_generated)
  ## CS generates private/ public part of teh ECDHE
private_key = ec.generate_private_key( ec.SECP256R1(), default_backend())
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()
x = public_numbers.x
y = public_numbers.y
  ## CS returns the public part of teh ECDHE using the KeyShare Entry format
key_exchange = {'legacy_form' : 4, 'x' : x, 'y' : y }
keyshare_entry = { 'group' : 'secp256r1', 'key_exchange' : key_exchange }
  ## CS response
eph_gen = { 'ephemeral_method': 'secret_generated', 'key': keyshare_entry } 
ctx_struct = {'_status' : 'success'}
test_struct( Ephemeral, eph_gen, ext_title="secret_generated", ctx_struct=ctx_struct ) 

## certificate ( empty )
cert_empty = { 'certificate_type': 'empty', 'certificate_data' : b'' }
test_struct( LURKTLS13Certificate, cert_empty, ext_title = "empty" ) 

## certificate ( finger_print )
cert_entry = {'cert' : b'certificate_entry', 'extensions':[] }
  ## TLS certificate structure 
hs_cert = { 'msg_type' : 'certificate', 
            'data' :  { 'certificate_request_context': b'',
                        'certificate_list' : [cert_entry, cert_entry] } }
digest = Hash( SHA256(), backend=default_backend())
digest.update( Handshake.build( hs_cert, _certificate_type='X509' ))
cert_finger = {'certificate_type': 'finger_print', 'certificate_data': digest.finalize()[:4]}
test_struct( LURKTLS13Certificate, cert_finger, ext_title = "finger_print" ) 

## certificate ( uncompressed) 
cert_uncompressed = {'certificate_type': 'uncompressed', 
                     'certificate_data': hs_cert[ 'data' ] }
ctx_struct = { '_certificate_type' : 'X509' }
test_struct( Certificate, hs_cert[ 'data' ],\
             ext_title = "certificate", ctx_struct=ctx_struct ) 
test_struct( LURKTLS13Certificate, cert_uncompressed,\
             ext_title = "uncompressed", ctx_struct=ctx_struct ) 

## psk_id
psk_id = { 'identity': b'key_id', 'obfuscated_ticket_age': b'\x00\x01\x02\x03'}
test_struct( PskIdentity, psk_id ) 



## SInitCertVerifyRequest

def init_cert_verify_handshake_list( ephemeral_mode:str, role='server') -> list:
  """ returns a list of possible handshake messages """
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

  hs_client_hello[ 'data' ][ 'extensions' ] = \
    [ ext13, ext45, ext49, ext10, ext51_ch ]
  
  hs_server_hello[ 'data' ][ 'extensions' ] = [ ext49, ext10 ]
  if ephemeral_mode == 'secret_generated':
    hs_server_hello[ 'data' ][ 'extensions' ].append( ext51_sh_empty )
  else: 
    hs_server_hello[ 'data' ][ 'extensions' ].append( ext51_sh )

  if role == 'server':
    hs = [ hs_client_hello, hs_server_hello, hs_encrypted_extensions,\
           hs_certificate_request ]
    hs_list = [ hs, deepcopy( hs )[:-1] ]

  elif role == 'server':
    hs_list = [ hs_client_hello, hs_server_hello, hs_encrypted_extensions,\
                hs_certificate_request, hs_certificate, hs_certificate_verify,\
                hs_finished ]

  return hs_list 

def init_cert_verify_request_list( sig_algo: str ='ed25519', conf=None, last_exchange=None ):
 
  if conf == None:
    role = 'server'
    fp = token_bytes( 4 )
    cert_data = hs_cert[ 'data' ] 
  else: 
    role = conf.role()
    fp = conf.cert_finger_print
    cert_data = conf.hs_cert_msg[ 'data' ]

  eph_gen = { 'ephemeral_method': 'secret_generated', 'key': None } # empty in request
  eph_provided = {\
    'ephemeral_method': 'secret_provided', 
    'key':  { 'group' : 'secp256r1', 
              'shared_secret' : token_bytes(32) } }
  if role == 'server':
    eph_list = [ eph_gen, eph_provided ]
  elif role == 'client':
    eph_list = [ eph_provided ]

  cert_finger = { 'certificate_type' : 'finger_print', 'certificate_data' : fp }
  cert_uncompressed = { 'certificate_type' : 'uncompressed',
                        'certificate_data' : cert_data }

  if last_exchange == None:
    last_exchange_list = [ True, False ]
  else:
    last_exchange_list = [ last_exchange ]

  list_req = []
  for last_exchange in last_exchange_list:
    if last_exchange == False:
      session_id = token_bytes( 4 )
    else:
      session_id = None
    for ephemeral in [ eph_gen, eph_provided ]:
      for handshake in init_cert_verify_handshake_list(ephemeral[ 'ephemeral_method' ], role=role ):
        for cert in [ cert_finger, cert_uncompressed ]:
          init_cert_verify_req = {\
            'tag' : { 'last_exchange' : last_exchange }, 
            'session_id' : session_id, 
            'freshness' : 'sha256',
            'ephemeral' : ephemeral, 
            'handshake' : handshake, 
            'certificate' : cert,
            'secret_request' : { "b":False, "e_s":False, "e_x":False, "h_c":True,\
                                 "h_s":True, "a_c":True, "a_s":True, "x":True, "r":False },
            'sig_algo' : sig_algo }
          list_req.append( init_cert_verify_req )
  return list_req

def init_cert_verify_request_title( req:dict ) -> str:
  """ returns the title associated to the request """
  tag = req[ 'tag' ][ 'last_exchange' ]
  eph = req[ 'ephemeral' ][ 'ephemeral_method' ]
  cert = req[ 'certificate' ]['certificate_type'] 
  return "last_exchange [%s] - %s - cert_type [%s]"%( tag, eph, cert )

def init_cert_verify_print( payload, status, role='server' ):
  if role == 'server':
    _type = 's_init_cert_verify'
  elif role == 'client':
    _type = 'c_init_cert_verify'

  if status == 'request':
    ext_title = init_cert_verify_request_title( payload )
  elif status == 'success':
    ext_title = init_cert_verify_response_title( payload )
  ctx_struct = { '_type' : _type, '_certificate_type' : 'X509',\
                 '_status' : status }
  test_struct( LURKTLS13Payload, payload, ctx_struct=ctx_struct, \
               ext_title=ext_title, print_data_struct=False, print_binary=False) 


for req in init_cert_verify_request_list():
  ext_title = init_cert_verify_request_title( req )
  ctx_struct = { '_type' : 's_init_cert_verify', '_certificate_type' : 'X509' }
##  test_struct( SInitCertVerifyRequest, req, ctx_struct=ctx_struct, ext_title=ext_title )
  init_cert_verify_print( req, 'request' )

## SInitCertVerifyResponse

def init_cert_verify_response_list( sig_algo: str ='ed25519', role='server'):


  eph_gen = { 
    'ephemeral_method': 'secret_generated', 
    'key': { 'group' : 'secp256r1', 
             'key_exchange' : key_exchange } }
  eph_provided = { 'ephemeral_method': 'secret_provided', 'key': None } # empty in response

  if role == 'server':
    eph_list = [ eph_gen, eph_provided ]
  elif role == 'client':
    eph_list = [ eph_provided ]

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
        'secret_list' : [ {'secret_type': 'h_c', 'secret_data': b'hand_client_secret' }, 
                          {'secret_type': 'h_s', 'secret_data': b'hand_server_secret' },
                          {'secret_type': 'a_c', 'secret_data': b'app_client_secret' },
                          {'secret_type': 'a_s', 'secret_data': b'app_server_secret' } ],
       'signature' : b'signature' } )
  return list_resp

def init_cert_verify_response_title( resp:dict ) -> str:
  tag = resp[ 'tag' ][ 'last_exchange' ]
  eph = resp[ 'ephemeral' ][ 'ephemeral_method' ]
  return "last_exchange [%s] - %s"%( tag, eph)

for resp in init_cert_verify_response_list( role='server'):
##  ext_title = init_cert_verify_response_title( resp )
##  print("::: resp: %s"%resp )
##  ctx_struct = { '_type' : 's_init_cert_verify' } 
##  test_struct( SInitCertVerifyResponse, resp,\
##               ctx_struct=ctx_struct )
  init_cert_verify_print( resp, 'success' )

## SInitEarlySecretRequest

def s_init_early_secret_handshake_list( psk_id=None ) -> list:
  """ returns a list of possible handshake messages """
  ## pre_shared_key
  if psk_id == None:
    psk_id = {'identity' : b'\x00\x00', \
              'obfuscated_ticket_age' : b'\x00\x01\x02\x03' }
  psk_binder = {'binder' : b'\xff\xff\xff\xff'}
  offered_psks= { 'identities' : [psk_id, psk_id], \
                'binders' : [psk_binder, psk_binder]}
  ext41_ch = { 'extension_type': 'pre_shared_key', \
               'extension_data' : offered_psks }
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

  hs_client_hello[ 'data' ][ 'extensions' ] = \
    [ ext13, ext45, ext49, ext10, ext51_ch, ext41_ch ]
  
  return [ hs_client_hello ]
 
def s_init_early_secret_request_list( psk_id=None):
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

def s_init_early_secret_print( payload, status ):
  ctx_struct = { '_type' : 's_init_early_secret', '_status' : status } 
  test_struct( LURKTLS13Payload, payload, ctx_struct=ctx_struct,\
               print_data_struct=False, print_binary=False) 
  

for req in s_init_early_secret_request_list( ):
  ctx_struct = { '_type' : 's_init_early_secret' } 
  test_struct( SInitEarlySecretRequest, req, ctx_struct=ctx_struct ) 
  s_init_early_secret_print( req, 'request' )



## SInitEarlySecretResponse

s_init_early_secret_resp = { \
  'session_id' : token_bytes( 4 ), 
  'secret_list' : [ {'secret_type': 'b', 'secret_data': b'binder_key' }, 
                    {'secret_type': 'e_s', 'secret_data': b'early_secret' },
                    {'secret_type': 'e_x', 'secret_data': b'early_exporter' } ] }
ctx_struct = { '_type' : 's_init_early_secret' } 
test_struct( SInitEarlySecretResponse, s_init_early_secret_resp,\
             ctx_struct=ctx_struct )

s_init_early_secret_print( s_init_early_secret_resp, 'success' )

#### SHandAndAppRequest

def s_hand_and_app_handshake_list( ephemeral_mode ) -> list:
##      'handshake' : [ hs_server_hello, hs_encrypted_extensions, hs_certificate_request ], 
  """ returns a list of possible handshake messages """
  ## pre_shared_key
  ext41_sh =  { 'extension_type': 'pre_shared_key', \
                'extension_data' : 0 }
  ## psk_key_exchange_mode
  ext45 ## all modes are supported
  ##post-handshake authentication
  ext49
  ## supported groups
  ext10 ## all groups are supported
  ## key_share
  ext51_sh # selects x448 for ECDHE
  ext51_sh_empty ## empty key_share

  hs_server_hello[ 'data' ][ 'extensions' ] = [ ext45, ext49, ext10, ext41_sh ]
  if ephemeral_mode == 'secret_generated':
    hs_server_hello[ 'data' ][ 'extensions' ].append( ext51_sh_empty )
  else: 
    hs_server_hello[ 'data' ][ 'extensions' ].append( ext51_sh )

  hs = [ hs_server_hello, hs_encrypted_extensions,\
         hs_certificate_request ]
  return [ hs, deepcopy( hs )[:-1] ]


def s_hand_and_app_secret_request_list( ):
  eph_gen = { 'ephemeral_method': 'secret_generated', 'key': None } # empty in request
  eph_provided = {\
    'ephemeral_method': 'secret_provided', 
    'key':  { 'group' : 'secp256r1', 
              'shared_secret' : token_bytes(32) } }
  eph_no = { 'ephemeral_method': 'no_secret', 'key': None } # empty in request

  req_list = []
  for last_exchange in [ True, False ]:
    for ephemeral in [ eph_no, eph_provided, eph_gen ]:
      for handshake in s_hand_and_app_handshake_list( ephemeral[ 'ephemeral_method' ] ):
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


def s_hand_and_app_secret_print( payload, status ):
  ctx_struct = { '_type' : 's_hand_and_app_secret', '_status' : status } 
  ext_title = s_hand_and_app_secret_title( payload ) 
  test_struct( LURKTLS13Payload, payload, ctx_struct=ctx_struct, \
               ext_title=ext_title, print_data_struct=False, print_binary=False) 

for req in s_hand_and_app_secret_request_list():
  ext_title = s_hand_and_app_secret_title( req )
  ctx_struct = { '_type' : 's_hand_and_app_secret', '_status' : 'request' }
  test_struct( SHandAndAppRequest, req, ctx_struct=ctx_struct, ext_title=ext_title )
  s_hand_and_app_secret_print( req, 'request' )
      

## SHandAndAppResponse

for last_exchange in [ True, False ]:
  for ephemeral in [ eph_no, eph_gen ]:
    s_hand_and_app_resp = {\
      'tag' : { 'last_exchange' : last_exchange }, 
      'session_id' : token_bytes (4 ), 
      'ephemeral' : ephemeral, 
      'secret_list' : [ {'secret_type': 'h_c', 'secret_data': b'hand_client_secret' }, 
                        {'secret_type': 'h_s', 'secret_data': b'hand_server_secret' },
                        {'secret_type': 'a_c', 'secret_data': b'app_client_secret' },
                        {'secret_type': 'a_s', 'secret_data': b'app_server_secret' } ] }
    ctx_struct = { '_type' : 's_hand_and_app_secret', '_status' : 'request' } 
    test_struct( SHandAndAppResponse, s_hand_and_app_resp,\
                 ctx_struct=ctx_struct )
    s_hand_and_app_secret_print( s_hand_and_app_resp, 'success' )

## SNewTicketRequest

def s_new_ticket_handshake_list() -> list:
  """ returns a list of possible handshake messages """
  return [ [ hs_finished ],\
           [ hs_certificate_verify, hs_finished ] ]


def s_new_ticket_request_list( ):
  list_req = []
  for last_exchange in [ True, False ]:
    for cert in [ cert_empty, cert_finger, cert_uncompressed ]:
      for handshake in s_new_ticket_handshake_list():
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
  cert = req[ 'certificate' ]['certificate_type'] 
  return "last_exchange [%s] - cert_type [%s]"%( tag, cert )

def s_new_ticket_print( payload, status ):
  if status == 'request':
    ctx_struct = { '_type' : 's_new_ticket', '_status' : 'request', \
                   '_certificate_type' : 'X509', '_cipher' : 'TLS_AES_128_GCM_SHA256' } 
    ext_title = s_new_ticket_request_title( payload )
    test_struct( LURKTLS13Payload, payload, ctx_struct=ctx_struct,\
                 ext_title=ext_title, print_data_struct=False, print_binary=False) 

  elif status == 'success' :
    ctx_struct = { '_type' : 's_new_ticket', '_status' : 'success' } 
    ext_title = s_new_ticket_response_title( payload )
    test_struct( LURKTLS13Payload, payload, ctx_struct=ctx_struct, \
                 ext_title=ext_title, print_data_struct=False, print_binary=False) 

for req in s_new_ticket_request_list( ):
  ext_title = s_new_ticket_request_title( req )
  ctx_struct = { '_type' : 's_new_ticket', '_certificate_type' : 'X509', \
                 '_cipher' : 'TLS_AES_128_GCM_SHA256' }
  test_struct( SNewTicketRequest, req, ctx_struct=ctx_struct )
  s_new_ticket_print( req, 'request' )
  

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
    'secret_list' : [ {'secret_type': 'h_c', 'secret_data': b'hand_client_secret' }, 
                      {'secret_type': 'h_s', 'secret_data': b'hand_server_secret' },
                      {'secret_type': 'a_c', 'secret_data': b'app_client_secret' },
                      {'secret_type': 'a_s', 'secret_data': b'app_server_secret' } ],
    'ticket_list' : [ new_ticket, new_ticket ]}
  ctx_struct = { '_type' : 's_new_ticket' } 
  test_struct( SNewTicketResponse, s_new_ticket_resp,\
               ctx_struct=ctx_struct )
  s_new_ticket_print( s_new_ticket_resp, 'success' )


print( "#######" )
print(" #######" )
print( "### LURK Extension: Testing TLS server exchanges" )
print( "#######" )
print( "#######" )


## Testing s_init_cert_verify 

sig_algo_list = [\
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



def configure(sig_algo:str, role:str ='server') -> dict:
  """ return the configuration associated to sig_algo """
  conf_builder = ConfBuilder()
  conf_builder.generate_keys( sig_algo, key_format='X509' )
  conf = Conf( conf=conf_builder.export() )
  conf.conf[ 'role' ] = role
  if sig_algo not in conf.msg( 'keys' )[ 'sig_algo' ]:
    raise Exception( " conf :%s"%\
      conf.msg( 'keys' )[ 'sig_algo' ] + \
      " does not contain %s"%sig_algo) 
  return conf


def s_init_cert_verify_session():
  """tests init_cert_verify_session exchange """
  for sig_algo in sig_algo_list: 
    conf = configure( sig_algo ) 
    for req in init_cert_verify_request_list( sig_algo, conf=conf ):
      session = SSession( conf ) 
      init_cert_verify_print( req, 'request', role='server' )
      resp = session.serve( req, 's_init_cert_verify', 'request')
      init_cert_verify_print( resp, 'success', role='server' )
      
if LURK_SERVER_PAYLOAD_EXCHANGE == True:
  s_init_cert_verify_session()

def s_new_ticket_session():
  """ test ticket_session generation and exchange 

    tickets are built after the init_cert_verify exchange
  """
  ctx_req = { '_type' : 's_new_ticket', '_status' : 'request', \
              '_certificate_type' : 'X509', '_cipher' : 'TLS_AES_128_GCM_SHA256' } 
  ctx_resp = { '_type' : 's_new_ticket', '_status' : 'success' } 
  sig_algo = 'ed25519'
  conf = configure( sig_algo ) 
  for req in s_new_ticket_request_list():
    ## initializing the session with a init_cert_verify
    s_init_cert_verify_req = init_cert_verify_request_list( sig_algo, conf=conf )[0]
    s_init_cert_verify_req[ 'tag' ]['last_exchange' ] = False
    session = SSession( conf )
    s_init_cert_verify_req_resp = session.serve( s_init_cert_verify_req, 's_init_cert_verify', 'request')
    req[ 'session_id' ] = s_init_cert_verify_req_resp[ 'session_id' ]
    ext_title = s_new_ticket_request_title( req )
    ctx_req = { '_type' : 's_new_ticket', '_status' : 'request', \
                '_certificate_type' : 'X509', '_cipher' : 'TLS_AES_128_GCM_SHA256' } 
    test_struct( LURKTLS13Payload, req, ctx_struct=ctx_req, ext_title=ext_title ) 
    resp = session.serve( req, 's_new_ticket', 'request')
    test_struct( LURKTLS13Payload, req, ctx_struct=ctx_req, ext_title=ext_title ) 
      
    
if LURK_SERVER_PAYLOAD_EXCHANGE == True:
  s_new_ticket_session()

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
  init_cert_verify_print( s_init_cert_verify_req, 'request', role='server' )
  session = SSession( conf )
  s_init_cert_verify_resp = session.serve( s_init_cert_verify_req, 's_init_cert_verify', 'request')
  init_cert_verify_print( s_init_cert_verify_resp, 'success', role='server' )

  ## s_new_ticket_session
  s_new_ticket_session_req[ 'session_id' ] = s_init_cert_verify_resp[ 'session_id' ]
##  s_new_ticket_print( s_new_ticket_session_req, 'request' )

  s_new_ticket_session_resp = session.serve( s_new_ticket_session_req, 's_new_ticket', 'request')
  s_new_ticket_print( s_new_ticket_session_resp, 'success' )

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
  s_init_early_secret_print( s_init_early_secret_req, 'request' )
  s_init_early_secret_resp = session.serve( s_init_early_secret_req,\
                                            's_init_early_secret', 'request')
  s_init_early_secret_print( s_init_early_secret_resp, 'success' )

  ## s_hand_and_app_secret
  s_hand_and_app_secret_req[ 'session_id' ] = s_init_early_secret_resp[ 'session_id' ]
  s_hand_and_app_secret_print( s_hand_and_app_secret_req, 'request' )
  s_hand_and_app_secret_resp =  session.serve( s_hand_and_app_secret_req,\
                                               's_hand_and_app_secret', 'request')
  s_hand_and_app_secret_print( s_hand_and_app_secret_resp, 'success' )

##if LURK_SERVER_PAYLOAD_EXCHANGE == True:
## testing a single session resumption
## sig_algo = 'ed25519'
## conf = configure( sig_algo )
## s_init_cert_verify_req = init_cert_verify_request_list( sig_algo, conf=conf, last_exchange=False )[0]
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

if LURK_SERVER_PAYLOAD_SESSION_RESUMPTION_LOOP == True:
  for sig_algo in sig_algo_list:
    conf = configure( sig_algo=sig_algo, role='server' )
    for s_init_cert_verify_req in \
      init_cert_verify_request_list( sig_algo, conf=conf, last_exchange=False ):
      for s_new_ticket_session_req in  s_new_ticket_request_list():
        for s_init_early_secret_req in s_init_early_secret_request_list():
          for s_hand_and_app_secret_req in s_hand_and_app_secret_request_list():
            for s_new_ticket_session_req2 in s_new_ticket_request_list():
              session_resumption( conf, s_init_cert_verify_req, \
                                  s_new_ticket_session_req, \
                                  s_init_early_secret_req, \
                                  s_hand_and_app_secret_req, \
                                  s_new_ticket_session_req2   )



### Testing LURK messages including the header

print( "#######" )
print(" #######" )
print( "### LURK Server: Testing TLS server exchanges" )
print( "#######" )
print( "#######" )


def lurk_client_new_session_ticket( server, s_new_ticket_session_req ):
  """ LURK new_session_ticket exchange with server """

  lurk_s_new_ticket_session_req = \
  { 'header' : { 'designation' : 'tls13',
                 'version' : 'v1',
                 'type' : 's_new_ticket', 
                 'status' : 'request', 
                 'id' : token_bytes( 8 ) },
    'payload' : s_new_ticket_session_req }
  test_struct( LURKMessage, lurk_s_new_ticket_session_req )
  resp = server.serve( LURKMessage.build( lurk_s_new_ticket_session_req )) 
  lurk_s_new_ticket_session_resp = LURKMessage.parse( resp )
  test_struct ( LURKMessage, lurk_s_new_ticket_session_resp)
  try:
    return lurk_s_new_ticket_session_resp[ 'payload' ][ 'ticket_list' ]
  except KeyError:
    return None

def lurk_client_ecdhe( server, s_init_cert_verify_req:dict, 
                       s_new_ticket_session_req:dict=None ):

  ## s_init_cert_verify_req 
  s_init_cert_verify_req[ 'tag' ]['last_exchange' ] = False
  lurk_s_init_cert_verify_req = \
  { 'header' : { 'designation' : 'tls13',
                 'version' : 'v1',
                 'type' : 's_init_cert_verify', 
                 'status' : 'request', 
                 'id' : token_bytes( 8 ) },
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
  { 'header' : { 'designation' : 'tls13',
                 'version' : 'v1',
                 'type' : 's_init_early_secret', 
                 'status' : 'request', 
                 'id' : token_bytes( 8 ) },
    'payload' : s_init_early_secret_req }
  test_struct ( LURKMessage, lurk_s_init_early_secret_req )
  resp = server.serve( LURKMessage.build( lurk_s_init_early_secret_req ))
  lurk_s_init_early_secret_resp = LURKMessage.parse( resp )
  test_struct ( LURKMessage, lurk_s_init_early_secret_resp )

  session_id = lurk_s_init_early_secret_resp[ 'payload' ][ 'session_id' ]

  s_hand_and_app_secret_req[ 'session_id' ] = session_id
 
  lurk_s_hand_and_app_secret_req = \
  { 'header' : { 'designation' : 'tls13',
                 'version' : 'v1',
                 'type' : 's_hand_and_app_secret', 
                 'status' : 'request', 
                 'id' : token_bytes( 8 ) },
    'payload' : s_hand_and_app_secret_req }
  test_struct ( LURKMessage, lurk_s_hand_and_app_secret_req )
  resp = server.serve( LURKMessage.build( lurk_s_hand_and_app_secret_req ))
  lurk_s_hand_and_app_secret_resp = LURKMessage.parse( resp )
  test_struct ( LURKMessage, lurk_s_hand_and_app_secret_resp )

  if s_new_ticket_session_req != None:
    s_new_ticket_session_req[ 'session_id' ] = session_id
    return lurk_client_new_session_ticket( server, s_new_ticket_session_req )

if LURK_SERVER_SESSION_RESUMPTION == True:
  sig_algo = 'ed25519'
  conf = configure(sig_algo=sig_algo, role='server')
  server = LurkServer( conf=conf )
  s_init_cert_verify_req = init_cert_verify_request_list( sig_algo, conf=conf, last_exchange=False )[0]
  s_new_ticket_session_req = s_new_ticket_request_list( )[ 0 ] 
  s_init_early_secret_req = s_init_early_secret_request_list()[ 0 ]
  s_hand_and_app_secret_req = s_hand_and_app_secret_request_list( )[0]
  s_new_ticket_session_req2 = s_new_ticket_request_list( )[ 0 ] 
  
  ticket_list = lurk_client_ecdhe( server, s_init_cert_verify_req, s_new_ticket_session_req)
  identity = ticket_list[ 0 ][ 'ticket' ]
  lurk_client_session_resumption( server, identity, s_init_early_secret_req, s_hand_and_app_secret_req, s_new_ticket_session_req2 )

if LURK_SERVER_SESSION_RESUMPTION_LOOP == True:

  for sig_algo in sig_algo_list:
    conf = configure( sig_algo=sig_algo, role='server' )
    server = LurkServer( conf=conf )
    for s_init_cert_verify_req in \
      init_cert_verify_request_list( sig_algo, conf=conf, last_exchange=False ):
      for s_new_ticket_session_req in  s_new_ticket_request_list():
        for s_init_early_secret_req in s_init_early_secret_request_list():
          for s_hand_and_app_secret_req in s_hand_and_app_secret_request_list():
            for s_new_ticket_session_req2 in s_new_ticket_request_list():
              ticket_list = lurk_client_ecdhe( server, s_init_cert_verify_req, s_new_ticket_session_req)
              identity = ticket_list[ 0 ][ 'ticket' ]
              lurk_client_session_resumption( server, identity, s_init_early_secret_req, s_hand_and_app_secret_req, s_new_ticket_session_req2 )
              

print( "EOF" )


## Testing messages on the TLS Client

## CInitCertVerifyRequest
conf = configure('ed25519', role='client')
for req in c_init_cert_verify_request_list( conf=conf):
  ext_title = init_cert_verify_request_title( req )
  ctx_struct = { '_type' : 'c_init_cert_verify', '_certificate_type' : 'X509' }

## CInitCertVerifyResponse
for resp in init_cert_verify_response_list( role='server'):
##  ext_title = init_cert_verify_response_title( resp )
##  print("::: resp: %s"%resp )
##  ctx_struct = { '_type' : 's_init_cert_verify' } 
##  test_struct( SInitCertVerifyResponse, resp,\
##               ctx_struct=ctx_struct )
  init_cert_verify_print( resp, 'success', role='server' )






print( "#######" )
print(" #######" )
print( "### Testing TLS Client exchanges" )
print( "#######" )
print( "#######" )


def c_init_cert_verify_session():
  for sig_algo in sig_algo_list: 
    conf = configure( sig_algo ) 
    for req in s_init_cert_verify_request_list( sig_algo, conf=conf ):
      session = CSession( conf ) 
      init_cert_verify_print( req, 'request', role='client' )
      resp = session.serve( req, 'c_init_cert_verify', 'request')
      init_cert_verify_print( resp, 'success', role='client' )
      


