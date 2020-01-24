from  pylurk.extensions.tls13_lurk_struct import *
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


def test_struct( struct, data_struct, ext_title='', \
                 no_title=False, io_check=True ):
  """ checks the Extension """
 
  if not no_title: 
    title("Testing %s [%s]  structure"%(struct.__class__.__name__, ext_title))
  binary = struct.build(data_struct)
  data = struct.parse(binary)
  print("struct: %s"%data_struct)
  print("bytes: %s"%binary)
  print("struct: %s"%struct.parse(binary))
  if io_check:
    assert ( data_struct == data )
  return binary, data

## KeyRequest
data_struct = {"b":True, "e_s":False, "e_x":True, "h_c":False,\
               "h_s":True, "a_c":False, "a_s":True, "x":False, \
               "r":True}
binary, struct = test_struct(KeyRequest, data_struct, io_check=False)
assert(len(binary) == 2)
data_struct['reserved'] = 0
assert(data_struct == struct) 

title("Testing Secret structure")

## Secret
secret_data = b'secret'
for secret_type in ['b', 'e_s', 'e_x', 'h_c', 'h_s', 'a_c', 'a_s', 'x', 'r']:
  data_struct = {'secret_type': secret_type, 'secret_data': secret_data}
  test_struct(Secret, data_struct, ext_title=secret_type)

## Extensions
psk = { 'extension_type': 'psk_id', \
        'extension_data': { 'identity': b'key_identity',\
                            'obfuscated_ticket_age': b'\x00\x01\x02\x03'} }
secret = {'secret_type': 'x', 'secret_data': b'secret'}
eph = { 'extension_type': 'ephemeral',\
        'extension_data': { 'ephemeral_method': 'secret_provided',\
                            'secrets': [secret, secret] } }
frsh = { 'extension_type': 'freshness', 'extension_data': 'sha256'}
sess = { 'extension_type': 'session_id',\
         'extension_data': b'\x00\x01\x02\x03' }
all_ext = [ psk, eph, frsh, sess ]

for ext in all_ext:
  test_struct(LURK13Extension, ext, ext['extension_type'])


## SecretRequest
key_req = {"b":True, "e_s":False, "e_x":True, "h_c":False,\
            "h_s":True, "a_c":False, "a_s":True, "x":False, \
            "r":True}
handshake_ctx =b'\x00\x01\x02'
sec_req = {'key_request': key_req, \
           'handshake_contex': handshake_ctx, \
           'extension_list': all_ext }
binary, struct = test_struct(SecretRequest, sec_req, io_check=False)
sec_req['key_request']['reserved']=0
assert( struct == sec_req)

## SecretResponse
a_c = {'secret_type': 'a_c', 'secret_data': b'secret_ac'}
a_s = {'secret_type': 'a_s', 'secret_data': b'secret_as'}
sec_resp = {'secret_list' : [a_c, a_s], 'extension_list': all_ext}
test_struct(SecretResponse, sec_resp)

## SignatureRequest
key = { 'key_id_type' : 'sha256_32', 'key_id' : b'\x00\x01\x02\x03' }
cert_32 = { 'certificate_type' : 'sha256_32',\
            'certificate_data' : b'\x00\x01\x02\x03' } 
x509 = {'certificate_request_context' : b'\x00\x01', \
        'certificate_list' : []}
## clarifying certi_req_context as well as certificate_type
cert_tls = { 'certificate_type' : 'tls13', \
             'certificate_data' : x509}
sig_req = {'key_id': key, \
           'sig_algo' : 'rsa_pkcs1_sha256' ,\
           'certificate' : cert_32 }
test_struct(SignatureRequest, sig_req)

## SignatureResponse
sig_resp = { 'signature' :  b'\x00\x01\x02\x03' }
test_struct(SignatureResponse, sig_resp)


