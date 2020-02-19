from construct.core import *
from construct.lib import *
from construct.debug import *

from pylurk.extensions.tls13_tls13_struct import PskIdentity, Certificate,\
  SignatureScheme, NewSessionTicket, HandshakeType, ClientHello,\
  ServerHello, EndOfEarlyData, EncryptedExtensions, CertificateRequest,\
  Certificate, CertificateVerify, Finished, KeyUpdate



TLS13Type = Enum( BytesInteger(1), 
  capabilities = 0, 
  ping = 1,
  s_init_early_secret = 2,
  s_init_cert_verify = 3,
  s_hand_and_app_secret = 4,
  s_new_ticket = 5,
  c_binder_key = 6, 
  c_init_early_secret = 7, 
  c_init_hand_secret = 8,
  c_hand_secret = 9,
  c_app_secret = 10,
  c_cert_verify = 11, 
  c_register_ticket = 12,
  c_post_hand = 13
)

TLS13Status = Enum( BytesInteger(1), 
  request = 0,
  success = 1, 
  undefined_error = 2,
  invalid_payload_format = 3, 
  invalid_psk = 4, 
  
)

## Common structures
KeyRequest = BitStruct(
  "b"   / Flag, 
  "e_s" / Flag,
  "e_x" / Flag,
  "h_c" / Flag,
  "h_s" / Flag,
  "a_c" / Flag,
  "a_s" / Flag,
  "x"   / Flag,
  "r"   / Flag,
  "reserved" / Const(0,BitsInteger(7))
)


SecretType = Enum ( BytesInteger(1),
  b = 0,
  e_s = 1,
  e_x = 2,
  h_c = 3,
  h_s = 4,
  a_c = 5, 
  a_s = 6,
  x = 7, 
  r = 8
)

Secret = Struct(
  '_name' / Computed(Const(b'Secret')),
  'secret_type' / SecretType, 
  'secret_data' / Prefixed(BytesInteger(1), GreedyBytes)
)



LURK13ExtensionType = Enum( BytesInteger(1),
  psk_id = 1, 
  ephemeral = 2, 
  freshness = 3,
  session_id = 4
)

## Extension Data

EphemeralMethod = Enum ( BytesInteger(1),
  secret_provided = 0,
  secret_generated = 1
)

EphemeralData = Struct(
  'ephemeral_method' / EphemeralMethod, 
  'secrets' / Prefixed(BytesInteger(2), GreedyRange(Secret))
)

FreshnessFunct = Enum( BytesInteger(1),
    sha256 = 0,
    null = 255,
)



LURK13Extension = Struct (
  '_name' / Computed(Const(b'LURK13Extension')),
  'extension_type' / LURK13ExtensionType, 
##  'extension_data' / Prefixed(1, GreedyBytes())
  'extension_data' / Prefixed(BytesInteger(1), Switch(this.extension_type,
    { 'psk_id' : PskIdentity, 
      'ephemeral': EphemeralData, 
      'freshness': FreshnessFunct,
      'session_id': Bytes(4) 
    }) 
  )
)

## Sub exchange structures

HandshakeContext = Switch( this._type, 
  { 's_init_early_secret' : Sequence(
      Struct( 'msg_type' / Const('client_hello', HandshakeType), 
              'data' / ClientHello )), 
    's_init_cert_verify' : Sequence(
      Struct( 'msg_type' / Const('client_hello', HandshakeType), 
              'data' / ClientHello ), 
      Struct( 'msg_type' / Const('server_hello', HandshakeType), 
              'data' / ServerHello ), 
      Struct( 'msg_type' / Const('encrypted_extensions', HandshakeType), 
              'data' / EncryptedExtensions ),
      Optional(Struct( 'msg_type' / Const('certificate_request', HandshakeType), 
              'data' / CertificateRequest))),
    's_new_ticket' : Sequence(
      Optional(Struct( 'msg_type' / Const('certificate', HandshakeType), 
              'data' / Certificate)),
      Optional(Struct( 'msg_type' / Const('certificate_verify', HandshakeType), 
              'data' / CertificateVerify)),
      Struct( 'msg_type' / Const('finished', HandshakeType), 
              'data' / Finished )),
    's_hand_and_app_secret' : Sequence(
      Struct( 'msg_type' / Const('server_hello', HandshakeType), 
              'data' / ServerHello ), 
      Struct( 'msg_type' / Const('encrypted_extensions', HandshakeType), 
              'data' / EncryptedExtensions ),
      Optional(Struct( 'msg_type' / Const('certificate_request', HandshakeType), 
              'data' / CertificateRequest))),
    'c_binder_key' : Sequence(), 
    'c_init_early_secret' : Sequence(
      Struct( 'msg_type' / Const('client_hello', HandshakeType), 
              'data' / ClientHello )), 
    'c_init_hand_secret' : Sequence(
      Struct( 'msg_type' / Const('client_hello', HandshakeType), 
              'data' / ClientHello ), 
      Struct( 'msg_type' / Const('server_hello', HandshakeType), 
              'data' / ServerHello )),
    'c_hand_secret' : Sequence(
      Struct( 'msg_type' / Const('server_hello', HandshakeType), 
              'data' / ServerHello )),
    'c_app_secret' : Sequence(
      Struct( 'msg_type' / Const('encrypted_extensions', HandshakeType), 
              'data' / EncryptedExtensions ),
      Optional(Struct( 'msg_type' / Const('certificate_request', HandshakeType), 
              'data' / CertificateRequest)),
      Optional(Struct( 'msg_type' / Const('certificate', HandshakeType), 
              'data' / Certificate)),
      Optional(Struct( 'msg_type' / Const('certificate_verify', HandshakeType), 
              'data' / CertificateVerify)),
      Struct( 'msg_type' / Const('finished', HandshakeType), 
              'data' / Finished )),
    'c_cert_verify' : Sequence( 
      Struct( 'msg_type' / Const('encrypted_extensions', HandshakeType), 
              'data' / EncryptedExtensions ),
      Optional(Struct( 'msg_type' / Const('certificate_request', HandshakeType), 
              'data' / CertificateRequest)),
      Optional(Struct( 'msg_type' / Const('certificate', HandshakeType), 
              'data' / Certificate)),
      Optional(Struct( 'msg_type' / Const('certificate_verify', HandshakeType), 
              'data' / CertificateVerify)),
      Struct( 'msg_type' / Const('finished', HandshakeType), 
              'data' / Finished ),
      Optional(Struct( 'msg_type' / Const('end_of_early_data', HandshakeType), 
              'data' / EndOfEarlyData))),
    'c_register_ticket' : Sequence( 
      Optional(Struct( 'msg_type' / Const('certificate', HandshakeType), 
              'data' / Certificate)),
      Optional(Struct( 'msg_type' / Const('certificate_verify', HandshakeType), 
              'data' / CertificateVerify)),
      Struct( 'msg_type' / Const('finished', HandshakeType), 
              'data' / Finished )),
  }, default=Error
)




SecretRequest = Struct(
  '_name' / Computed(Const(b'SecretRequest')),
  '_type' / Computed(this._._type),
  'key_request' / KeyRequest,
  'handshake_context' / Prefixed( BytesInteger(4), HandshakeContext ),
  'extension_list' / Prefixed( BytesInteger(2), GreedyRange(LURK13Extension )),  
)



SecretResponse = Struct(
  '_name' / Computed(Const(b'SecretResponse')),
  'secret_list' / Prefixed( BytesInteger(2), GreedyRange(Secret)),
  'extension_list' / Prefixed( BytesInteger(2), GreedyRange(LURK13Extension))  
)

LURK13CertificateType = Enum ( BytesInteger(1),
  X509 = 0,
  RawPublicKey = 1,
  sha256_32 = 128
)

## CertificateEntry is a TLS 1.3 structure but is redefined here as the
## certificate type  is not contained in the original structure. 
## _certificate_type is defined so that it can be interpreted by TLS 1.3
## sub construtors. 

LURK13Certificate = Struct(
  '_name' / Computed(Const(b'LURK13Certificate')),
  'certificate_type' /  LURK13CertificateType, 
  '_certificate_type' /  Computed(this.certificate_type), 
  'certificate_data' / Switch( this.certificate_type,
    { 'sha256_32' : Bytes(4), 
      'X509' : Certificate,
      'RawPublicKey' : Certificate
    }  
  ) 
)

KeyPairIDType = Enum( BytesInteger(1),
  sha256_32 = 0
)

KeyPairID = Struct(
  '_name' / Computed(Const(b'KeyPairID')),
  'key_id_type' / KeyPairIDType,
  'key_id' / Switch( this.key_id_type,
        { 'sha256_32' : Bytes(4)
        }
    )
)

SigningRequest = Struct(
  '_name' / Computed(Const(b'SigningRequest')),
  'key_id'/ KeyPairID, 
  'sig_algo' / SignatureScheme, 
  'certificate' / LURK13Certificate
)

SigningResponse = Struct(
  '_name' / Computed(Const(b'SigningResponse')),
  'signature' / Prefixed( BytesInteger(2), GreedyBytes)
)

SessionID = Struct(
  '_name' / Computed(Const(b'SessionID')),
  'session_id' / Bytes(4)
)

## LURK request / response structures on the TLS server

InitEarlySecretRequest = Struct(
  '_name' / Computed(Const(b'InitEarlySecretRequest')),
  '_type' / Computed(this._._type),
  'secret_request' / SecretRequest
)


InitEarlySecretResponse = Struct(
  '_name' / Computed(Const(b'InitEarlySecretResponse')),
  'secret_response' / SecretResponse
)


InitCertVerifyRequest = Struct(
  '_name' / Computed(Const(b'InitCertVerifyRequest')),
  '_type' / Computed(this._._type),
  'secret_request' / SecretRequest,
  'signing_request' / SigningRequest
)

InitCertVerifyResponse = Struct(
  '_name' / Computed(Const(b'InitCertVerifyResponse')),
  'secret_response' / SecretResponse,
  'signing_response' / SigningResponse
)


HandAndAppRequest = Struct(
  '_name' / Computed(Const(b'HandAndAppRequest')),
  '_type' / Computed(this._._type),
  'session_id' / Optional(If(this._._session_id_agreed == True, Bytes(4))), 
  'secret_request' / SecretRequest
)
  
HandAndAppResponse = Struct(
  '_name' / Computed(Const(b'HandAndAppResponse')),
  'session_id' / If(this._._session_id_agreed == True, Bytes(4)), 
  'secret_response' / SecretResponse
)


NewTicketRequest = Struct(
  '_name' / Computed(Const(b'NewTicketRequest')),
  'session_id' / Bytes(4), 
  'ticket_nbr' / BytesInteger(1), 
  'key_request' / KeyRequest,
  'handshake_context' / Prefixed( BytesInteger(4), GreedyBytes),
)

NewTicketResponse = Struct(
  '_name' / Computed(Const(b'NewTicketResponse')),
  'session_id' / Bytes(4),
  'ticket_list' / Prefixed(BytesInteger(2), GreedyRange(NewSessionTicket))
)


## LURK request / response structures on the TLS client

BinderKeyRequest = Struct(
  '_name' / Computed(Const(b'BinderKeyRequest')),
  '_type' / Computed(this._._type),
  'secret_request' / SecretRequest 
)

BinderKeyResponse = Struct(
  '_name' / Computed(Const(b'BinderKeyResponse')),
  'secret_response' / SecretResponse 
)

InitHandRequest = Struct(            #### to be checked in the draft
  '_name' / Computed(Const(b'InitHandRequest')),
  '_type' / Computed(this._._type),
  'secret_request' / SecretRequest 
)

InitHandResponse = Struct(
  '_name' / Computed(Const(b'InitHandResponse')),
  'secret_response' / SecretResponse 
)

CertVerifyRequest = Struct(
  '_name' / Computed(Const(b'CertVerifyRequest')),
  '_type' / Computed(this._._type),
  'session_id' / Bytes(4), 
  'secret_request' / SecretRequest,
  'signing_request' / SigningRequest
)

CertVerifyResponse =Struct(
  '_name' / Computed(Const(b'CertVerifyResponse')),
  'session_id' / Bytes(4), 
  'secret_response' / SecretResponse,
  'signing_response' / SigningResponse
)

RegisterTicketRequest = Struct(
  '_name' / Computed(Const(b'RegisterTicketRequest')),
  'session_id' / Bytes(4), 
  'handshake_context' / Prefixed( BytesInteger(4), GreedyBytes),
  'ticket_list' / Prefixed(BytesInteger(2), GreedyRange(NewSessionTicket)),
  'key_request' / KeyRequest,
)

RegisterTicketResponse = Struct(
  '_name' / Computed(Const(b'RegisterTicketResponse')),
  'session_id' / Bytes(4), 
)

PostHandRequest = Struct(
  '_name' / Computed(Const(b'PostHandRequest')),
  'session_id' / Bytes(4), 
  'handshake_context' / Prefixed( BytesInteger(4), GreedyBytes),
  'app_n' / BytesInteger(2), 
)

PostHandResponse = Struct(
  '_name' / Computed(Const(b'PostHandResponse')),
  'session_id' / Bytes(4), 
)


ErrorResponse = Struct()


LURKTLS13Payload = Switch(this._type, 
  { 's_init_early_secret' : Switch( this._status,
       { 'request' : InitEarlySecretRequest, 
         'success' : InitEarlySecretResponse, 
        }, default=ErrorResponse), 
    's_init_cert_verify' : Switch( this._status,
       { 'request' : InitCertVerifyRequest, 
         'success' : InitCertVerifyResponse, 
        }, default=ErrorResponse), 
    's_hand_and_app_secret' : Switch( this._status,
       { 'request' : HandAndAppRequest, 
         'success' : HandAndAppResponse, 
        }, default=ErrorResponse), 
    's_new_ticket' : Switch( this._status,
       { 'request' : NewTicketRequest, 
         'success' : NewTicketResponse, 
        }, default=ErrorResponse), 
    'c_binder_key' : Switch( this._status,
       { 'request' : BinderKeyRequest, 
         'success' : BinderKeyResponse, 
        }, default=ErrorResponse), 
    'c_init_early_secret' : Switch( this._status,
       { 'request' : InitEarlySecretRequest, 
         'success' : InitEarlySecretResponse, 
        }, default=ErrorResponse), 
    'c_init_hand_secret' : Switch( this._status,
       { 'request' : InitHandRequest, 
         'success' : InitHandResponse, 
        }, default=ErrorResponse), 
    'c_hand_secret' : Switch( this._status,
       { 'request' : HandAndAppRequest, 
         'success' : HandAndAppResponse, 
        }, default=ErrorResponse), 
    'c_app_secret' : Switch( this._status,
       { 'request' : HandAndAppRequest, 
         'success' : HandAndAppResponse, 
        }, default=ErrorResponse), 
    'c_cert_verify' : Switch( this._status,
       { 'request' : CertVerifyRequest, 
         'success' : CertVerifyResponse, 
        }, default=ErrorResponse), 
    'c_register_ticket' : Switch( this._status,
       { 'request' : RegisterTicketRequest, 
         'success' : RegisterTicketResponse, 
        }, default=ErrorResponse), 
    'c_post_hand' : Switch( this._status,
       { 'request' : PostHandRequest, 
         'success' : PostHandResponse, 
        }, default=ErrorResponse), 
  }, default=Error
)



