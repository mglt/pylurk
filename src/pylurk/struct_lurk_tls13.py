from construct.core import *
from construct.lib import *
from construct.debug import *

from struct_tls13 import PskIdentity, Certificate, CompressedCertificate, \
  SignatureScheme, KeyShareEntry, NamedGroup, ExtensionType,\
  HandshakeType, Extension, \
  NewSessionTicket, ClientHello, ServerHello, EndOfEarlyData,\
  EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify,\
  Finished, KeyUpdate,\
  HSClientHello, HSPartialClientHello, HSServerHello, HSEndOfEarlyData, HSEncryptedExtensions,\
  HSCertificateRequest, HSCertificate, HSCertificateVerify, HSFinished, \
  TLSCiphertext, Handshake

## TODO
##  * structure for secret list secret_request depending on _type
##  * handshakeList is does not handle properly the combination of multiple optional messages. 

TLS13Version = Enum( BytesInteger(1), 
  v1 = 1
)

TLS13Type = Enum( BytesInteger(1), 
  capabilities = 0, 
  ping = 1,
  s_init_cert_verify = 2,
  s_new_ticket = 3,
  s_init_early_secret = 4,
  s_hand_and_app_secret = 5,
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
  invalid_format = 3,
  invalid_secret_request = 4, 
  invalid_session_id = 5,
  invalid_handshake = 6, 
  invalid_freshness = 7, 
  invalid_ephemeral = 8, 
  invalid_psk = 9, 
  invalid_certificate = 10,
  invalid_cert_type = 10,
  invalid_type = 11,
)

## Common structures
SecretRequest = BitStruct(
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
  '_name' / Computed('Secret'),
  'secret_type' / SecretType, 
  'secret_data' / Prefixed( BytesInteger(1), GreedyBytes )
)

HandshakeList = Switch( this._type, 
  { 's_init_early_secret' : Sequence( HSClientHello ),
    's_init_cert_verify' : Select( \
      Sequence( HSClientHello, HSServerHello, HSEncryptedExtensions, HSCertificateRequest ),
      Sequence( HSClientHello, HSServerHello, HSEncryptedExtensions )),  
    's_new_ticket' : Select( \
      Sequence( HSCertificate, HSCertificateVerify, HSFinished ),
      Sequence( HSFinished ) ),
    's_hand_and_app_secret' : Select(\
      Sequence( HSServerHello, HSEncryptedExtensions, HSCertificateRequest ),
      Sequence( HSServerHello, HSEncryptedExtensions ) ),  
    'c_init_cert_verify' : Sequence(HSClientHello, HSServerHello, HSEncryptedExtensions, HSCertificateRequest, HSCertificate, HSCertificateVerify, Finished), 
    'c_init_post_hand_auth' : Select(
      ## we are missing ClientHelloRetry
      ## server cert = yes / no
      ## client cert = no
      ## early data = yes / no
      ## ( server cert, early_data ) = (yes, yes) 
      Sequence(
      HSClientHello, HSServerHello, HSEncryptedExtensions, HSCertificateRequest, HSCertificate, HSCertificateVerify, HSFinished, HSEndOfEarlyData, HSFinished, HSCertificateRequest),  
      ## ( server cert, early_data ) = (yes, no) 
      Sequence(
      HSClientHello, HSServerHello, HSEncryptedExtensions, HSCertificateRequest, HSCertificate, HSCertificateVerify, HSFinished, HSFinished, HSCertificateRequest), 
      ## ( server cert, early_data ) = (no, yes) 
      Sequence(
      HSClientHello, HSServerHello, HSEncryptedExtensions, HSFinished, HSEndOfEarlyData, HSFinished, HSCertificateRequest),  
      ## ( server cert, early_data ) = (no, no) 
      Sequence(
      HSClientHello, HSServerHello, HSEncryptedExtensions, HSFinished, HSFinished, HSCertificateRequest) 
    ),  
    'c_post_hand_auth' : Sequence( HSCertificateRequest ), 
    'c_init_ephemeral' : Sequence( HSPartialClientHello ),
    'c_init_early_secret' : Sequence( HSPartialClientHello ),
    'c_hand_and_app_secret' : Select( \
      Sequence( ServerHello, TLSCiphertext, EndOfEarlyData ),
      Sequence( ServerHello, TLSCiphertext ) ),
      ## TLSCiphertext {EncryptedExtensions}, {CertificateRequest*},  
      ##               {Certificate*},  {CertificateVerify*}  {Finished}
  }, default=Error
)

Freshness = Enum( BytesInteger(1),
    sha256 = 0,
    sha384 = 1,
    sha512 = 2,
    null = 255,
)


EphemeralMethod = Enum ( BytesInteger(1),
  no_secret = 0,
  e_generated = 1,
  cs_generated = 2
)

SharedSecret = Struct(
  '_name' / Computed('SharedSecret'),
  'group' / NamedGroup, 
  'shared_secret' / Switch(this.group, 
  { 'secp256r1' : Bytes(32),
    'secp384r1' : Bytes(48),
    'secp521r1' : Bytes(66),
    'x25519' : Bytes(32),
    'x448' : Bytes(56)
  }, Error)
)

Ephemeral = Struct(
  '_name' / Computed('Ephemeral'),
  '_status' / Computed( this._._status ),
  'ephemeral_method' / EphemeralMethod, 
   'key' / Switch(this.ephemeral_method,
    { 'e_generated' : Switch(this._status, {
         'request' : Prefixed(BytesInteger(2), SharedSecret),
         'success' : Const(b'')
        }, Error),
      'cs_generated' : Switch(this._status, {
         'request' : Const( b'' ), 
         'success' : Prefixed(BytesInteger(2), KeyShareEntry),
        }, Error),
      'no_secret' : Switch(this._status, {
         'request' : Const( b'' ), 
         'success' : Const( b'' ),
    }, Error)
  } )
)


#LURKTLS13CertificateType = Enum ( BytesInteger(1),
#  no_certificate = 0,
#  finger_print = 1,
#  uncompressed = 128
#)

#LURKTLS13Certificate = Struct(
#  '_name' / Computed('LURKTLS13Certificate'),
#  'certificate_type' /  LURKTLS13CertificateType, 
# '_certificate_type' / If( this.certificate_type == 'uncompressed', Computed(this._._certificate_type)),
#  'certificate_data' / Switch( this.certificate_type,
#    { 'no_certificate' : Const(b''), 
#      'finger_print' : Bytes(4),
#      'uncompressed' : Certificate
#    }  
#  ) 
#)

CertType = Enum ( BytesInteger(2),
  zlib = 1, 
  brotli = 2, 
  zstd = 3,
  no_certificate = 128,
  finger_print = 129,
  uncompressed = 130
)

FingerPrintCertificateEntry = Struct(
  '_name' / Computed('FingerPrintCertificateEntry'),
  'finger_print' / Bytes( 4 ),
  'extensions' / Prefixed( BytesInteger(2), GreedyRange( Extension ) )
)

FingerPrintCertificate = Struct(
  '_name' / Computed('FingerPrintCertificate'),
  'certificate_request_context' / Prefixed( BytesInteger(1), GreedyBytes),
  'certificate_list' / Prefixed(BytesInteger(3), GreedyRange(FingerPrintCertificateEntry))
)

Cert = Struct(
  '_name' / Computed('Cert'),
  'cert_type' /  CertType,
  Probe( this.cert_type ),
  'certificate' / Switch( this.cert_type, {
    'zlib' : CompressedCertificate, 
    'brotli' : CompressedCertificate,
    'zstd' : CompressedCertificate,
    'no_certificate' : Const( b'' ), 
    'finger_print' : FingerPrintCertificate,
    'uncompressed' : Certificate
    }
  )
)

Tag = BitStruct(
  "last_exchange"   / Flag, 
  "reserved" / Const(0,BitsInteger(7))
)


SInitEarlySecretRequest = Struct(
  '_name' / Computed('SInitEarlySecretRequest'),
  '_type' / Computed(this._._type),
  'session_id' / Bytes( 4 ),
  'freshness' / Freshness, 
  'selected_identity' / BytesInteger( 2 ), 
  'handshake' / Prefixed( BytesInteger(4), HandshakeList ),
  'secret_request' / SecretRequest,
)


SInitEarlySecretResponse = Struct(
  '_name' / Computed('SInitEarlySecretResponse'),
  '_type' / Computed(this._._type),
  'session_id' / Bytes( 4 ),
  'secret_list' / Prefixed( BytesInteger(2), GreedyRange( Secret ) )
)


SInitCertVerifyRequest = Struct(
  '_name' / Computed('SInitCertVerifyRequest'),
  '_type' / Computed(this._._type),
  '_status' / Computed('request'),
#  '_certificate_type' / Computed(this._._certificate_type),
  'tag' / Tag,
#  Probe(this.tag),
#  Probe(this._type),
#  Probe(this._status),
  'session_id' / Switch( this.tag.last_exchange,
    { True : Const( b'' ), 
      False : Bytes( 4 ),
    }  
  ),
#  Probe(this.session_id),
  'freshness' / Freshness,
#  Probe(this.freshness),
  'ephemeral' / Ephemeral, 
#  Probe(this.ephemeral),
  'handshake' / Prefixed( BytesInteger(4), HandshakeList ), 
#  'handshake' / Prefixed( BytesInteger(4), GreedyRange( Handshake ) ), 
#  'handshake' / Prefixed( BytesInteger(4), Sequence(
#      HSClientHello, HSServerHello, HSEncryptedExtensions) ), 
#  Probe(this.handshake),
#  'certificate' / LURKTLS13Certificate, 
  'certificate' / Cert, 
#  Probe(this.certificate),
  'secret_request' / SecretRequest,
  'sig_algo' / SignatureScheme,
#  Probe(this.sig_algo),
)

SInitCertVerifyResponse = Struct(
  '_name' / Computed('SInitCertVerifyResponse'),
  '_type' / Computed(this._._type),
  '_status' / Computed('success'),
  'tag' / Tag,
  'session_id' / Switch( this.tag.last_exchange,
    { True : Const(b''), 
      False : Bytes(4),
    }  
  ),
  'ephemeral' / Ephemeral, 
  'secret_list' / Prefixed( BytesInteger(2), GreedyRange( Secret ) ),
  'signature' / Prefixed( BytesInteger(2), GreedyBytes )
)


SHandAndAppRequest = Struct(
  '_name' / Computed('SHandAndAppRequest'),
  '_type' / Computed(this._._type),
  '_status' / Computed('request'),
  'tag' / Tag,
##  'session_id' / Optional(If(this._._session_id_agreed == True, Bytes(4))), 
  'session_id' / Bytes( 4 ), 
  'ephemeral' / Ephemeral, 
  'handshake' / Prefixed( BytesInteger(4), HandshakeList ), 
  'secret_request' / SecretRequest
)
  
SHandAndAppResponse = Struct(
  '_name' / Computed('SHandAndAppResponse'),
  '_status' / Computed('success'),
  'tag' / Tag,
  'session_id' / Bytes(4) , 
  'ephemeral' / Ephemeral, 
  'secret_list' / Prefixed( BytesInteger(2), GreedyRange( Secret ) )
)


SNewTicketRequest = Struct(
  '_name' / Computed('SNewTicketRequest'),
  '_type' / Computed(this._._type),
#  '_certificate_type' / Computed(this._._certificate_type),
#  '_cipher' / Computed(this._._cipher),
  'tag' / Tag,
  'session_id' / Bytes(4), 
  'handshake' / Prefixed( BytesInteger(4), HandshakeList),
#  'certificate' / LURKTLS13Certificate, 
  'certificate' / Cert, 
  'ticket_nbr' / BytesInteger(1), 
  'secret_request' / SecretRequest,
)

SNewTicketResponse = Struct(
  '_name' / Computed('SNewTicketResponse'),
  'tag' / Tag,
  'session_id' / Bytes(4),
  'secret_list' / Prefixed( BytesInteger(2), GreedyRange( Secret ) ),
  'ticket_list' / Prefixed( BytesInteger( 2 ), GreedyRange( NewSessionTicket ) )
)


## LURK request / response structures on the TLS client


CInitCertVerifyRequest = SInitCertVerifyRequest 
CInitCertVerifyResponse = SInitCertVerifyResponse


CInitPostHandAuthRequest = Struct(
  '_name' / Computed('PostHandRequest'),
  'tag' / Tag,
  'session_id' / Switch( this.tag.last_exchange,
    { True : Const(b''), 
      False : Bytes(4),
    }  
  ),
  'freshness' / Freshness,
  'handshake' / Prefixed( BytesInteger(4), HandshakeList ),
#  'certificate' / LURKTLS13Certificate,
  'certificate' / Cert,
  'sig_algo' / SignatureScheme,
)

CInitPostHandAuthResponse = Struct(
  '_name' / Computed('PostHandResponse'),
  'tag' / Tag,
  'session_id' / Switch( this.tag.last_exchange,
    { True : Const(b''), 
      False : Bytes(4),
    }  
  ),
  'signature' / Prefixed( BytesInteger(2), GreedyBytes )
)


CPostHandAuthRequest = Struct(
  '_name' / Computed('PostHandRequest'),
  'tag' / Tag,
  'session_id' / Bytes(4), 
  'handshake' / Prefixed( BytesInteger(4), HandshakeList ),
#  'certificate' / LURKTLS13Certificate,
  'certificate' / Cert,
  'sig_algo' / SignatureScheme,
)

CPostHandAuthResponse = Struct(
  '_name' / Computed('PostHandResponse'),
  'tag' / Tag,
  'session_id' / Bytes(4), 
  'signature' / Prefixed( BytesInteger(2), GreedyBytes )
)


CInitEphemeralBinderRequest = Struct(
  '_name' / Computed('CInitEphemeralBinderRequest'),
  'session_id' / Bytes( 4 ), 
  'ephemeral' / Ephemeral, ## secret_request or nothing - if only binder_key is requested 
  'handshake' / Prefixed( BytesInteger(4), HandshakeList), # ClientHelllo or partialClientHello or HelloRetry || CLientHEllo, or HelloRetry || partialClientHello.
  'secret_list' / Prefixed( BytesInteger(2), GreedyRange( Secret ) ) ## psk
)


CInitEphemeralBinderResponse = Struct(
  '_name' / Computed('CInitEphemeralBinderResponse'),
  '_status' / Computed('success'),

  'secret_list' / Prefixed( BytesInteger(2), GreedyRange( Secret ) )
) 


BinderKeyRequest = Struct(
  '_name' / Computed('BinderKeyRequest'),
  'ticket_id_list' / Prefixed(BytesInteger(2), Bytes( 4 )),
)

BinderKeyResponse = Struct(
  '_name' / Computed('BinderKeyResponse'),
  'secret_list' / Prefixed( BytesInteger(2), GreedyRange( Secret ) )
)

InitHandRequest = Struct(            #### to be checked in the draft
  '_name' / Computed('InitHandRequest'),
  '_type' / Computed(this._._type),
  'secret_request' / SecretRequest 
)

InitHandResponse = Struct(
  '_name' / Computed('InitHandResponse'),
  'secret_list' / Prefixed( BytesInteger(2), GreedyRange( Secret ) )
)

CertVerifyRequest = Struct(
  '_name' / Computed('CertVerifyRequest'),
  '_type' / Computed(this._._type),
  'session_id' / Bytes(4), 
  'secret_request' / SecretRequest,
  'sig_algo' / SignatureScheme
)

CertVerifyResponse =Struct(
  '_name' / Computed('CertVerifyResponse'),
  'session_id' / Bytes(4), 
  'secret_list' / Prefixed( BytesInteger(2), GreedyRange( Secret ) ),
  'signature' / Prefixed( BytesInteger(2), GreedyBytes )
)

RegisterTicketRequest = Struct(
  '_name' / Computed('RegisterTicketRequest'),
  'session_id' / Bytes(4), 
  'handshake' / Prefixed( BytesInteger(4), HandshakeList),
  'ticket_list' / Prefixed(BytesInteger(2), GreedyRange(NewSessionTicket)),
  'secret_request' / SecretRequest,
)

RegisterTicketResponse = Struct(
  '_name' / Computed('RegisterTicketResponse'),
  'session_id' / Bytes(4), 
  'ticket_id_list' / Prefixed(BytesInteger(2), Bytes( 4 )),
  'secret_list' / Prefixed( BytesInteger(2), GreedyRange( Secret ) )
)

############  LURKErrorPayload

ErrorPayload = Struct (
  'lurk_state' / Bytes(4), \
)


TLS13Payload = Switch(this._type, 
  { 's_init_early_secret' : Switch( this._status,
       { 'request' : SInitEarlySecretRequest, 
         'success' : SInitEarlySecretResponse, 
        }, default=ErrorPayload), 
    's_init_cert_verify' : Switch( this._status,
       { 'request' : SInitCertVerifyRequest, 
         'success' : SInitCertVerifyResponse, 
        }, default=ErrorPayload), 
    's_hand_and_app_secret' : Switch( this._status,
       { 'request' : SHandAndAppRequest, 
         'success' : SHandAndAppResponse, 
        }, default=ErrorPayload), 
    's_new_ticket' : Switch( this._status,
       { 'request' : SNewTicketRequest, 
         'success' : SNewTicketResponse, 
        }, default=ErrorPayload), 
    'c_binder_key' : Switch( this._status,
       { 'request' : BinderKeyRequest, 
         'success' : BinderKeyResponse, 
        }, default=ErrorPayload), 
    'c_init_early_secret' : Switch( this._status,
       { 'request' : SInitEarlySecretRequest, 
         'success' : SInitEarlySecretResponse, 
        }, default=ErrorPayload), 
    'c_init_hand_secret' : Switch( this._status,
       { 'request' : InitHandRequest, 
         'success' : InitHandResponse, 
        }, default=ErrorPayload), 
    'c_hand_secret' : Switch( this._status,
       { 'request' : SHandAndAppRequest, 
         'success' : SHandAndAppResponse, 
        }, default=ErrorPayload), 
    'c_app_secret' : Switch( this._status,
       { 'request' : SHandAndAppRequest, 
         'success' : SHandAndAppResponse, 
        }, default=ErrorPayload), 
    'c_cert_verify' : Switch( this._status,
       { 'request' : CertVerifyRequest, 
         'success' : CertVerifyResponse, 
        }, default=ErrorPayload), 
    'c_register_ticket' : Switch( this._status,
       { 'request' : RegisterTicketRequest, 
         'success' : RegisterTicketResponse, 
        }, default=ErrorPayload), 
#    'c_post_hand' : Switch( this._status,
#       { 'request' : PostHandRequest, 
#         'success' : PostHandResponse, 
#        }, default=ErrorPayload), 
  }, default=ErrorPayload
)



