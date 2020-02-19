from construct.core import *
from construct.lib import *
from construct.debug import *

""" TLS 1.3 related strcutres """

## Extensions

## supported version
#SupportedVersions = Struct(
#          select (Handshake.msg_type) {
#              case client_hello:
#                   ProtocolVersion versions<2..254>;
#
#              case server_hello: /* and HelloRetryRequest */
#                   ProtocolVersion selected_version;
#          };
#)

## 


## signature_algorithm 
SignatureScheme = Enum( Bytes(2), 
  rsa_pkcs1_sha256 = b'\x04\x01',
  rsa_pkcs1_sha384 = b'\x05\x01',
  rsa_pkcs1_sha512 = b'\x06\x01',
  ecdsa_secp256r1_sha256 = b'\x04\x03',
  ecdsa_secp384r1_sha384 = b'\x05\x03',
  ecdsa_secp521r1_sha512 = b'\x06\x03',
  rsa_pss_rsae_sha256 = b'\x08\x04',
  rsa_pss_rsae_sha384 = b'\x08\x05',
  rsa_pss_rsae_sha512 = b'\x08\x06',
  ed25519 = b'\x08\x07',
  ed448 = b'\x08\x08',
  rsa_pss_pss_sha256 = b'\x08\x09',
  rsa_pss_pss_sha384 = b'\x08\x0a',
  rsa_pss_pss_sha512 = b'\x08\x0b',
  rsa_pkcs1_sha1 = b'\x02\x01',
  ecdsa_sha1 = b'\x02\x03',
)

SignatureSchemeList = Struct(
  'supported_signature_algorithms' / Prefixed(BytesInteger(2),\
                                       GreedyRange(SignatureScheme))
)

## psk_key_exchange_modes

PskKeyExchangeMode = Enum(BytesInteger(1), 
  psk_ke = 0,
  psk_dhe_ke = 1,
)

PskKeyExchangeModes = Struct(
  'ke_modes' / Prefixed(BytesInteger(1), GreedyRange(PskKeyExchangeMode))
)

## post_handshake_auth

PostHandshakeAuth = Struct()

## supported_group 

NamedGroup = Enum( Bytes(2),
##  unallocated_RESERVED(0x0000),
##  /* Elliptic Curve Groups (ECDHE) */
##  obsolete_RESERVED(0x0001..0x0016),
  secp256r1 = b'\x00\x17', 
  secp384r1 = b'\x00\x18', 
  secp521r1 = b'\x00\x19',
##  obsolete_RESERVED(0x001A..0x001C',
  x25519 = b'\x00\x1D', 
  x448 = b'\x00\x1E',
##  /* Finite Field Groups (DHE) */
  ffdhe2048 = b'\x01\x00', 
  ffdhe3072 = b'\x01\x01', 
  ffdhe4096 = b'\x01\x02',
  ffdhe6144 = b'\x01\x03', 
  ffdhe8192 = b'\x01\x04',
##  /* Reserved Code Points */
##  ffdhe_private_use(0x01FC..0x01FF),
##  ecdhe_private_use(0xFE00..0xFEFF),
##  obsolete_RESERVED(0xFF01..0xFF02), (0xFFFF)
)

NamedGroupList = Struct(
  'named_group_list' / Prefixed(BytesInteger(2), GreedyRange(NamedGroup))
)


## Key Share
KeyShareEntry = Struct(
  'group' / NamedGroup, 
  'key_exchange' / Prefixed(BytesInteger(2), GreedyBytes)
)

KeyShareClientHello = Struct(
   'client_shares' / Prefixed(BytesInteger(2), GreedyRange(KeyShareEntry)) 
)

KeyShareHelloRetryRequest = Struct(
  'selected_group' / NamedGroup
)

KeyShareServerHello = Struct(
  'server_share' / KeyShareEntry
)

## pre_shared_key
PskIdentity = Struct(
  'identity' / Prefixed( BytesInteger(2), GreedyBytes),
  'obfuscated_ticket_age' / Bytes(4)
)

PskBinderEntry = Struct(
  'binder' / Prefixed(BytesInteger(1), GreedyBytes)
)

OfferedPsks = Struct(
  'identities' / Prefixed(BytesInteger(2), GreedyRange(PskIdentity)), 
  'binders' / Prefixed(BytesInteger(2), GreedyRange(PskBinderEntry))
)


## Extension structure

ExtensionType = Enum( BytesInteger(2), 
  server_name = 0,                              
  max_fragment_length = 1,                      
  status_request = 5,                           
  supported_groups = 10,                        
  signature_algorithms = 13,                    
  use_srtp = 14,                                
  heartbeat = 15,                               
  application_layer_protocol_negotiation = 16,  
  signed_certificate_timestamp = 18,            
  client_certificate_type = 19,                 
  server_certificate_type = 20,                 
  padding = 21,                                 
  pre_shared_key = 41,                          
  early_data = 42,                              
  supported_versions = 43,                      
  cookie = 44,                                  
  psk_key_exchange_modes = 45,                  
  certificate_authorities = 47,                 
  oid_filters = 48,                             
  post_handshake_auth = 49,                     
  signature_algorithms_cert = 50,               
  key_share = 51,                               
)

## To do list all possible extensions with a Switch
## The default is set to Bytes, This is expected to be usefull for
## parsing but cannot be used for building when a structure is provided.
## Instead the rwa data may be provided - to be tested. 

Extension = Struct(
  'extension_type' / ExtensionType,
  ## checking the different levels for msg_type
  ## Probe(this._._._._.msg_type), 
  ## Probe(this._._._.msg_type), 
  ## Probe(this._._.msg_type), 
  ## Probe(this._.msg_type), 
  'extension_data' /  Prefixed(BytesInteger(2),
                      Switch(this.extension_type,
    {
      'supported_groups' : NamedGroupList,
      'signature_algorithms' : SignatureSchemeList, 
      'pre_shared_key' : PskIdentity, 
      'post_handshake_auth' : PostHandshakeAuth,
      'psk_key_exchange_modes' : PskKeyExchangeModes, 
       ## To build manually the extension with msg_type included during
       ## the call of Extension 
       ## 'key_share': Switch(this._.msg_type,
       ## Interestingly, we may also define the msg_type at several ctx
       ## above by iteratively write
       ##   "msg_type" / Computed(this._.msg_type),
       ## ClientHello (woudl get it from constructor of Handshake) 
      'key_share': Switch(this._._.msg_type, 
         {
          'client_hello' : Select(KeyShareClientHello, 
                           KeyShareHelloRetryRequest),
          'server_hello' : KeyShareServerHello
         }
        )
    }, default=Bytes)
  ) 
)

## For testing purposes enable to build the key_share Extension
## providing the necessary msg_type parameter. The only difference with
## Extension is the level where msg_type information is read.
KeyShareExt = Struct( 
  'extension_type' / ExtensionType,
  'extension_data' /  Prefixed(BytesInteger(2),
                      Switch(this.extension_type, 
    {
      'key_share': Switch(this._.msg_type, 
         {
          'client_hello' : Select(KeyShareClientHello, 
                           KeyShareHelloRetryRequest),
          'server_hello' : KeyShareServerHello
         }
        )
    }, default=Bytes)
  )
)


## ClientHello

CipherSuite = Enum( Bytes(2),
   TLS_AES_128_GCM_SHA256 = b'\x13\x01',
   TLS_AES_256_GCM_SHA384 = b'\x13\x02',
   TLS_CHACHA20_POLY1305_SHA256 = b'\x13\x03',
   TLS_AES_128_CCM_SHA256 = b'\x13\x04',
   TLS_AES_128_CCM_8_SHA256 = b'\x13\x05'
)

ClientHello = Struct( 
  'legacy_version' / Const(b'\x03\x03'),
  'random' / Bytes(32), 
  'cipher_suites' / Prefixed(BytesInteger(2), GreedyRange(CipherSuite)),
  'legacy_compression_methods' / Prefixed(BytesInteger(1), GreedyBytes),
  'extensions' / Prefixed(BytesInteger(2), GreedyRange(Extension))
)

## ServerHEllo

ServerHello = Struct(
  'legacy_version' / Const(b'\x03\x03'),
  'random' / Bytes(32), 
  'cipher_suite' / CipherSuite,
  'legacy_compression_method' / Const(b'\x00'),
  'extensions' / Prefixed(BytesInteger(2), GreedyRange(Extension))
)


## NewsessionTicket
NewSessionTicket = Struct(
  'ticket_lifetime' / BytesInteger(4), 
  'ticket_age_add' / BytesInteger(4), 
  'ticket_nonce' / Prefixed(BytesInteger(1), GreedyBytes), 
  'ticket' / Prefixed(BytesInteger(2), GreedyBytes),
  'extensions' / Prefixed(BytesInteger(2), GreedyRange(Extension))
)


## end_of_early_data
EndOfEarlyData = Struct ()

## encrypted extensions
EncryptedExtensions = Struct(
  'extensions' / Prefixed(BytesInteger(2), GreedyRange(Extension))
)


## Certificate 
CertificateType = Enum( BytesInteger(1),
  X509 = 0,
  RawPublicKey = 1
)

CertificateEntry = Struct(
   '_certificate_type' / Computed(this._._certificate_type),
   Probe(this._certificate_type),
   Probe(this._._certificate_type),
   Probe(this._._._certificate_type),
##   'cert' / Switch( this._._.certificate_type, {
   'cert' / Switch( this._certificate_type, {
    'RawPublicKey': Prefixed( BytesInteger(3), GreedyBytes),
    'X509': Prefixed(BytesInteger(3), GreedyBytes)
    }
  ),
  'extensions' / Prefixed( BytesInteger(2), GreedyRange(Extension))
)

Certificate = Struct(
  '_certificate_type' / Computed(this._._certificate_type),
  'certificate_request_context' / Prefixed( BytesInteger(1), GreedyBytes),
  'certificate_list' / Prefixed(BytesInteger(3), GreedyRange(CertificateEntry))
)

## CertificateRequest
CertificateRequest = Struct(
  'certificate_request_context' / Prefixed( BytesInteger(1), GreedyBytes),
  'extensions' / Prefixed(BytesInteger(2), GreedyRange(Extension))
)

## CErtificateVErify
CertificateVerify = Struct(
  'algorithm' / SignatureScheme,
  'signature' / Prefixed( BytesInteger(2), GreedyBytes)
)

## Finished

Finished = Struct(
  '_cipher' / Computed(this._._cipher),
  'verify_data' / Switch(this._cipher,  
    { 'TLS_AES_128_GCM_SHA256' : Bytes(32),
      'TLS_AES_256_GCM_SHA384' : Bytes(48),
      'TLS_CHACHA20_POLY1305_SHA256' : Bytes(32),
      'TLS_AES_128_CCM_SHA256' : Bytes(32),
      'TLS_AES_128_CCM_8_SHA256' : Bytes(32)
    }
  )
)

## KeyUpdate
KeyUpdateRequest = Enum( BytesInteger(1), 
  update_not_requested = 0, 
  update_requested = 1
)

KeyUpdate = Struct(
  'request_update' / KeyUpdateRequest
)

## Hanshake Message 
HandshakeType = Enum( BytesInteger(1), 
  client_hello = 1,
  server_hello = 2,
  new_session_ticket = 4,
  end_of_early_data = 5,
  encrypted_extensions = 8,
  certificate = 11,
  certificate_request = 13,
  certificate_verify = 15,
  finished = 20,
  key_update = 24,
  message_hash = 254,
)

## certificate_type and cipher can be passed as arguments to the 
## Handshake structure. These arguments are then passed down to the 
## downstreamed containers until the final structure. 
Handshake = Struct(
  'msg_type' / HandshakeType,
  '_certificate_type' / If( this.msg_type == 'certificate', Computed(this._._certificate_type)),   
  '_cipher' / If( this.msg_type == 'finished', Computed(this._._cipher)),   
  'data' / Prefixed( BytesInteger(3), Switch(this.msg_type,
    { 'client_hello' : ClientHello,
      'server_hello' : ServerHello,
      'end_of_early_data' : EndOfEarlyData,
      'encrypted_extensions' :  EncryptedExtensions,
      'certificate_request' : CertificateRequest,
      'certificate': Certificate,
      'certificate_verify' : CertificateVerify,
      'finished' : Finished,
      'new_session_ticket' : NewSessionTicket,
      'key_update' : KeyUpdate 
    })
  )
)

