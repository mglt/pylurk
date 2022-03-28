from construct.core import *
from construct.lib import *
from construct.debug import *

""" TLS 1.3 related structures """

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
 '_name' / Computed('KeyShareEntry'),
  'group' / NamedGroup, 
  'key_exchange' / Prefixed(BytesInteger(2), Switch(this.group,
  { 'secp256r1' : Struct(
      'legacy_form' / Const(4, BytesInteger(1)), 
      'x' / BytesInteger(32),
      'y' / BytesInteger(32)
      ), 
    'secp384r1' : Struct(
      'legacy_form' / Const(4, BytesInteger(1)), 
      'x' / BytesInteger(48),
      'y' / BytesInteger(48)
      ), 
    'secp521r1' : Struct(
      'legacy_form' / Const(4, BytesInteger(1)), 
      'x' / BytesInteger(66),
      'y' / BytesInteger(66)
      ), 
    'x25519' : Bytes(32),
    'x448' : Bytes(56),
  }))
)

### only for LURK
EmptyKeyShareEntry = Struct(
 '_name' / Computed('EmptyKeyShareEntry'),
  'group' / NamedGroup,
  'key_exchange' / Prefixed( BytesInteger(2), Const(b'') )
)

KeyShareClientHello = Struct(
 '_name' / Computed('KeyShareClientHello'),
 'client_shares' / Prefixed(BytesInteger(2), GreedyRange(KeyShareEntry)) 
)

## only for LURK
PartialKeyShareClientHello = Struct(
 '_name' / Computed('KeyShareClientHelloEmpty'),
 'client_shares' / Prefixed(BytesInteger(2), GreedyRange( Select( KeyShareEntry, EmptyKeyShareEntry ) ) ) 
)

## only for LURK
#KeyShareClient = Select( 
#  KeyShareClientHello, KeyShareClientHelloEmpty
#)

KeyShareHelloRetryRequest = Struct(
 '_name' / Computed('KeyShareHelloRetryRequest'),
  'selected_group' / NamedGroup
)

KeyShareServerHello = Struct(
 '_name' / Computed('KeyShareServerHello'),
  'server_share' / KeyShareEntry
)

## defining the EmptyKeyShareEntry as a potential structure
## for KeyShareEntry.


KeyShareServerHelloEmpty = Struct(
 '_name' / Computed('KeyShareServerHelloEmpty'),
  'server_share' / EmptyKeyShareEntry
)

## LURK and non LURK
KeyShareServer = Select(
  KeyShareServerHello, KeyShareServerHelloEmpty,
  KeyShareHelloRetryRequest
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


## Only for LURK

#ExtendedPskIdentity = Struct(
#  '_name' / Computed(''), 
#  'identity' / Prefixed( BytesInteger(2), GreedyBytes ),
#  'obfuscated_ticket_age' / Bytes(4)
#  'tls_hahs' / TLSHash, 
#  'psk_bytes' / Prefixed( BytesInteger(2), GreedyBytes ),
#)

OfferedPsksWithNoBinders = Struct(
  'identities' / Prefixed(BytesInteger(2), GreedyRange(PskIdentity)) 
)



## server_certificate

## https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-3
CertificateType = Enum( BytesInteger(1), 
  X509 = 0, 
  RawPublicKey = 2
)

##   struct {
##           select(ClientOrServerExtension) {
##               case client:
##                 CertificateType client_certificate_types<1..2^8-1>;
##               case server:
##                 CertificateType client_certificate_type;
##           }
##   } ClientCertTypeExtension;
##
##   struct {
##           select(ClientOrServerExtension) {
##               case client:
##                 CertificateType server_certificate_types<1..2^8-1>;
##               case server:
##                 CertificateType server_certificate_type;
##           }
##   } ServerCertTypeExtension;



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
  '_name' / Computed('Extension'),
  'extension_type' / ExtensionType,
  'extension_data' /  Prefixed(BytesInteger(2),
                      Switch(this.extension_type,
    {
      'supported_groups' : NamedGroupList,
      'signature_algorithms' : SignatureSchemeList, 
      'pre_shared_key' : Switch(this._._msg_type,
         {
           'client_hello' : OfferedPsks, 
           'server_hello' : BytesInteger( 2 ) 
         }
        ),
      'post_handshake_auth' : PostHandshakeAuth,
      'psk_key_exchange_modes' : PskKeyExchangeModes, 
      'key_share': Switch(this._._msg_type, 
         {
          'client_hello' : KeyShareClientHello, 
          'server_hello' : KeyShareServer, 
         }
        )
    }, default=Bytes)
  ) 
)

##LURK only -- we may do the same with ServerHello
## PartialCHExtension

PartialCHExtension = Struct(
  '_name' / Computed('PartialCHExtension'),
  'extension_type' / ExtensionType,
  'extension_data' /  Prefixed(BytesInteger(2),
                      Switch(this.extension_type,
    {
      'supported_groups' : NamedGroupList,
      'signature_algorithms' : SignatureSchemeList, 
      'pre_shared_key' : Switch(this._._msg_type,
         {
           'client_hello' : OfferedPsksWithNoBinders, 
           'server_hello' : BytesInteger( 2 ) 
         }
        ),
      'post_handshake_auth' : PostHandshakeAuth,
      'psk_key_exchange_modes' : PskKeyExchangeModes, 
      'key_share': Switch(this._._msg_type, 
         {
          'client_hello' : Select( PartialKeyShareClientHello, KeyShareClientHello ),
          'server_hello' : KeyShareServer, 
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
  '_name' / Computed('ClientHello'),
  '_msg_type' / Computed('client_hello'),
  'legacy_version' / Const(b'\x03\x03'),
  'random' / Bytes(32), 
  'cipher_suites' / Prefixed(BytesInteger(2), GreedyRange(CipherSuite)),
  'legacy_compression_methods' / Prefixed(BytesInteger(1), GreedyBytes),
  'extensions' / Prefixed(BytesInteger(2), GreedyRange(Extension))
)


## LURK only
PartialClientHello = Struct( 
  '_name' / Computed('ClientHello'),
  '_msg_type' / Computed('client_hello'),
  'legacy_version' / Const(b'\x03\x03'),
  'random' / Bytes(32), 
  'cipher_suites' / Prefixed(BytesInteger(2), GreedyRange(CipherSuite)),
  'legacy_compression_methods' / Prefixed(BytesInteger(1), GreedyBytes),
  'extensions' / Prefixed(BytesInteger(2), GreedyRange(PartialCHExtension))
)


## ServerHello

ServerHello = Struct(
  '_name' / Computed('ServerHello'),
  '_msg_type' / Computed('server_hello'),
  'legacy_version' / Const(b'\x03\x03'),
  'random' / Bytes(32), 
  'cipher_suite' / CipherSuite,
  'legacy_compression_method' / Const(b'\x00'),
  'extensions' / Prefixed(BytesInteger(2), GreedyRange(Extension))
)


## NewsessionTicket
NewSessionTicket = Struct(
  '_name' / Computed('NewTicketSession'),
  '_msg_type' / Computed('new_ticket_session'),
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
  '_name' / Computed('EncryptedExtensions'),
  'extensions' / Prefixed(BytesInteger(2), GreedyRange(Extension))
)


## Certificate 
CertificateType = Enum( BytesInteger(1),
  X509 = 0,
  RawPublicKey = 2
)

CertificateEntry = Struct(
   
#   '_certificate_type' / Computed(this._._certificate_type),
#   'cert' / Switch( this._certificate_type, {
#    'RawPublicKey': Prefixed( BytesInteger(3), GreedyBytes),
#    'X509': Prefixed(BytesInteger(3), GreedyBytes)
#    }
#  ),
  'cert' / Prefixed(BytesInteger(3), GreedyBytes),
  'extensions' / Prefixed( BytesInteger(2), GreedyRange(Extension))
)

Certificate = Struct(
  '_name' / Computed('Certificate'),
#  '_certificate_type' / Computed(this._._certificate_type),
  'certificate_request_context' / Prefixed( BytesInteger(1), GreedyBytes),
  'certificate_list' / Prefixed(BytesInteger(3), GreedyRange(CertificateEntry))
)

## Compressed Certificate
CertificateCompressionAlgorithm = Enum ( BytesInteger(2),
  zlib = 1,
  brotli = 2,
  zstd = 3
)

CompressedCertificate = Struct( 
  '_name' / Computed('CompressedCertificate'),
  'algorithm' / CertificateCompressionAlgorithm, 
  'uncompressed_length' / BytesInteger(3),
  'compressed_certificate_message' / Prefixed(BytesInteger(3), GreedyBytes)
)


## CertificateRequest
CertificateRequest = Struct(
  '_name' / Computed('CertificateRequest'),
  'certificate_request_context' / Prefixed( BytesInteger(1), GreedyBytes),
  'extensions' / Prefixed(BytesInteger(2), GreedyRange(Extension))
)

## CErtificateVErify
CertificateVerify = Struct(
  '_name' / Computed('CertificateVerify'),
  'algorithm' / SignatureScheme,
  'signature' / Prefixed( BytesInteger(2), GreedyBytes)
)

## Finished

Finished = Struct(
  '_name' / Computed('Finished'),
##  '_cipher' / Computed(this._._cipher),
##  '_verify_data_length' / Switch(this._cipher,  
##    { 'TLS_AES_128_GCM_SHA256' : Const(32, Int8ul),
##      'TLS_AES_256_GCM_SHA384' : Const(48, Int8ul),
##      'TLS_CHACHA20_POLY1305_SHA256' : Const(32, Int8ul),
##      'TLS_AES_128_CCM_SHA256' : Const(32, Int8ul),
##      'TLS_AES_128_CCM_8_SHA256' : Const(32, Int8ul)
##    }, default=Rebuild( Byte, len_( this.verify_data ) ) ),
  'verify_data' / Select( Bytes( 32 ), Bytes( 48 ) )
#  'verify_data' / Bytes( this._verify_data_length )  
)

##Finished = Struct(
##  '_name' / Computed('Finished'),
##  '_cipher' / Computed(this._._cipher),
##  'verify_data' / Switch(this._cipher,  
##    { 'TLS_AES_128_GCM_SHA256' : Bytes(32),
##      'TLS_AES_256_GCM_SHA384' : Bytes(48),
##      'TLS_CHACHA20_POLY1305_SHA256' : Bytes(32),
##      'TLS_AES_128_CCM_SHA256' : Bytes(32),
##      'TLS_AES_128_CCM_8_SHA256' : Bytes(32)
##    }
##  )
##)

## KeyUpdate
KeyUpdateRequest = Enum( BytesInteger(1), 
  update_not_requested = 0, 
  update_requested = 1
)

KeyUpdate = Struct(
  '_name' / Computed('KeyUpdate'),
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
  '_name' / Computed('Handshake'),
  'msg_type' / HandshakeType,
#  '_certificate_type' / If( this.msg_type == 'certificate', Computed(this._._certificate_type)),   
##  '_certificate_type' / If( this.msg_type == 'certificate', Computed('X509') ),   
##  '_cipher' / If( this.msg_type == 'finished', Computed(this._._cipher)),   
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

## Designation of specific handshake messages
## These structures have been designed to designate Sequences. 
## As Sequences are nesting structures and initializing the 
## context in the Sequence has not been performed, the parameters
## associated to the context are read one level above. 
## Unless there is such need, it is recommended to use the Handshake 
## and other associated message specific structures

HSClientHello = Struct( 
  '_name' / Computed('HSClientHello'),
  'msg_type' / Const('client_hello', HandshakeType),
  'data' / ClientHello
)

## only for LURK
HSPartialClientHello = Struct( 
  '_name' / Computed('HSPartialClientHello'),
  'msg_type' / Const('client_hello', HandshakeType),
  'data' / PartialClientHello
)

HSServerHello = Struct(
  '_name' / Computed('HSServerHello'),
  'msg_type' / Const('server_hello', HandshakeType),
  'data' / ServerHello
)

HSEncryptedExtensions = Struct( 
  '_name' / Computed('HSEncryptedExtensions'),
  'msg_type' / Const('encrypted_extensions', HandshakeType), 
  'data' / EncryptedExtensions 
)

HSCertificateRequest = Struct(
  '_name' / Computed('HSCertificateRequest'),
  'msg_type' / Const('certificate_request', HandshakeType), 
  'data' / CertificateRequest
)

HSCertificate = Struct( 
#  '_certificate_type' / Computed(this._._._certificate_type),
  '_name' / Computed('HSCertificate'),
  'msg_type' / Const('certificate', HandshakeType), 
  'data' / Certificate
)

HSCertificateVerify = Struct(
  '_name' / Computed('HSCertificateVerify'),
  'msg_type' / Const('certificate_verify', HandshakeType), 
  'data' / CertificateVerify
)

HSFinished = Struct(
  '_name' / Computed('HSFinished'),
  'msg_type' / Const('finished', HandshakeType), 
  'data' / Finished 
)

HSEndOfEarlyData = Struct( 
  '_name' / Computed('HSEndOfEarlyData'),
  'msg_type' / Const('end_of_early_data', HandshakeType),
  'data' / EndOfEarlyData
)


#### Encrypted messages
ContentType = Enum( BytesInteger(1), 
  invalid = 0,
  change_cipher_spec = 20, 
  alert = 21,
  handshake = 22, 
  application_data = 23
)

TLSCiphertext = Struct(
  'opaque_type' / Const( ContentType.build( 'application_data' )), 
  'legacy_record_version' / Const( b'\x03\x03' ),
  'length' / BytesInteger(2), 
  'encrypted_reccord' / Bytes( this.length )
)


TLSInnerPlaintext = Struct(
  'content' / GreedyBytes,
  'type' / ContentType, 
  'zeros' / Array( this._._length_of_padding, Const(b'\x00') ) 
)
