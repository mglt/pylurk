from construct.core import *
from construct.lib import *

""" TLS 1.3 related strcutres """
## RFC8446 section 4.2

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
 
Extension = Struct(
  'extension_type' / ExtensionType,
  'extension_data' /  Prefixed(BytesInteger(2), GreedyBytes) 
)


## RFC8446 section 4.2.11
PskIdentity = Struct(
  'identity' / Prefixed( BytesInteger(2), GreedyBytes),
  'obfuscated_ticket_age' / Bytes(4)
)

## RFC8446 section 4.4.2
CertificateType = Enum( BytesInteger(1),
  X509 = 0,
  RawPublicKey = 1
)

CertificateEntry = Struct(
  Switch( this._.certificate_type, {
    'RawPublicKey': Prefixed( BytesInteger(3), GreedyBytes),
    'X509': Prefixed(3, GreedyBytes)
    }
  ),
  'extensions' / Prefixed( BytesInteger(2), GreedyRange(Extension))
)

Certificate = Struct(
  'certificate_request_context' / Prefixed( BytesInteger(1), GreedyBytes),
  'certificate_list' / Prefixed(3, GreedyRange(CertificateEntry))
)

## RFC8446 4.2.3
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

