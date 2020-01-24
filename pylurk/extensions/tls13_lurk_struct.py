from construct.core import *
from construct.lib import *
from pylurk.extensions.tls13_tls13_struct import PskIdentity, Certificate,\
                                                  SignatureScheme

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


SecretRequest = Struct(
  'key_request' / KeyRequest,
  'handshake_contex' / Prefixed( BytesInteger(4), GreedyBytes),
  'extension_list' / Prefixed( BytesInteger(2), GreedyRange(LURK13Extension)) 
)

SecretResponse = Struct(
  'secret_list' / Prefixed( BytesInteger(2), GreedyRange(Secret)),
  'extension_list' / Prefixed( BytesInteger(2), GreedyRange(LURK13Extension))  
)


LURK13CertificateType = Enum ( BytesInteger(1),
  tls13 = 0, 
  sha256_32 = 1
)

LURK13Certificate = Struct(
  'certificate_type' /  LURK13CertificateType, 
  'certificate_data' / Switch( this.certificate_type,
    { 'sha256_32' : Bytes(4), 
      'tls13' : Certificate
    }  
  ) 
)

KeyPairIDType = Enum( BytesInteger(1),
  sha256_32 = 0
)

KeyPairID = Struct(
  "key_id_type" / KeyPairIDType,
  "key_id" / Switch( this.key_id_type,
        {
        "sha256_32" : Bytes(4)
        }
    )
)


SignatureRequest = Struct(
  'key_id'/ KeyPairID, 
  'sig_algo' / SignatureScheme, 
  'certificate' / LURK13Certificate
)

SignatureResponse = Struct(
  'signature' / Prefixed( BytesInteger(2), GreedyBytes)
)


