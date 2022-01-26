from construct.core import *
from construct.lib import * 
from os import urandom
from time import time


#from pylurk.extensions.lurk_lurk_struct import LURKType, LURKStatus, LURKPayload, Designation, Version
##from pylurk.extensions.tls12_struct import TLS12Type, TLS12Status
from pylurk.lurk_tls13_struct import TLS13Version, TLS13Type, TLS13Status, TLS13Payload

## LURK is mostly an envelop that carries Extension payloads
## LURK Type 
LURKType = Enum( Byte,
  capabilities = 0,
  ping = 1,
  error = 2
)

## LURK status
LURKStatus = Enum( Byte,
  request = 0,
  success = 1,
  undefined_error = 2,
  invalid_format = 3,
  invalid_extension = 4,
  invalid_type = 5,
  invalid_status = 6,
  temporary_failure = 7
)

## list the supported extensions
Designation = Enum( Byte,
  lurk = 0,
  tls12 = 1,
  tls13 = 2
)

LURKVersion = Enum( Byte,
  v1 = 1
)

############# LURKCapabilitiesResponse

Extension = Struct(
  'designation' / Designation,
  'version' / Version
)

LURKSupportedExtensions = Prefixed(
  BytesInteger(2),
  GreedyRange(Extension)
)

LURKCapabilitiesResponse = Struct( \
  'supported_extensions' / LURKSupportedExtensions, \
  'lurk_state' / Bytes(4)
)

############  LURKErrorResponse

ErrorResponse = Struct (
  'lurk_state' / Bytes(4), \
)

########### Empty Payload
NoPayload = Struct()

LURKPayload = Switch(this._type,
  { 'capabilities' : Switch( this._status,
      { 'request' : NoPayload,
        'response' : LURKCapabilitiesResponse
      }, default=ErrorResponse
    ),
    'ping' : NoPayload,
  }, default=Error
)

LURKHeader = Struct ( 
  'designation' / Designation, 
  'version' / Switch( this.designation, 
    { 'lurk' : LURKVersion, 
##     'tls12' : TLS12Version
      'tls13' : TLS13Version
    }, default=Error ),
  'type' / Switch( this.designation, 
    { 'lurk' : LURKType, 
##     'tls12' : TLS12Type,
      'tls13' : TLS13Type,
    }, default=Error 
  ), 
  'status' / Switch( this.designation, 
     { 'lurk' : LURKStatus, 
##      'tls12' : TLS12Status,
       'tls13' : TLS13Status,
     }, default=Error 
  ), 
  'id' / Default( Bytes(8), 
                 Computed( lambda ctx: urandom(8) ).parse(b"") )
)

LURKMessage = Struct(
  '_name' / Computed('LURK message'),
  'header' / LURKHeader,
  ## these values are used by Payloads 
  '_type' / Computed(this.type),
  '_status' / Computed(this.status),
  ## default parameters for TLS13
  '_certificate_type' / Computed( 'X509' ),
  'payload' / Prefixed( BytesInteger(4), Switch( this.designation,
     { 'lurk' : LURKPayload, 
#       'tls12' : TLS12Status,
       'tls13' : LURKTLS13Payload,
     }, default=Error 
  ))  
)

## structure used to parse LURK messages. 
## We consider such structure to be able to accept a list of LURK requests. 
## We do not want the fields to be checks during the parsing as a bad 
## structure will will raise an error and reject all other (valid) structures.

LURKMessageParser = Struct( 
  'header' / Bytes( 12), 
  'payload' / Prefixed( BytesInteger(4), GreedyRange( Byte ) ) 
)

LURKMessageParserList = GreedyRange( LURKMessageParser )

#LURKMessage = Struct(
#  'header' / LURKHeader,
#  ## parameters to be passed to payloads
#  '_type' / Computed(this.header.type),
#  '_status' / Computed(this.header.status),
#  ## default parameters for TLS13
#  '_certificate_type' / Computed( 'X509' ),
#  '_cipher' / Default( Select( Computed('TLS_AES_128_GCM_SHA256'), Computed('TLS_AES_256_GCM_SHA384') ) ),
#  'payload' / Prefixed( BytesInteger(4), Switch( this.header.designation,
#     { 'lurk' : LURKPayload, 
#       'tls12' : TLS12Status,
#       'tls13' : LURKTLS13Payload,
#     }, default=Error 
#  ))
#) 




