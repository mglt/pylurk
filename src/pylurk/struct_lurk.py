from construct.core import *
from construct.lib import *

## Extensions are added here
## It may be discussed whether LURK is an extension or not.
## we considered it as an extension to make sure we scale to
## additional extension as well as for readability.
## This is not fully achieved as LURKCapabilitiesResponse
## is defined here as it needs the knowledge of all existing
## extensions.
from pylurk.lurk.struct_lurk_lurk import LURKVersion, LURKType, LURKStatus, ErrorPayload, EmptyPayload
from pylurk.tls13.struct_lurk_tls13 import TLS13Version, TLS13Type, TLS13Status, TLS13Payload


## list the supported extensions
## can parse any value but cannot build any value.
Designation = Enum( BytesInteger( 1 ),
  lurk = 0,
  tls12 = 1,
  tls13 = 2
)


## building generic variables across extensions
## The format of a packet may take any value
## The only valid case is that these unexpected
## values are associated to an ErrorResponse
##
## default is set to Byte so any value can be returned.
Version = Switch( this.designation,
  { 'lurk' : LURKVersion,
    'tls13' : TLS13Version
  }, default=Byte )

Type = Switch( this.designation,
  { 'lurk' : LURKType,
    'tls13' : TLS13Type,
  }, default=Byte)

## The default is set to LURKStatus so an error with a
## bad designation can be returned with a effective error message.
## when the parsing occurs, number is returned.
Status = Switch( this.designation,
     { 'lurk' : LURKStatus,
       'tls13' : TLS13Status,
     }, default=LURKStatus )


## LURK Capability needs global information - that is not
## restricted to the lurk lurk extension:
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

## The Payload lists the acceptable payload
## and raises an Error otherwise.
## The server will be responsible to return the
## appropriated ErrorResponse from that Error.
LURKPayload = Switch(this._type,
  { 'capabilities' : Switch( this._status,
      { 'request' : EmptyPayload,
        'success' : LURKCapabilitiesResponse
      }, default=ErrorPayload
    ),
    'ping' : EmptyPayload,
  }, default=ErrorPayload
)

### generic structure for LURK Messages
LURKHeader = Struct (
  '_name' / Computed('LURK message'),
  'designation' / Designation,
  'version' / Version,
  'type' / Type,
  'status' / Status,
  'id' / BytesInteger(8),
)

LURKMessage = Struct (
  '_name' / Computed('LURK message'),
  'designation' / Designation,
  'version' / Version,
  'type' / Type,
  'status' / Status,
  'id' / BytesInteger(8),
  ## these values are used by Payloads
  '_type' / Computed(this.type),
  '_status' / Computed(this.status),
  ## default parameters for TLS13
  '_certificate_type' / Computed( 'X509' ),
  'payload' / Prefixed( BytesInteger(4),
#     IfThenElse( this.status in [ 'request', 'success' ],
       Switch( this.designation,
         { 'lurk' : LURKPayload,
           'tls13' : TLS13Payload,
         }, default=ErrorPayload ), # other designation are
                                     # associated to ErrorResponse
#       ErrorPayload) # other status are associated to ErrorResponse
  ) # end of prefix
)

LURKMessageList = GreedyRange( LURKMessage )

