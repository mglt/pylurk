from construct.core import *
from construct.lib import * 


LURKType = Enum( Byte, 
  capabilities = 0,  
  ping = 1,  
  error = 2 
)

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

Designation = Enum( Byte,
  lurk = 0,
  tls12 = 1,
  tls13 = 2 
)

Version = Enum( Byte, 
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
    'error' : Switch( this._status,
      { 'response' : ErrorResponse 
      }, default=Error 
    )   
  }, default=Error
)


