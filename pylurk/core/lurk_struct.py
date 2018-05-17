from construct.core import *
from construct.lib import * 
from os import urandom
from time import time


from pylurk.extensions.tls12_struct import TLS12Type, TLS12Status


Extension = Struct(
    "designation" / Enum( Byte,
        lurk = 0, 
        tls12 = 1
    ), 
    "version" / Switch( this.designation ,
        {
            "lurk": Enum( Byte, v1 = 1 ), 
            "tls12": Enum( Byte, v1 = 1 ) 
        }
    )
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


LURKType = Enum( Byte, 
   capabilities = 0, 
   ping = 1, 
   error = 2
)


LURKHeader = Struct(
   Embedded( Extension ),
   "type" / Switch( this.designation, 
       { 
           "lurk" : LURKType, 
           "tls12" : TLS12Type,
       }, 
   ), 
   "status" / Switch( this.designation, 
       {
           "lurk" : LURKStatus, 
           "tls12" : TLS12Status,
       }, 
      ), 
   "id" / Default( Bytes(8), 
                   Computed( lambda ctx: urandom(8) ).parse(b"") ), 
   "length" / BytesInteger(4), 
) 

############# LURKCapabilitiesResponse

LURKSupportedExtensions = Prefixed( 
    BytesInteger(2), 
    GreedyRange(Extension) 
)

LURKCapabilitiesResponsePayload = Struct( \
    "supported_extensions" / LURKSupportedExtensions, \
    "lurk_state" / Bytes(4), \
)


############  LURKErrorResponse

LURKErrorPayload = Struct (
    "lurk_state" / Bytes(4), \
)



