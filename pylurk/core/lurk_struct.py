from construct.core import *
from construct.lib import * 
from os import urandom
from time import time


from pylurk.extensions.lurk_lurk_struct import LURKType, LURKStatus, LURKPayload, Designation, Version
##from pylurk.extensions.tls12_struct import TLS12Type, TLS12Status
from pylurk.extensions.tls13_lurk_struct import TLS13Type, TLS13Status, LURKTLS13Payload


LURKHeader = Struct(
  'designation' / Designation, 
  'version' / Version,
  'type' / Switch( this.designation, 
    { 'lurk' : LURKType, 
#      'tls12' : TLS12Type,
      'tls13' : TLS13Type,
    }, default=Error 
  ), 
  'status' / Switch( this.designation, 
     { 'lurk' : LURKStatus, 
#       'tls12' : TLS12Status,
       'tls13' : TLS13Status,
     }, default=Error 
  ), 
  'id' / Default( Bytes(8), 
                 Computed( lambda ctx: urandom(8) ).parse(b"") ),
)

LURKMessage = Struct(
  'header' / LURKHeader,
  ## parameters to be passed to payloads
  '_type' / Computed(this.header.type),
  '_status' / Computed(this.header.status),
  ## default parameters for TLS13
  '_certificate_type' / Computed( 'X509' ),
#  '_cipher' / Default( Select( Computed('TLS_AES_128_GCM_SHA256'), Computed('TLS_AES_256_GCM_SHA384') ) ),
  'payload' / Prefixed( BytesInteger(4), Switch( this.header.designation,
     { 'lurk' : LURKPayload, 
#       'tls12' : TLS12Status,
       'tls13' : LURKTLS13Payload,
     }, default=Error 
  ))
) 




