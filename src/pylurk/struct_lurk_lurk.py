from construct.core import *
from construct.lib import *

LURKVersion = Enum( BytesInteger( 1 ),
  v1 = 1
)

## LURK Type
LURKType = Enum( BytesInteger( 1 ) ,
  capabilities = 0,
  ping = 1,
  error = 2
)

## LURK status
LURKStatus = Enum( BytesInteger( 1 ),
  request = 0,
  success = 1,
  undefined_error = 2,
  invalid_format = 3,
  invalid_extension = 4,
  invalid_type = 5,
  invalid_status = 6,
  temporary_failure = 7
)

############  LURKErrorResponse

ErrorPayload = Struct (
  'lurk_state' / Bytes(4), \
)

########### Empty Payload
EmptyPayload = Struct()
