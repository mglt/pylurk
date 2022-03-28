from test_utils import * 
from secrets import randbelow
from copy import deepcopy

## inserting the src in the search path 
import sys
sys.path.insert( 0, '../src/')

from pylurk.struct_lurk import *

## Ability to receive unexpected header
print( Designation.parse( b'\x05' ) )
print( Designation.build( 5 )  )

## ability to parse
print( Version.parse( b'\x00', designation='lurk' ) ) ## expected
print( Version.parse( b'\x06', designation='lurk' ) ) ## unexpected version
print( Version.parse( b'\x06', designation=b'\x05' ) ) ## unexpected version / designation


print( Version.build( 6, designation=5 ) ) ## unexpected version / designation

ping_req = { 'designation' : 'lurk', 
             'version' : 'v1', 
             'type'  : 'ping',
             'status' : 'request',
             'id' : randbelow( 2  ** 64 ),  
             'payload' : {} }

ping_resp = { 'designation' : 'lurk', 
              'version' : 'v1', 
              'type'  : 'ping',
              'status' : 'success',
              'id' : randbelow( 2  ** 64 ),  
              'payload' : {} }

cap_req = { 'designation' : 'lurk', 
            'version' : 'v1', 
            'type'  : 'capabilities',
            'status' : 'request',
            'id' : randbelow( 2  ** 64 ),  
            'payload' : {} }

cap_resp = { 'designation' : 'lurk', 
             'version' : 'v1', 
             'type'  : 'capabilities',
             'status' : 'success',
             'id' : randbelow( 2  ** 64 ),  
             'payload' : { \
                'supported_extensions' : [ { 'designation' : 'lurk', 'version' : 'v1'},
                                            { 'designation' : 'tls13', 'version' : 'v1'} ], 
                 'lurk_state' : b'1234' } }

# this error may be returned an error occurs inside the extension
error_resp = { 'designation' : 'lurk', 
               'version' : 'v1', 
               'type'  : 'capabilities',
               'status' : 'invalid_format',
               'id' : randbelow( 2  ** 64 ),
               'payload' : { 'lurk_state' : b'1234' } }

# these errors indicates there is no extensions, but may
# be sent by the server as well
# undefined values MUST be replaced by integers to allow the 
# response to be built 
error_resp2 = { 'designation' : 5, 
               'version' : 5, 
               'type'  : 5,
               'status' : 90,
               'id' : randbelow( 2  ** 64 ),
               'payload' : { 'lurk_state' : b'1234' } }

## Sending a status set to success should not be possible
## with an error message. This needs to be controlled by the server 
## as opposed to by the definition of the structure.
error_resp_unval = { 'designation' : 'lurk', 
                     'version' : 'v1', 
                     'type'  : 'invalid_',
                     'status' : 'success',
                     'id' : randbelow( 2  ** 64 ),
                     'payload' : { 'lurk_state' : b'1234' } }



for msg in [ ping_req, ping_resp, cap_req, cap_resp, error_resp, error_resp2 ]:
  test_struct( LURKMessage, msg, no_title=True, print_data_struct=True )

for msg in [ error_resp_unval ]:  
  try:
    test_struct( LURKMessage, msg, no_title=True )
  except MappingError as e :
    print( f"{e.args[ 0 ]}" )

# testing how mapping Error can be caught 
ping_req_test = deepcopy( ping_req )
ping_req_test[ 'designation' ] = 'test'
try:
  test_struct( LURKMessage, ping_req_test, no_title=True )
except MappingError as e :
  print( f"{e.args[ 0 ]}" )
  msg = e.args[ 0 ]
  m = msg.split ('\n' )
  var_type = m[ 0 ].split( '->' )
  var_type = var_type[ 1] 
  var_value = m[ 1 ].split( 'for' )
  var_value = var_value[ 1 ] 
  print( f"vartype: {var_type} - var_value: {var_value}" ) 

## testing parsing with extra bytes
## extra bytes are simply ignored during parsing
byte_ping_req = LURKMessage.build( ping_req )
LURKMessage.parse( byte_ping_req + b'\x00' )



from pylurk.cs import CryptoService
import pylurk.conf

conf = deepcopy( pylurk.conf.conf_template ) 

cs = CryptoService( conf )
for req in [ ping_req, cap_req ]:
  resp = cs.serve( LURKMessage.build( req ) )
  resp =  LURKMessage.parse( resp )
  match( req, resp ) 

byte_ping_req = LURKMessage.build( ping_req )

print( "## testing too short packet" )
byte_req = byte_ping_req[:-1]
resp = cs.serve( byte_req )
if resp != b'':
  raise ValueError( f" too short packets ( {len(byte_req)} bytes )"\
                    f"expects to receive b'' as a response." )
print( "## testing bad designation" )
byte_req = byte_ping_req
byte_req = b'\xff' + byte_ping_req[1:]
byte_resp = cs.serve( byte_req )
resp = LURKMessage.parse( byte_resp )
if resp[ 'status' ] != 'invalid_extension' :
  raise ValueError( f" 'invalid_extension' status expected {resp}" )

print( "## testing bad type" )
byte_req = byte_ping_req
byte_req = byte_ping_req[ : 2] + b'\xff' + byte_ping_req[ 3 : ]
byte_resp = cs.serve( byte_req )
resp = LURKMessage.parse( byte_resp )
if resp[ 'status' ] != 'invalid_type' :
  raise ValueError( f" 'invalid_type' status expected {resp}" )

print( "## testing bad status" )
byte_req = byte_ping_req
byte_req = byte_ping_req[ : 3] + b'\xff' + byte_ping_req[ 4 : ]
byte_resp = cs.serve( byte_req )
resp = LURKMessage.parse( byte_resp )
if resp[ 'status' ] != 'invalid_status' :
  raise ValueError( f" 'invalid_status' status expected {resp}" )


print( "## testing bad payload" )
byte_req = byte_ping_req
byte_req = byte_ping_req + b'\xff'
byte_resp = cs.serve( byte_req )
resp = LURKMessage.parse( byte_resp )
print( f"{resp}" )
if resp[ 'status' ] != 'invalid_type' :
  raise ValueError( f" 'invalid_type' status expected {resp}" )





