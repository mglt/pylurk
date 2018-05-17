import sys
import os
#sys.path.append(os.path.abspath("../../"))

from pylurk.utils.utils import *
from pylurk.core.lurk import LurkServer, ImplementationError,\
                 HEADER_LEN, LurkClient
import threading
##from ..utils import message_exchange, bytes_error_testing, \
##                  resolve_exchange 


print( "+---------------------------------------+" )
print( "|             MESSAGE TESTS              |" )
print( "+---------------------------------------+" )


print("--- Payload Testing: testing build/parse/serve functions" + \
      "--- for queries and response.")
designation = 'lurk'
version = 'v1'

for mtype in [ "capabilities", "ping" ]:
    message_exchange( designation, version, mtype, payload={} )


print( "+---------------------------------------+" )
print( "|             SERVER ERROR TESTS              |" )
print( "+---------------------------------------+" )


server = LurkServer()
query_ref_bytes = LurkMessage().build( designation='lurk', version='v1',\
                   status="request")
lurk_header_error = [\
    ("Invalid Designation", 0, 0,   "invalid_extension" ), \
    ("Invalid Version",     1, 1,   "invalid_extension" ), \
    ("Invalid Type",        2, 2,   "invalid_type" ), \
    ("Invalid Status",      3, 3,   "invalid_status" ), \
    ("Invalid Length",      12, 15, "invalid_format" )\
]

bytes_error_testing( server, query_ref_bytes, lurk_header_error)



print( "+---------------------------------------+" )
print( "|       LURK CLIENT / SERVER TESTS      |" )
print( "+---------------------------------------+" )

srv_conf = LurkConf()
srv_conf.set_role( 'server' )
srv_conf.set_connectivity( type='local' ) 
server = LurkServer( conf=srv_conf.conf )


clt_conf = LurkConf()
clt_conf.set_role( 'client' )
clt_conf.set_connectivity( type='local' ) 
client = LurkClient( conf=clt_conf.conf )

designation = 'lurk' 
version = 'v1'

for mtype in [ "capabilities", "ping" ]:
    resolve_exchange( client, server, designation, version, mtype, \
                      payload={} )

print( "+---------------------------------------+" )
print( "|    UDP  LURK CLIENT / SERVER TESTS    |" )
print( "+---------------------------------------+" )


print("-- Starting LURK UDP Client")
clt_conf = LurkConf()
clt_conf.set_role( 'server' )
clt_conf.set_connectivity( type='udp', ip_address="127.0.0.1", port=6789 ) 
client = LurkUDPClient( conf=clt_conf.conf )

print("-- Starting LURK UDP Server")
srv_conf = LurkConf()
srv_conf.set_role( 'server' )
srv_conf.set_connectivity( type='udp', ip_address="127.0.0.1", port=6789 ) 

t = threading.Thread( target=LurkUDPServer, kwargs= { 'conf' : srv_conf.conf } )
t.daemon = True
t.start()


designation = 'lurk' 
version = 'v1'

for mtype in [ "capabilities", "ping" ]:
    resolve_exchange( client, server, designation, version, mtype, \
                      payload={} )




