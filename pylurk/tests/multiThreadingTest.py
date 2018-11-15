from  os.path import join
import threading
import pkg_resources
data_dir = pkg_resources.resource_filename( __name__, '../data/')

from pylurk.core.lurk import LurkServer, ImplementationError, LurkMessage, \
                 HEADER_LEN, LurkClient, LurkServer, LurkUDPClient, \
                 LurkUDPServer, LurkTCPClient, LurkTCPServer, LurkConf, UDPServerConf, PoolMixIn, LurkHTTPSserver, LurkHTTPSClient,HTTPSRequestHandler,ThreadedLurkHTTPSserver
from pylurk.extensions.tls12 import Tls12RsaMasterConf,  Tls12EcdheConf, \
                       Tls12RsaMasterRequestPayload,\
                       Tls12ExtRsaMasterRequestPayload,\
                       Tls12EcdheRequestPayload

from pylurk.utils.utils import message_exchange, resolve_exchange, bytes_error_testing
#import requests


#print(requests.__version__)


print( "+-------------------------------------------------------+" )
print( "|    UDP  LURK CLIENT / SERVER - MULTI-Threads TESTS    |" )
print( "+-------------------------------------------------------+" )

print("-- Starting LURK UDP Clients")
clt_conf = LurkConf( )
clt_conf.set_role( 'client' )
clt_conf.set_connectivity( type='udp', ip_address="127.0.0.1", port=6789 )
client = LurkUDPClient( conf = clt_conf.conf )
client2 = LurkUDPClient( conf = clt_conf.conf )


print("-- Starting LURK UDP Server")
srv_conf = LurkConf()
srv_conf.set_role( 'server' )
srv_conf.set_connectivity( type='udp', ip_address="127.0.0.1", port=6789 )

updServer = LurkUDPServer (srv_conf.conf)
threadedUDPServer = updServer.get_thread_udpserver(7)


# Start a thread with the server -- that thread will then start one
# more thread for each request (not for each client)
t = threading.Thread( target=threadedUDPServer.serve_forever)
t.daemon = True
t.start()

designation = 'tls12'
version = 'v1'


for mtype in [ 'rsa_master', 'ecdhe', 'ping', 'rsa_extended_master', \
               'capabilities']:
    if mtype in [ 'ping', 'capabilities' ]:
        resolve_exchange( client, updServer, designation, version, mtype, \
                          payload={} )
        continue
    for freshness_funct in [ "null", "sha256" ]:
        resolve_exchange( client2, updServer, designation, version, mtype, \
                          payload={ 'freshness_funct' : freshness_funct } )

threadedUDPServer.shutdown()
threadedUDPServer.server_close()

print( "+--------------------------------------------------------+" )
print( "|    HTTPS  LURK CLIENT / SERVER  - MULTI-Threads TESTS  |" )
print( "+--------------------------------------------------------+" )


print("-- Starting LURK HTTPS Clients")
clt_conf = LurkConf( )
clt_conf.set_role( 'client' )
clt_conf.set_connectivity( type='tcp', ip_address="127.0.0.1", port=6789 ) #keep to tcp?
client = LurkHTTPSClient( conf = clt_conf.conf )

print("-- Starting LURK HTTPS Server")
srv_conf = LurkConf()
srv_conf.set_role( 'server' )
srv_conf.set_connectivity( type='tcp', ip_address="127.0.0.1", port=6789 )#keep to tcp?

lurkHttpsServer = ThreadedLurkHTTPSserver(srv_conf.conf, max_workers=7 )
t = threading.Thread( target=lurkHttpsServer.serve_forever)

t.daemon = True
t.start()

designation = 'tls12'
version = 'v1'

for mtype in [ 'rsa_master', 'ecdhe', 'ping', 'rsa_extended_master', \
                'capabilities']:
    if mtype in [ 'ping', 'capabilities' ]:
        resolve_exchange( client, lurkHttpsServer, designation, version, mtype, \
                          payload={} )
        continue
    for freshness_funct in [ "null", "sha256" ]:
        resolve_exchange( client, lurkHttpsServer, designation, version, mtype, \
                          payload={ 'freshness_funct' : freshness_funct } )

lurkHttpsServer.shutdown()
lurkHttpsServer.server_close()


