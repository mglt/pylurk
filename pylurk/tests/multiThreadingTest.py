from  os.path import join
import threading
import pkg_resources
data_dir = pkg_resources.resource_filename( __name__, '../data/')

from pylurk.core.lurk import LurkServer, ImplementationError, LurkMessage, \
                 HEADER_LEN, LurkClient, LurkServer, LurkUDPClient, \
                 LurkUDPServer, ThreadedLurkUDPServer, LurkTCPClient, LurkTCPServer, ThreadedLurkTCPServer, LurkConf, UDPServerConf, PoolMixIn, LurkHTTPserver, LurkHTTPClient,HTTPRequestHandler,ThreadedLurkHTTPserver
from pylurk.extensions.tls12 import Tls12RsaMasterConf,  Tls12EcdheConf, \
                       Tls12RsaMasterRequestPayload,\
                       Tls12ExtRsaMasterRequestPayload,\
                       Tls12EcdheRequestPayload

from pylurk.utils.utils import message_exchange, resolve_exchange, bytes_error_testing
#import requests


#print(requests.__version__)

tls_keys = { 'client': join( data_dir, 'key_tls12_rsa_client.key'),
             'server': join( data_dir, 'key_tls12_rsa_server.key'),
            }
tls_certs ={'client': join( data_dir, 'cert_tls12_rsa_client.crt'),
            'server': join( data_dir, 'cert_tls12_rsa_server.crt'),
            }

print( "+-------------------------------------------------------+" )
print( "|    UDP  LURK CLIENT / SERVER - MULTI-Threads TESTS    |" )
print( "+-------------------------------------------------------+" )


print("-- Starting LURK UDP Clients")
clt_conf = LurkConf( )
clt_conf.set_role( 'client' )
clt_conf.set_connectivity( type='udp', ip_address="127.0.0.1", port=6789,keys= tls_keys, certs=tls_certs)
client = LurkUDPClient( conf = clt_conf.conf )


print("-- Starting LURK UDP Server")
srv_conf = LurkConf()
srv_conf.set_role( 'server' )
srv_conf.set_connectivity( type='udp', ip_address="127.0.0.1", port=6789, keys= tls_keys, certs=tls_certs)

threadedUDPServer = ThreadedLurkUDPServer (srv_conf.conf, max_workers=7)

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
        resolve_exchange( client, threadedUDPServer, designation, version, mtype, \
                          payload={} )
        continue
    for freshness_funct in [ "null", "sha256" ]:
        resolve_exchange( client, threadedUDPServer, designation, version, mtype, \
                          payload={ 'freshness_funct' : freshness_funct } )

threadedUDPServer.shutdown()
threadedUDPServer.server_close()

print( "+--------------------------------------------------------+" )
print( "|    HTTPS  LURK CLIENT / SERVER  - MULTI-Threads TESTS  |" )
print( "+--------------------------------------------------------+" )


print("-- Starting LURK HTTPS Clients")
clt_conf = LurkConf( )
clt_conf.set_role( 'client' )
clt_conf.set_connectivity( type='http', ip_address="127.0.0.1", port=6789 , keys= tls_keys, certs=tls_certs)
client = LurkHTTPClient( conf = clt_conf.conf, secureTLS_connection=True )

print("-- Starting LURK HTTPS Server")
srv_conf = LurkConf()
srv_conf.set_role( 'server' )
srv_conf.set_connectivity( type='http', ip_address="127.0.0.1", port=6789, keys= tls_keys, certs=tls_certs )

lurkHttpsServer = ThreadedLurkHTTPserver(srv_conf.conf, max_workers=7 , secureTLS_connection=True)
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



print( "+--------------------------------------------------------+" )
print( "|    TCP/TLS  LURK CLIENT / SERVER  - MULTI-Threads TESTS  |" )
print( "+--------------------------------------------------------+" )

try:
    print("-- Starting LURK TCP Clients")
    clt_conf = LurkConf( )
    clt_conf.set_role( 'client' )
    clt_conf.set_connectivity( type='tcp', ip_address="127.0.0.1", port=6789, keys= tls_keys, certs=tls_certs )
    client = LurkTCPClient( conf = clt_conf.conf, secureTLS_connection=True )

    print("-- Starting LURK TCP Server")
    srv_conf = LurkConf()
    srv_conf.set_role( 'server' )
    srv_conf.set_connectivity( type='tcp', ip_address="127.0.0.1", port=6789, keys= tls_keys, certs=tls_certs )

    lurkTCPServer = ThreadedLurkTCPServer(srv_conf.conf, max_workers=7 , secureTLS_connection=True)
    t = threading.Thread( target=lurkTCPServer.serve_forever)

    t.daemon = True
    t.start()

    designation = 'tls12'
    version = 'v1'

    for mtype in [ 'rsa_master', 'ecdhe', 'ping', 'rsa_extended_master', \
                    'capabilities']:
        if mtype in [ 'ping', 'capabilities' ]:
            resolve_exchange( client, lurkTCPServer, designation, version, mtype, \
                              payload={} )
            continue
        for freshness_funct in [ "null", "sha256" ]:
            resolve_exchange( client, lurkTCPServer, designation, version, mtype, \
                              payload={ 'freshness_funct' : freshness_funct } )

    lurkTCPServer.shutdown()
    lurkTCPServer.server_close()
except:
   print("Error occurred")