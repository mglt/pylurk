from  os.path import join
import multiprocessing as mp
from time import sleep
import threading
import pkg_resources
data_dir = pkg_resources.resource_filename( __name__, '../data/')

### merge ###<<<<<<< HEAD
### merge ###                 HEADER_LEN, LurkClient, LurkServer, LurkUDPClient, \
### merge ###                 LurkUDPServer, ThreadedLurkUDPServer, LurkTCPClient, LurkTCPServer, ThreadedLurkTCPServer, LurkConf, UDPServerConf, PoolMixIn, LurkHTTPserver, LurkHTTPClient,HTTPRequestHandler,ThreadedLurkHTTPserver
### =======
from pylurk.core.lurk import LurkServer, ImplementationError, LurkMessage, \
                 HEADER_LEN, LurkClient, LurkServer, \
                 LurkUDPClient, LurkUDPServer, \
                 LurkTCPClient, LurkTCPServer, BaseTCPServer, TCPHandle,  \
                 LurkConf, UDPServerConf, \
                 LurkHTTPserver, LurkHTTPClient,HTTPRequestHandler,ThreadedLurkHTTPserver \
                 ## PoolMixIn, \
###  >>>>>>> mlt2-gmlt
from pylurk.extensions.tls12 import Tls12RsaMasterConf,  Tls12EcdheConf, \
                       Tls12RsaMasterRequestPayload,\
                       Tls12ExtRsaMasterRequestPayload,\
                       Tls12EcdheRequestPayload

from pylurk.utils.utils import message_exchange, resolve_exchange, bytes_error_testing
#import requests


#print(requests.__version__)

###<<<<<<< HEAD
tls_keys = { 'client': join( data_dir, 'key_tls12_rsa_client.key'),
             'server': join( data_dir, 'key_tls12_rsa_server.key'),
            }
tls_certs ={'client': join( data_dir, 'cert_tls12_rsa_client.crt'),
            'server': join( data_dir, 'cert_tls12_rsa_server.crt'),
            }

### merge ###print( "+-------------------------------------------------------+" )
### merge ###print( "|    UDP  LURK CLIENT / SERVER - MULTI-Threads TESTS    |" )
### merge ###print( "+-------------------------------------------------------+" )
### merge ###
### merge ###
### merge ###print("-- Starting LURK UDP Clients")
### merge ###clt_conf = LurkConf( )
### merge ###clt_conf.set_role( 'client' )
### merge ###clt_conf.set_connectivity( type='udp', ip_address="127.0.0.1", port=6789,keys= tls_keys, certs=tls_certs)
### merge ###client = LurkUDPClient( conf = clt_conf.conf )
### merge ###
### merge ###
### merge ###print("-- Starting LURK UDP Server")
### merge ###srv_conf = LurkConf()
### merge ###srv_conf.set_role( 'server' )
### merge ###srv_conf.set_connectivity( type='udp', ip_address="127.0.0.1", port=6789, keys= tls_keys, certs=tls_certs)
### merge ###
### merge ###threadedUDPServer = ThreadedLurkUDPServer (srv_conf.conf, max_workers=7)
### merge ###
### merge #### Start a thread with the server -- that thread will then start one
### merge #### more thread for each request (not for each client)
### merge ###t = threading.Thread( target=threadedUDPServer.serve_forever)
### merge ###t.daemon = True
### merge ###t.start()
### merge ###
### merge ###designation = 'tls12'
### merge ###version = 'v1'
### merge ###
### merge ###
### merge ###for mtype in [ 'rsa_master', 'ecdhe', 'ping', 'rsa_extended_master', \
### merge ###               'capabilities']:
### merge ###    if mtype in [ 'ping', 'capabilities' ]:
### merge ###        resolve_exchange( client, threadedUDPServer, designation, version, mtype, \
### merge ###                          payload={} )
### merge ###        continue
### merge ###    for freshness_funct in [ "null", "sha256" ]:
### merge ###        resolve_exchange( client, threadedUDPServer, designation, version, mtype, \
### merge ###                          payload={ 'freshness_funct' : freshness_funct } )
### merge ###
### merge ###threadedUDPServer.shutdown()
### merge ###threadedUDPServer.server_close()

### to check ###print( "+--------------------------------------------------------+" )
### to check ###print( "|    HTTPS  LURK CLIENT / SERVER  - MULTI-Threads TESTS  |" )
### to check ###print( "+--------------------------------------------------------+" )
### to check ###
### to check ###
### to check ###print("-- Starting LURK HTTPS Clients")
### to check ###clt_conf = LurkConf( )
### to check ###clt_conf.set_role( 'client' )
### to check ###clt_conf.set_connectivity( type='http', ip_address="127.0.0.1", port=6789 , keys= tls_keys, certs=tls_certs)
### to check ###client = LurkHTTPClient( conf = clt_conf.conf, secureTLS_connection=True )
### to check ###
### to check ###print("-- Starting LURK HTTPS Server")
### to check ###srv_conf = LurkConf()
### to check ###srv_conf.set_role( 'server' )
### to check ###srv_conf.set_connectivity( type='http', ip_address="127.0.0.1", port=6789, keys= tls_keys, certs=tls_certs )
### to check ###
### to check ###lurkHttpsServer = ThreadedLurkHTTPserver(srv_conf.conf, max_workers=7 , secureTLS_connection=True)
### to check ###t = threading.Thread( target=lurkHttpsServer.serve_forever)
### to check ###
### to check ###t.daemon = True
### to check ###t.start()
### to check ###
### to check ###designation = 'tls12'
### to check ###version = 'v1'
### to check ###
### to check ###for mtype in [ 'rsa_master', 'ecdhe', 'ping', 'rsa_extended_master', \
### to check ###                'capabilities']:
### to check ###    if mtype in [ 'ping', 'capabilities' ]:
### to check ###        resolve_exchange( client, designation, version, mtype, \
### to check ###                          payload={} )
### to check ###        continue
### to check ###    for freshness_funct in [ "null", "sha256" ]:
### to check ###        resolve_exchange( client, designation, version, mtype, \
### to check ###                          payload={ 'freshness_funct' : freshness_funct } )
### to check ###
### to check ###lurkHttpsServer.shutdown()
### to check ###lurkHttpsServer.server_close()
### to check ###
### to check ###sleep(5)

### to check ###print( "+--------------------------------------------------------+" )
### to check ###print( "|    TCP/TLS  LURK CLIENT / SERVER  - MULTI-Threads TESTS  |" )
### to check ###print( "+--------------------------------------------------------+" )
### to check ###
### to check ###try:
### to check ###    print("-- Starting LURK TCP Clients")
### to check ###    clt_conf = LurkConf( )
### to check ###    clt_conf.set_role( 'client' )
### to check ###    clt_conf.set_connectivity( type='tcp', ip_address="127.0.0.1", port=6789, keys= tls_keys, certs=tls_certs )
### to check ###    client = LurkTCPClient( conf = clt_conf.conf, secureTLS_connection=True )
### to check ###
### to check ###    print("-- Starting LURK TCP Server")
### to check ###    srv_conf = LurkConf()
### to check ###    srv_conf.set_role( 'server' )
### to check ###    srv_conf.set_connectivity( type='tcp', ip_address="127.0.0.1", port=6789, keys= tls_keys, certs=tls_certs )
### to check ###
### to check ###    lurkTCPServer = ThreadedLurkTCPServer(srv_conf.conf, max_workers=7 , secureTLS_connection=True)
### to check ###    t = threading.Thread( target=lurkTCPServer.serve_forever)
### to check ###
### to check ###    t.daemon = True
### to check ###    t.start()
### to check ###
### to check ###    designation = 'tls12'
### to check ###    version = 'v1'
### to check ###
### to check ###    for mtype in [ 'rsa_master', 'ecdhe', 'ping', 'rsa_extended_master', \
### to check ###                    'capabilities']:
### to check ###        if mtype in [ 'ping', 'capabilities' ]:
### to check ###            resolve_exchange( client, lurkTCPServer, designation, version, mtype, \
### to check ###                              payload={} )
### to check ###            continue
### to check ###        for freshness_funct in [ "null", "sha256" ]:
### to check ###            resolve_exchange( client, designation, version, mtype, \
### to check ###                              payload={ 'freshness_funct' : freshness_funct } )
### to check ###
### to check #####    lurkTCPServer.shutdown()
### to check #####    lurkTCPServer.server_close()
### to check ###except:
### to check ###   t.terminate()
### to check ###   print("Error occurred")
### to check ###
### to check ###sleep(5)

#### =======
def set_lurk( role, **kwargs):
    try:
        type = kwargs['type']
    except KeyError:
        type='udp'
    try:
        ip_address = kwargs['ip_address']
    except KeyError:
        ip_address = '127.0.0.1'
    try:
        port=kwargs['port']
    except KeyError:
        port = 6789
    try:
        background = kwargs['background']
    except KeyError:
        background = True

    conf = LurkConf( )
    conf.set_role( role )
    conf.set_connectivity( type='udp', ip_address="127.0.0.1", port=6789 )
    if role == 'client':
        print("Setting client %s"%type)
        if type == 'udp':
            return LurkUDPClient(conf = conf.conf)
        elif type == 'tcp':
            return LurkTCPClient(conf = conf.conf)
        else: 
            print("UNKNOWN type: %s for client"%type)
    elif role == 'server':
        print("Setting server %s"%type)
        if type == 'udp' and background == True: 
            p = mp.Process(target=LurkUDPServer, args=(conf.conf,),\
                   kwargs={'thread' : 40}, name="udp server", daemon=True )
            p.start()
            return p
        if type == 'udp' and background == False: 
            LurkUDPServer(conf.conf, thread=False) 
        elif type == 'tcp' and background == True:
            p = mp.Process(target=LurkTCPServer, args=(conf.conf,),\
                   kwargs={'thread' : 40}, name="udp server", daemon=True )
            p.start()
            return p
        if type == 'tcp' and background == False: 
             LurkTCPServer(conf.conf, thread=False) 

        else: 
            print("UNKNOWN type: %s for server"%type)


def test_basic_exchanges(type):

    server = set_lurk('server', type=type)
    sleep(5)
    client = set_lurk('client', type=type)
    
    designation = 'tls12'
    version = 'v1'
    
    for mtype in [ 'rsa_master', 'ecdhe', 'ping', 'rsa_extended_master', \
                   'capabilities']:
        if mtype in [ 'ping', 'capabilities' ]:
            resolve_exchange( client, designation, version, mtype,\
                              payload={}, silent=True )
            continue
        for freshness_funct in [ "null", "sha256" ]:
            print("---- %s, %s"%(mtype, freshness_funct))
            resolve_exchange(client, designation, version, mtype,
                   payload={ 'freshness_funct' :freshness_funct}, silent=False)
    
    server.terminate()

if __name__ == "__main__":
    print( "+-------------------------------------------------------+" )
    print( "|    UDP  LURK CLIENT / SERVER - MULTI-Threads TESTS    |" )
    print( "+-------------------------------------------------------+" )

    test_basic_exchanges('udp')
    sleep(5)

    print( "+-------------------------------------------------------+" )
    print( "|    TCP  LURK CLIENT / SERVER - MULTI-Threads TESTS    |" )
    print( "+-------------------------------------------------------+" )

    test_basic_exchanges('tcp')
    sleep(5)
#conf = LurkConf( )
#conf.set_role( 'server' )
#conf.set_connectivity( type='tcp', ip_address="127.0.0.1", port=6789 )
#LurkTCPServer(conf=conf.conf, thread=40)

#p = mp.Process( target=LurkTCPServer, args=(conf.conf,),\
#                kwargs={'thread' : 40}, name="tcp server", daemon=True )
#p.start()
#
#import time
#time.sleep(5)
#
#import socket
#host= "127.0.0.1"
#port = 6789
#sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sock.connect((host, port))
#
#server = set_lurk('server', type='tcp')
#client = set_lurk('client', type='tcp')
    
    
    print( "+--------------------------------------------------------+" )
    print( "|    HTTPS  LURK CLIENT / SERVER  - MULTI-Threads TESTS  |" )
    print( "+--------------------------------------------------------+" )
    
    
    print("-- Starting LURK HTTPS Clients")
    clt_conf = LurkConf( )
    clt_conf.set_role( 'client' )
    clt_conf.set_connectivity( type='tcp', ip_address="127.0.0.1", port=6789 ) #keep to tcp?
    client = LurkHTTPClient( conf = clt_conf.conf, secureTLS_connection=True )
    
    print("-- Starting LURK HTTPS Server")
    srv_conf = LurkConf()
    srv_conf.set_role( 'server' )
    srv_conf.set_connectivity( type='tcp', ip_address="127.0.0.1", port=6789 )#keep to tcp?
    
    lurkHttpsServer = ThreadedLurkHTTPserver(srv_conf.conf, max_workers=7 , secureTLS_connection=True)
    t = threading.Thread( target=lurkHttpsServer.serve_forever)
    
    t.daemon = True
    t.start()
    
    designation = 'tls12'
    version = 'v1'
    
    for mtype in [ 'rsa_master', 'ecdhe', 'ping', 'rsa_extended_master', \
                    'capabilities']:
        if mtype in [ 'ping', 'capabilities' ]:
            resolve_exchange( client, designation, version, mtype, \
                              payload={} )
            continue
        for freshness_funct in [ "null", "sha256" ]:
            resolve_exchange( client, designation, version, mtype, \
                              payload={ 'freshness_funct' : freshness_funct } )
    
    lurkHttpsServer.shutdown()
    lurkHttpsServer.server_close()
## >>>>>>> mlt2-gmlt
