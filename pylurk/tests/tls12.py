from  os.path import join
import threading
import pkg_resources
data_dir = pkg_resources.resource_filename( __name__, '../data/')

from pylurk.core.lurk import LurkServer, ImplementationError, LurkMessage, \
                 HEADER_LEN, LurkClient, LurkServer, LurkUDPClient, \
                 LurkUDPServer, LurkConf, UDPServerConf, LurkTCPClient, LurkTCPServer
from pylurk.extensions.tls12 import Tls12RSAMasterConf,  Tls12ECDHEConf, \
                      Tls12RsaMasterRequestPayload,\
                      Tls12ExtMasterRequestPayload,\
                      Tls12ECDHERequestPayload
from pylurk.extensions.tls12_struct import ProtocolVersion, Random
from pylurk.utils.utils import message_exchange, resolve_exchange, bytes_error_testing
from time import time
from secrets import randbits


print( "+---------------------------------------+" )
print( "|             MESSAGE TESTS              |" )
print( "+---------------------------------------+" )



print("--- Payload Testing: testing build/parse/serve functions" + \
      "--- for queries and response.")
designation = 'tls12'
version = 'v1'

for mtype in [ 'rsa_master', 'ecdhe', 'ping', 'rsa_extended_master' ]:
             #'capabilities' ]:
    message_exchange( designation, version, mtype, payload={} )



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

designation = 'tls12'
version = 'v1'

for mtype in [ 'rsa_master', 'ecdhe', 'ping', 'rsa_extended_master' ]: #, \
#######               'capabilities' ]:
    if mtype in [ 'ping', 'capabilities' ]:
        resolve_exchange( client, server, designation, version, mtype, \
                          payload={} )
        continue
    for freshness_funct in [ "null", "sha256" ]:
        resolve_exchange( client, server, designation, version, mtype, \
                          payload={ 'freshness_funct' : freshness_funct } )

print( "+---------------------------------------+" )
print( "|       LURK CLIENT / SERVER TESTS      |" )
print( "|          --- Error Testing ---        |" )
print( "+---------------------------------------+" )

query_ref_bytes = LurkMessage().build( designation='tls12', version='v1',\
                   status="request", type='rsa_master' )

rsa_query_error = [\
("Invalid Key Type",             HEADER_LEN + 0,  HEADER_LEN + 0,  "invalid_key_id_type"), \
("Invalid Key Id",               HEADER_LEN + 1,  HEADER_LEN + 4,  "invalid_key_id" ) ,\
("Invalid Client Random (Time)", HEADER_LEN + 5,  HEADER_LEN + 8,  "invalid_tls_random" ), \
("Invalid Server Random (Time)", HEADER_LEN + 37, HEADER_LEN + 40, "invalid_tls_random" ), \
("Invalid TLS Version",          HEADER_LEN + 69, HEADER_LEN + 70, "invalid_tls_version"), \
("Invalid PRF",                  HEADER_LEN + 71, HEADER_LEN + 71, "invalid_prf"),\
("Invalid Encrypted PreMaster",  HEADER_LEN + 72, HEADER_LEN + 80, "invalid_encrypted_premaster")\
]

bytes_error_testing( server, query_ref_bytes, rsa_query_error)

print( "+---------------------------------------+" )
print( "|    UDP  LURK CLIENT / SERVER TESTS    |" )
print( "+---------------------------------------+" )


print("-- Starting LURK UDP Client")
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
#t = threading.Thread( target=LurkUDPServer, kwargs={ 'conf' : srv_conf.conf } )
t = threading.Thread( target=updServer.serve_client)#single thread (no parallelism)
t.daemon = True
t.start()

designation = 'tls12'
version = 'v1'

for mtype in [ 'rsa_master', 'ecdhe', 'ping', 'rsa_extended_master', \
               'capabilities' ]:
    if mtype in [ 'ping', 'capabilities' ]:
        resolve_exchange( client, server, designation, version, mtype, \
                          payload={} )
        continue
    for freshness_funct in [ "null", "sha256" ]:
        resolve_exchange( client2, server, designation, version, mtype, \
                          payload={ 'freshness_funct' : freshness_funct } )


print( "+---------------------------------------+" )
print( "|      UDP  LURK Client / Server        |" )
print( "|      Edge Server Integration (RSA)    |" )
print( "+---------------------------------------+" )


print("-- Starting LURK UDP Client")

conf = { 'role' : "client",
         'connectivity' : {
             'type' : "udp",  # "udp", "local",
              'ip_address' : "127.0.0.1",
              'port' : 6789,
        },
        'extensions' : [
             { 'designation' : "tls12",
               'version' : "v1",
               'type' : "rsa_master",
               'key_id_type' : [  "sha256_32" ],
               'freshness_funct' : [ "sha256" ],
               'random_time_window' : 0,
               'check_server_random' : True,
               'check_client_random' : False,
               'cert' : [ join( data_dir, "cert-rsa-enc.der" ) ],
#               'key' : [ "key-rsa-enc-pkcs8.der" ],
             }] }
client = LurkUDPClient( conf=conf )

## creating utils for the demo
## LurkMessage is used to build LURK messages and printing them
## rsa_conf is the default rsa configuration parameters for LURK
## rsa_utils is a tool box for RSA, it is used to simulate the various
## involved values and parameters.
msg = LurkMessage()
rsa_conf = LurkConf( conf=conf ).get_type_conf( 'tls12', 'v1', 'rsa_master')[0]
rsa_utils = Tls12RSAMasterConf( conf=rsa_conf )


def pretty_print( struct, value):
    return struct.parse(struct.build( value ) )

print("TLS Client          Edge Server         Key Server\n")

print("================ Edge Server receives ClientHello")
print("ClientHello")
print("   server_version")
print("   client_random")
print("   cipher_suite")
print("       TLS_RSA_*, ...")
print("-------->")

print("================ Edge Server reads from ClientHello")
#tls_version = ProtocolVersion.parse( ProtocolVersion.build( {} ) )
tls_version = rsa_utils.default_tls_version()
#print("    - server_version: %s"%\
#    pretty_print(ProtocolVersion.build, tls_version ) )
client_random = rsa_utils.default_random()
print("    - client_random: %s"%\
    pretty_print(Random, client_random ) )
print("================ Edge Server builds ServerHello")
print("== LURK impacts sever_random generation")
edge_server_random = rsa_utils.default_random()
print("    - LURK server_random: %s"%\
    pretty_print(Random, edge_server_random ) )
server_random = rsa_utils.pfs( edge_server_random , "sha256" )
print("    - TLS server_random: %s"%\
    pretty_print(Random, server_random ) )
print("================ Edge Server sends ServerHello")
print("                    ServerHello")
print("                        tls_version")
print("                        server_random (TLS)")
print("                        Cipher_suite=TLS_RSA")
print("                    Certificate")
print("                        RSA Public Key")
print("                    ServerHelloDone")
print("                    <--------")
print("================ Edge Server receives ClientKeyExchange")
print("ClientKeyExchange")
print("    EncryptedPremasterSecret")
print("================ Edge Server reads from ClientKeyExchange")
request = msg.build_payload( designation='tls12', version='v1', \
                             status='request', type='rsa_master', \
                             payload= {})
encrypted_premaster = request[ 'payload' ][ 'encrypted_premaster' ]
print("    - encrypted_premaster:%s"% encrypted_premaster )
print("================ LURK Exchange between Edge Server and Key Server")
payload_args = { 'cert' : conf[ 'extensions' ][0][ 'cert' ][0],\
                 'client_random' : client_random, \
                 'server_random' : edge_server_random, \
                 'freshness_funct' : conf[ 'extensions' ][0][ 'freshness_funct' ][0],
                 'encrypted_premaster' : encrypted_premaster }
query, response = client.resolve( designation='tls12', \
                                  version='v1', \
                                  type='rsa_master', \
                                  payload=payload_args )
print("LURK Query >>>>")
msg.show( query )
print("LURK Response <<<<")
msg.show( response )
print("================ Edge Server get the master secret")
print("    - master: %s"%response[ 'payload' ][ 'master' ])

print("================ KEX done between Edge Server and TLS Client")
print("[ChangeCipherSpec]")
print("Finished")
print("-------->")
print("                    [ChangeCipherSpec]")
print("                        Finished")
print("                    <--------")
print("Application Data      <------->     Application Data")




print( "+---------------------------------------+" )
print( "|      UDP  LURK Client / Server        |" )
print( "|      Edge Server Integration (ECDHE)  |" )
print( "+---------------------------------------+" )

print("-- Starting LURK UDP Client")

conf = { 'role' : "client",
         'connectivity' : {
             'type' : "udp",
              'ip_address' : "127.0.0.1",
              'port' : 6789,
        },
        'extensions' : [
             { 'designation' : "tls12",
               'version' : "v1",
               'type' : "ecdhe",
               'key_id_type' : [  "sha256_32" ],
               'freshness_funct' : [ "sha256" ],
               'random_time_window' : 0,
               'check_server_random' : True,
               'check_client_random' : False,
               'cert' : [ join( data_dir + "cert-ecc-sig.der" ) ],
#               'key' : [ "key-ecc-sig-pkcs8.der" ],
#               'cert' : [ "cert-rsa-sig.der" ],
#               'key' : [ "key-rsa-sig-pkcs8.der" ],
               'sig_and_hash' : [ ( 'sha256', 'rsa' ),       ( 'sha512', 'rsa' ),\
                                  ( 'sha256', 'ecdsa' ), ( 'sha512', 'ecdsa' ) ],
                ## acceptable ecdsa curves when 'ecdsa' is chosen in
                ## 'sig_andhahs'. This parameter must not be specified
                ## when 'rsa' is the only acceptable signature.
               'ecdsa_curves' : ['secp256r1', 'secp384r1', 'secp512r1'],
                ## acceptable curves for ecdhe. This is used to check
                ## the provided ecdhe_params before signing those. It is
                ## only required for the server. Client only needs then
                ## when they generate the parameters and SHOULD be omitted
                ## in the configuration.
               'ecdhe_curves' : ['secp256r1', 'secp384r1', 'secp512r1' ],
                ## defines how proo-of ownership is generated.
               'poo_prf' : [ "null", "sha256_128", "sha256_256" ]
             }] }



#print("-- Starting LURK UDP Server")
#srv_conf = dict( conf )
#srv_conf[ 'role' ] = 'server'
#srv_conf[ 'extensions' ][0][ 'key' ] = [  "key-ecc-sig-pkcs8.der" ]

#srv_conf.set_role( 'server' )
#srv_conf.set_connectivity( type='udp', ip_address="127.0.0.1", port=6789 )

#t = threading.Thread( target=LurkUDPServer, kwargs={ 'conf' : srv_conf } )
#t.daemon = True
#t.start()


client = LurkUDPClient( conf=conf )

msg = LurkMessage()
ecdhe_conf = LurkConf( conf=conf ).get_type_conf( 'tls12', 'v1', 'ecdhe')[0]
ecdhe_utils = Tls12ECDHEConf( conf=ecdhe_conf)

mtype ='echde'

print("TLS Client          Edge Server         Key Server\n")
print("================ Edge Server receives ClientHello")
print("ClientHello")
print("   tls_version")
print("   client_random")
print("   cipher_suite")
print("       TLS_ECDHE_ECDSA_*, TLS_ECDHE_RSA_*, ...")
print("       Extension Supported EC, Supported Point Format")
print("-------->")
print("================ Edge Server reads from ClientHello")
tls_version = ecdhe_utils.default_tls_version()
print("    - server_version: %s"%tls_version)
client_random = ecdhe_utils.default_random()
print("    - client_random: %s"%client_random)
print("================ Edge Server builds ServerHello Random")
print("== LURK impacts sever_random generation")
edge_server_random = ecdhe_utils.default_random()
server_random = ecdhe_utils.pfs( edge_server_random , "sha256" )
print("    - server_random: %s"%server_random)
print("================ Edge Server builds ECDHE Parameters and" +\
      "Proof of Ownership")
params = Tls12ECDHERequestPayload().build_payload()
ecdhe_params = params[ 'ecdhe_params' ]
poo_params = params[ 'poo_params' ]
print("    - ecdhe_params: %s"%ecdhe_params )
print("    - poo_params: %s"%poo_params )
print("================ LURK Exchange between Edge Server and Key Server")

payload_args = {'server_random' : edge_server_random, \
         'client_random' : client_random,\
         'tls_version' : tls_version, \
         'echde_params' : ecdhe_params, \
         'poo_params' : poo_params }

request, response = client.resolve( designation='tls12', \
                                  version='v1', \
                                  type='ecdhe', \
                                  payload=payload_args )
print("LURK Query >>>>")
msg.show( request )
print("LURK Response <<<<")
msg.show( response )
print("================ Edge Server get the signed_params")
print("    - master: %s"%response[ 'payload' ][ 'signed_params' ])

print("================ Terminating KEX between Edge Server and TLS Client")
print("")
print("                       ServerHello")
print("                           edge_server_version")
print("                           edge_server_random")
print("                           Cipher_suite=TLS_ECDHE_ECDSA")
print("                           Extension Supported EC,")
print("                           Supported Point Format")
print("                       Certificate")
print("                           ECDSA Public Key")
print("                       ServerKeyExchange")
print("                           ecdhe_params")
print("                           signature")
print("                       ServerHelloDone")
print("                       <--------")
print("   ClientKeyExchange")
print("   [ChangeCipherSpec]")
print("   Finished")
print("   -------->")
print("                       [ChangeCipherSpec]")
print("                       Finished")
print("                       <--------")
print("   Application Data      <------->     Application Data")


print( "+---------------------------------------+" )
print( "|      UDP  LURK Client / Server        |" )
print( "|      --- Performance tests ---        |" )
print( "+---------------------------------------+" )

clt_conf = LurkConf( )
clt_conf.set_role( 'client' )
clt_conf.set_connectivity( type='udp', ip_address="127.0.0.1", port=6789 )
client = LurkUDPClient( conf = clt_conf.conf )


x = 0
mtypes = [ 'ping', 'rsa_master', 'rsa_extended_master', 'ecdhe' ]
for mtype in mtypes:
    payload = {}
    time_start = time()
    for i in range(x):
        request, response = client.resolve( designation='tls12', \
                                  version='v1', \
                                  type=mtype, \
                                  payload=payload )
    time_stop = time()
    print("%s %s resolutions in %s sec."%( x, mtype, (time_stop - time_start) ) )

print( "+---------------------------------------+" )
print( "|      LURK vs openssl -- vector test   |" )
print( "+---------------------------------------+" )


#
#print("-- UDP Server Configuration")
#network_udp = NetworkUDPConf()
#network_udp.ip_address = "127.0.0.1"
#network_udp.port = 6790
#
#lurk = LurkConf()
#lurk.mtype = { ("lurk", "v1") : [ "capabilities", "ping", "error"], \
#               ("tls12", "v1"): [ "rsa_master" ] }
#
#rsa = Tls12RSAMasterConf()
#rsa.role = "server"
#rsa.key_id_type = [ "sha256_32" ]
#rsa.tls_version = [ "TLS1.2" ]
#rsa.prf = [ "sha256_null" ]
#rsa.random_window_time = 0
#cert_dir = "/home/emigdan/gitlab/pylurk/test/"
#rsa.serverX509Cert =  [ join( cert_dir, "serverX509Cert.pem") ]
#rsa.serverX509Key =  [ join( cert_dir, "serverX509Key.pem") ]
#
#srv_conf = update_conf( [ network_udp, lurk, rsa ] )
#
#print("-- Starting LURK UDP Server")
#t = threading.Thread( target=LurkUDPServer, kwargs= { 'conf' : srv_conf } )
#t.daemon = True
#t.start()
#
#print("-- UDP Client Configuration")
#
#lurk.mtype = { ("lurk", "v1") : [ "capabilities", "ping"], \
#               ("tls12", "v1"): [ "rsa_master" ] }
#rsa.role = "client"
#rsa.key_id_type = [ "sha256_32" ]
#rsa.tls_version = [ "TLS1.2" ]
#rsa.prf = [ "sha256_null" ]
#rsa.random_window_time = 0
#cert_dir = "/home/emigdan/gitlab/pylurk/test/"
#rsa.serverX509Cert =  [ join( cert_dir, "serverX509Cert.pem") ]
#
#clt_conf = update_conf( [ network_udp, lurk, rsa ] )
#
#print("-- Starting LURK UDP Client")
#client = LurkUDPClient(conf = clt_conf)
#
#
nginx_encrypted_premaster = \
b'\xe1\x84\x43\x50\xea\xff\xc4\x25\xe1\x50\x00\x19\x18\x39\x0d\xe1\x1b\x38\x54\xb7\x94\x43\x30\xf9\x97\xdc\xf2\x92\x4f\xae\x65\xf8\x27\x16\x95\xf6\xc4\x35\x02\x99\x55\xa4\x11\x45\x86\x6d\x74\xfa\xc5\x23\xe1\xea\xdb\x47\x37\xc4\x55\x34\xf6\xfe\x9f\xab\x48\x78\x85\xcd\xdd\xdd\xfc\x97\x3d\x55\x75\x24\x64\x76\x72\x77\xe1\xe9\xf3\x56\x15\xe4\xb2\xd5\x23\xb8\xa7\xd7\x36\xc6\xe0\x4a\xfe\xa2\xf3\xd1\x1d\xd4\x23\x90\xe7\xbd\xcc\x6b\x6b\x2e\x70\x59\xf7\x34\xfb\x68\xb0\x62\x4d\x32\x0c\x35\x55\x4d\x58\x55\xca\xf0\xa4\xbc\x0b\x40\xeb\x17\x26\x0e\x77\xff\xf7\x06\x42\x06\xe4\xf7\xbd\xbb\xef\xb7\x0a\xde\xec\xba\xab\x69\xf9\x1d\x65\x82\xe6\x9d\xd0\xbb\x7a\x19\xf0\x95\x13\x1e\x31\xea\x25\x27\x10\xcc\x66\x52\xdb\xf6\x00\x5d\x19\xa3\xed\x33\x93\x97\xcd\x70\x5d\x53\x05\xfa\x78\x22\x76\x1e\xea\xed\xaf\x64\x1b\x03\xfb\x34\xfc\x33\x9a\x06\xb5\x76\x6e\xee\x74\x04\x3b\xeb\xa3\x01\xc7\x8b\xde\x86\x4c\xa0\x99\x3d\xcc\x45\x21\x9e\xac\xa7\xfa\x67\x88\x39\xb7\xf6\x32\x38\xd1\x44\x0c\xe5\x19\x9d\xca\x2e\x87\xa3\x2b\x42\x98\x6d\xb2\x30\x85\xe1'

nginx_premaster_secret = \
b'\x03\x03\xda\x55\x83\xc7\x55\xd2\xbf\xe2\xff\x9e\x30\xb9\x68\xeb\x45\xd1\xc6\x2e\xad\x8a\xe1\x20\x70\xd8\x76\x9e\x62\x4e\xb4\x80\x7a\x99\xc9\xe0\x5d\x7e\x5c\xfb\xbc\xab\x39\x1e\x09\xbf\x62\x49'
nginx_client_random = \
b'\x5a\x90\x50\x0a\x30\xbf\xc0\x8a\x32\x11\x8c\x55\x68\x14\x12\x12\x9d\x44\xcc\xb1\x73\x32\xc4\x5a\x1f\xc2\x3e\x91\xf0\xf6\x90\x51'
nginx_server_random = \
b'\x5a\x90\x50\x0a\x72\x24\x2a\x3d\x4d\x0f\x2f\x7a\xe0\xd6\x1a\xfb\x37\x9b\x6f\xf3\x4c\xe0\xcc\x2c\xa4\xda\xaa\x66\x8d\xca\x43\xd0'
nginx_master_secret = \
b'\x68\x5a\xe9\xb4\x9c\x4b\xc4\xea\x13\x01\xed\x09\xcd\x67\x1b\x18\xec\x8a\xe3\xa4\x3c\x23\x6e\xec\xa0\xd9\xf9\xfa\xe1\x05\xe7\x86\x23\x2d\x72\x40\x52\xed\xeb\x37\xd0\xa5\xd9\x54\x0c\x95\x99\x36'

measurements = {'nginx_encrypted_premaster' : nginx_encrypted_premaster, \
                'nginx_premaster_secret' : nginx_premaster_secret, \
                'nginx_client_random' : nginx_client_random, \
                'nginx_server_random' : nginx_server_random, \
                'nginx_master_secret' : nginx_master_secret}


print( "+--------------------------------------------------------------+" )
print( "|    TCP  LURK CLIENT / SERVER - One client one server TEST    |" )
print( "+--------------------------------------------------------------+" )


print("-- Starting LURK TCP Client")
clt_conf = LurkConf( )
clt_conf.set_role( 'client' )
clt_conf.set_connectivity( type='tcp', ip_address="127.0.0.1", port=6789 )
client = LurkTCPClient( conf = clt_conf.conf )

print("-- Starting LURK TCP Server")
srv_conf = LurkConf()
srv_conf.set_role( 'server' )
srv_conf.set_connectivity( type='tcp', ip_address="127.0.0.1", port=6789 )
tcpServer = LurkTCPServer (srv_conf.conf)

t = threading.Thread( target=tcpServer.serve_client)
t.daemon = True
t.start()

designation = 'tls12'
version = 'v1'

for mtype in [ 'rsa_master', 'ecdhe', 'ping', 'rsa_extended_master', \
               'capabilities']:
    if mtype in [ 'ping', 'capabilities' ]:
        resolve_exchange( client, tcpServer, designation, version, mtype, \
                          payload={} )
        continue
    for freshness_funct in [ "null", "sha256" ]:
        resolve_exchange( client, tcpServer, designation, version, mtype, \
                          payload={ 'freshness_funct' : freshness_funct } )
