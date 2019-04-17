from  os.path import join
import threading
import pkg_resources
data_dir = pkg_resources.resource_filename( __name__, '../data/')

from pylurk.core.lurk import *
from pylurk.extensions.tls12 import *
from pylurk.extensions.tls12_struct import ProtocolVersion, Random
from pylurk.utils.utils import message_exchange, resolve_exchange,\
                               bytes_error_testing, set_title, \
                               tls12_serve_payloads, set_lurk
from time import time
from secrets import randbits
#import pylurk.tests.tls12_serve_payloads 
import pylurk.tests.tls12_client_server 

print(set_title( "MESSAGE TESTS"))
print("--- Payload Testing: testing build/parse/serve functions" + \
      "--- for queries and response.")
designation = 'tls12'
version = 'v1'

for mtype in [\
 'rsa_master', \
 'ecdhe', 'ping', 
 'rsa_extended_master',  
 'rsa_master_with_poh',  
 'rsa_extended_master_with_poh', 
 'capabilities' 
]:
    message_exchange( designation, version, mtype, payload={} )


tls12_serve_payloads(silent=False)
pylurk.tests.tls12_client_server

print(set_title("ERROR TESTING: LURK CLIENT / SERVER"))
server = LurkServer()
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

print( set_title("DEMO: UDP  LURK Client / Server with Edge Server (RSA)"))

print("-- Starting LURK UDP Server")
server = set_lurk('server', connectivity={'type':'udp'}, background=True)

print("-- Starting LURK UDP Client")

conf = { 'role' : "client",
         'connectivity' : {
             'type' : "udp",  # "udp", "local",
              'ip_address' : "127.0.0.1",
              'port' : 6789,
              'keys': {#TLS keys
                    'client': join( data_dir, 'key_tls12_rsa_client.key'),
                    'server': join( data_dir, 'key_tls12_rsa_server.key'),
                },
              'certs': {#TLS certifications
                    'client': join( data_dir, 'cert_tls12_rsa_client.crt'),
                    'server': join( data_dir, 'cert_tls12_rsa_server.crt'),
              },
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
               'cert' : [ join( data_dir, "cert-rsa-enc.der" ) ],\
               'prf_hash' : ["sha256", "sha384", "sha512"],\
               'cipher_suites' : ["TLS_RSA_WITH_AES_128_GCM_SHA256", \
                            "TLS_RSA_WITH_AES_256_GCM_SHA384"] 
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
rsa_utils = Tls12RsaMasterConf( conf=rsa_conf )


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
resolutions, errors = client.resolve([{'designation':'tls12', \
                                  'version':'v1', 'status':"request", \
                                  'type':'rsa_master', \
                                  'payload':payload_args}])
query = resolutions[0][0]
response = resolutions[0][1]
print("LURK Query >>>>")
msg.show(query)
print("LURK Response <<<<")
msg.show(response)
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

server.terminate()


print( "+---------------------------------------+" )
print( "|      UDP  LURK Client / Server        |" )
print( "|      Edge Server Integration (ECDHE)  |" )
print( "+---------------------------------------+" )

print("-- Starting LURK UDP Server")
server = set_lurk('server', connectivity={'type':'udp'}, background=True)
print("-- Starting LURK UDP Client")

conf = { 'role' : "client",
         'connectivity' : {
             'type' : "udp",
              'ip_address' : "127.0.0.1",
              'port' : 6789,
              'keys': {#TLS keys
                    'client': join( data_dir, 'key_tls12_rsa_client.key'),
                    'server': join( data_dir, 'key_tls12_rsa_server.key'),
                },
              'certs': {#TLS certifications
                    'client': join( data_dir, 'cert_tls12_rsa_client.crt'),
                    'server': join( data_dir, 'cert_tls12_rsa_server.crt'),
              },
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
               'sig_and_hash' : [('sha256', 'ecdsa' )],
                ## acceptable ecdsa curves when 'ecdsa' is chosen in
                ## 'sig_andhahs'. This parameter must not be specified
                ## when 'rsa' is the only acceptable signature.
               'ecdsa_curves' : ['secp256r1'],
                ## acceptable curves for ecdhe. This is used to check
                ## the provided ecdhe_params before signing those. It is
                ## only required for the server. Client only needs then
                ## when they generate the parameters and SHOULD be omitted
                ## in the configuration.
               'ecdhe_curves' : ['secp256r1'],
                ## defines how proo-of ownership is generated.
               'poo_prf' : [ "null", "sha256_128", "sha256_256" ], 
               'cipher_suites' : ['TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', \
                    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',\
                    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', \
                    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384']
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
ecdhe_utils = Tls12EcdheConf( conf=ecdhe_conf)

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
params = Tls12EcdheRequestPayload().build_payload()
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

resolutions, erros = client.resolve([{'designation':'tls12', 'version':'v1', \
                                      'type':'ecdhe', 'payload':payload_args}])
query = resolutions[0][0]
response = resolutions[0][1]
print("LURK Query >>>>")
msg.show(query)
print("LURK Response <<<<")
msg.show(response)
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

server.terminate()

