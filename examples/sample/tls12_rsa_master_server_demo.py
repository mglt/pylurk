"""This scripts has been generated the demonstrate how the LURK
extension for TLS 1.2 works. The example details the RSA Master
authentication. 

The default configuration is in core/conf.py

"""

from pylurk.core.lurk import LurkUDPServer
from pylurk.core.conf import default_conf

conf = default_conf
conf[ 'role' ] = 'server'
conf[ 'connectivity' ][ 'type' ] = 'udp'
extensions = []
for ext in conf[ 'extensions' ]:
    try:
        ext[ 'random_time_window' ] = 0
        ext[ 'check_server_random' ] = False
        ext[ 'check_client_random' ] = False
    except KeyError:
        pass

print("Server started with configuration below:")
print("    - role: %s"%conf[ 'role' ])
print("    - connectivity: %s"%conf[ 'connectivity'] )
print("    - extensions:")
for e in conf[ 'extensions' ]:
    d = e[ 'designation' ]
    v = e[ 'version' ]
    t = e[ 'type' ] 
    print("        - %s, %s, %s"%(d, v, t))
    if d == "tls12" and v == "v1" and t == "rsa_master" :
        for k in [ 'designation', 'version', 'type', 'key_id_type',\
                    'freshness_funct', 'random_time_window', 'check_server_random',\
                    'check_client_random', 'cert', 'key' ] :
            print("             > %s: %s"%(k, e[ k ]) )
print("\n")
print("UDP Server listening...")
LurkUDPServer(conf=conf)





