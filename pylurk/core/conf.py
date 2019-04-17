from  os.path import join
import pkg_resources
data_dir = pkg_resources.resource_filename(__name__, '../data/')

"""
Structure that provides the various configuration parameters:

Args:
    cert (list): the list of certificates. The list contains a list of
        files name that contains the certificates or the raw keys. By
        convention, a file that contains the string "key" indicates
        that it contains a raw key. A file that contains the string
        "cert" indicates that it contains a x509 certificate. Unless
        one of these string is found in the file name, the file is
        assumed to contain a x509 certificate. Type of the certificate
        is required as the capability provides tehtype.


"""


default_conf = {
    'role' : 'server', # "client", "server"
    'connectivity' : {
        'type' : "udp",  # "local", "tcp", "tcp+tls", http, https
        'ip_address' : "127.0.0.1",
        'port' : 6789,
        'key' : join(data_dir, 'key_tls12_rsa_server.key'),
        'cert' : join(data_dir, 'cert_tls12_rsa_server.crt'),
        'key_peer' : join(data_dir, 'key_tls12_rsa_client.key'),
        'cert_peer' : join(data_dir, 'cert_tls12_rsa_client.crt')
#        'keys': {#TLS keys
#              'client': join(data_dir, 'key_tls12_rsa_client.key'),
#              'server': join(data_dir, 'key_tls12_rsa_server.key'),
#          },
#        'certs': {#TLS certifications
#              'client': join(data_dir, 'cert_tls12_rsa_client.crt'),
#              'server': join(data_dir, 'cert_tls12_rsa_server.crt'),
#        },
        },
    'extensions' : [
        {'designation' : "lurk",
         'version' : "v1",
         'type' : 'ping',
        },
        {'designation' : "lurk",
         'version' : "v1",
         'type' : 'capabilities',
        },
        {'designation' : "tls12",
         'version' : "v1",
         'type' : 'ping',
        },
        {'designation' : "tls12",
         'version' : "v1",
         'type' : 'capabilities',
        },

        {'designation' : "tls12",
         'version' : "v1",
         'type' : "rsa_master",
         'key_id_type' : ["sha256_32"],
         'freshness_funct' : ["null", "sha256"],
         'prf_hash' : ["sha256", "sha384", "sha512"],
         'random_time_window' : 5,
         'check_server_random' : True,
         'check_client_random' : False,
         'cert' : [join(data_dir, 'cert-rsa-enc.der')],
         'key' : [join(data_dir, 'key-rsa-enc-pkcs8.der')],
         'cipher_suites' : ["TLS_RSA_WITH_AES_128_GCM_SHA256", \
                            "TLS_RSA_WITH_AES_256_GCM_SHA384"]
        },
        {'designation' : "tls12",
         'version' : "v1",
         'type' : "rsa_master_with_poh",
         'key_id_type' : ["sha256_32"],
         'freshness_funct' : ["null", "sha256"],
         'prf_hash' : ["sha256", "sha384", "sha512"],
         'random_time_window' : 5,
         'check_server_random' : True,
         'check_client_random' : False,
         'cert' : [join(data_dir, 'cert-rsa-enc.der')],
         'key' : [join(data_dir, 'key-rsa-enc-pkcs8.der')],
         'cipher_suites' : ["TLS_RSA_WITH_AES_128_GCM_SHA256", \
                            "TLS_RSA_WITH_AES_256_GCM_SHA384"]
        },
        {'designation' : "tls12",
         'version' : "v1",
         'type' : "rsa_extended_master",
         'key_id_type' : ["sha256_32"],
         'freshness_funct' : ["null", "sha256"],
         'prf_hash' : ["sha256", "sha384", "sha512"],
         'random_time_window' : 5,
         'check_server_random' : True,
         'check_client_random' : False,
         'cert' : [join(data_dir, 'cert-rsa-enc.der')],
         'key' : [join(data_dir, 'key-rsa-enc-pkcs8.der')],
         'cipher_suites' : ["TLS_RSA_WITH_AES_128_GCM_SHA256", \
                            "TLS_RSA_WITH_AES_256_GCM_SHA384"]
        },
        {'designation' : "tls12",
         'version' : "v1",
         'type' : "rsa_extended_master_with_poh",
         'key_id_type' : ["sha256_32"],
         'freshness_funct' : ["null", "sha256"],
         'prf_hash' : ["sha256", "sha384", "sha512"],
         'random_time_window' : 5,
         'check_server_random' : True,
         'check_client_random' : False,
         'cert' : [join(data_dir, 'cert-rsa-enc.der')],
         'key' : [join(data_dir, 'key-rsa-enc-pkcs8.der')],
         'cipher_suites' : ["TLS_RSA_WITH_AES_128_GCM_SHA256", \
                            "TLS_RSA_WITH_AES_256_GCM_SHA384"]
        },
        {'designation' : "tls12",
         'version' : "v1",
         'type' : "ecdhe",
         'key_id_type' : ["sha256_32"],
         'freshness_funct' : ["null", "sha256"],
         'random_time_window' : 5,
         'check_server_random' : True,
         'check_client_random' : False,
         'cert' : [join(data_dir, "cert-ecc-sig.der")],
         'key' : [join(data_dir, "key-ecc-sig-pkcs8.der")],
         'sig_and_hash' : [('sha256', 'rsa'), ('sha512', 'rsa'),\
                            ('sha256', 'ecdsa'), ('sha512', 'ecdsa')],
         ## acceptable ecdsa curves when 'ecdsa' is chosen in
         ## 'sig_andhahs'. This parameter must not be specified
         ## when 'rsa' is the only acceptable signature.
         'ecdsa_curves' : ['secp256r1', 'secp384r1', 'secp521r1'],
         ## acceptable curves for ecdhe. This is used to check
         ## the provided ecdhe_params before signing those. It is
         ## only required for the server. Client only needs then
         ## when they generate the parameters and SHOULD be omitted
         ## in the configuration.
         'ecdhe_curves' : ['secp256r1', 'secp384r1', 'secp521r1'],
         ## defines how proo-of ownership is generated.
         'poo_prf' : ["null", "sha256_128", "sha256_256"],
         'cipher_suites' : ['TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', \
                             'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',\
                             'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', \
                             'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384']
        }]
}
