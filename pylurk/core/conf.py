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
        },
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'keys', 
         'public_key' : [join(data_dir, 'cert-rsa-enc.der')], ## certificate chain
         'private_key' : join(data_dir, 'key-rsa-enc.pkcs8'), ## der, pkcs8
         'sig_algo' : ['rsa_pkcs1_sha256', \
                       'rsa_pkcs1_sha384', \
                       'rsa_pkcs1_sha512',\
                       'ecdsa_secp256r1_sha256', \
                       'ecdsa_secp384r1_sha384',\
                       'ecdsa_secp521r1_sha512', \
                       'rsa_pss_rsae_sha256', \
                       'rsa_pss_rsae_sha384', \
                       'rsa_pss_rsae_sha512', \
                       'ed25519', \
                       'ed448', \
                       'rsa_pss_pss_sha256', \
                       'rsa_pss_pss_sha384', \
                       'rsa_pss_pss_sha512' ]
        },
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 's_init_early_secret',
         'session_id' : True, ## session_is are not expected. 
         'client_early_secret_authorized' : True,
         'early_exporter_secret_authorized' : True,
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 's_init_cert_verify',
         'last_exchange' : False,  
         'app_secret_authorized' : True, 
         'exporter_secret_authorized' : True, 
         'ephemeral_methods' : ['no_secret', 'secret_generated', 'secret_provided'],
         'authorized_ecdhe_group' : ['secp256r1', 'secp384r1', 
                                     'secp521r1', 'x25519', 'x448'], 
##         'public_key' : [join(data_dir, 'cert-rsa-enc.der')], ## certificate chain
##         'private_key' : join(data_dir, 'key-rsa-enc.pkcs8'), ## der, pkcs8
##         'sig_algo' : ['rsa_pkcs1_sha256', \
##                       'rsa_pkcs1_sha384', \
##                       'rsa_pkcs1_sha512',\
##                      'ecdsa_secp256r1_sha256', \
##                       'ecdsa_secp384r1_sha384',\
##                       'ecdsa_secp521r1_sha512', \
##                       'rsa_pss_rsae_sha256', \
##                       'rsa_pss_rsae_sha384', \
##                       'rsa_pss_rsae_sha512', \
##                       'ed25519', \
##                       'ed448', \
##                       'rsa_pss_pss_sha256', \
##                       'rsa_pss_pss_sha384', \
##                       'rsa_pss_pss_sha512' ]
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 's_hand_and_app_secret',
         'last_exchange' : False,  
         'app_secret_authorized' : True, 
         'exporter_secret_authorized' : True, 
         'ephemeral_methods' : ['no_secret', 'secret_generated', 'secret_provided'],
         'authorized_ecdhe_group' : ['secp256r1', 'secp384r1', 
                                     'secp521r1', 'x25519', 'x448'], 
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 's_new_ticket',
         'resumption_secret_authorized' : True,
         'max_tickets' : 6, 
##         'max_new_ticket_exchange' : 1, 
         'ticket_life_time' : 172800, # 2d = 2*24*3600 < 2**32-1
         'ticket_nonce_len' : 20,  ## bytes < 255
         'ticket_generation_method': 'ticket', ## versus index 
         'public_key': join(data_dir, 'ticket-cert-rsa-enc.der'), ## one key
         'private_key' : join(data_dir, 'key-rsa-enc.pkcs8'), ## der, pkcs8
         'ticket_len' : 4,  ## bytes < 255
        },
        
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'c_init_cert_verify',
         'ephemeral_methods' : ['secret_provided'],
         'authorized_ecdhe_group' : ['secp256r1', 'secp384r1', 
                                     'secp521r1', 'x25519', 'x448'],
         'last_exchange' : False,  
##         'public_key' : [join(data_dir, 'cert-rsa-enc.der')], ## certificate chain
##         'private_key' : join(data_dir, 'key-rsa-enc.pkcs8'), ## der, pkcs8
##         'sig_algo' : ['rsa_pkcs1_sha256', \
##                       'rsa_pkcs1_sha384', \
##                       'rsa_pkcs1_sha512',\
##                       'ecdsa_secp256r1_sha256', \
##                       'ecdsa_secp384r1_sha384',\
##                       'ecdsa_secp521r1_sha512', \
##                       'rsa_pss_rsae_sha256', \
##                       'rsa_pss_rsae_sha384', \
##                       'rsa_pss_rsae_sha512', \
##                       'ed25519', \
##                       'ed448', \
##                       'rsa_pss_pss_sha256', \
##                       'rsa_pss_pss_sha384', \
##                       'rsa_pss_pss_sha512' ]
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'c_init_post_auth',
         'last_exchange' : False,  
         'ephemeral_methods' : ['secret_provided'], ## MANDATORY
         'authorized_ecdhe_group' : ['secp256r1', 'secp384r1', 
                                     'secp521r1', 'x25519', 'x448'], 
         'last_exchange' : False
##         'public_key' : [join(data_dir, 'cert-rsa-enc.der')], ## certificate chain
##         'private_key' : join(data_dir, 'key-rsa-enc.pkcs8'), ## der, pkcs8
##         'sig_algo' : ['rsa_pkcs1_sha256', \
##                       'rsa_pkcs1_sha384', \
##                       'rsa_pkcs1_sha512',\
##                       'ecdsa_secp256r1_sha256', \
##                       'ecdsa_secp384r1_sha384',\
##                       'ecdsa_secp521r1_sha512', \
##                       'rsa_pss_rsae_sha256', \
##                       'rsa_pss_rsae_sha384', \
##                       'rsa_pss_rsae_sha512', \
##                       'ed25519', \
##                       'ed448', \
##                       'rsa_pss_pss_sha256', \
##                       'rsa_pss_pss_sha384', \
##                       'rsa_pss_pss_sha512' ]
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'c_post_auth',
         'max_post_handshake_authentication' : True
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'c_init_ephemeral',
         'ephemeral_methods' : [ 'secret_generated' ], ## MANDATORY
         'authorized_ecdhe_group' : ['secp256r1', 'secp384r1', 
                                     'secp521r1', 'x25519', 'x448'], 
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'c_init_early_secret',
         'client_early_secret_authorized' : True,
         'early_exporter_secret_authorized' : True,
         'ephemeral_methods' : [ 'no_secret', 'secret_generated' ], ## MANDATORY
         'authorized_ecdhe_group' : ['secp256r1', 'secp384r1', 
                                     'secp521r1', 'x25519', 'x448'], 
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'c_hand_and_app_secret',
         'last_exchange' : False,
         'app_secret_authorized' : True, 
         'exporter_secret_authorized' : True, 
         'resumption_secret_authorized' : True,
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'c_register_ticket',
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'c_post_hand',
        }, 

        ]
}
