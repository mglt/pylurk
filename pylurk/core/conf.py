from  os.path import join
import pkg_resources
data_dir = pkg_resources.resource_filename( __name__, '../data/')


default_conf = { 
    'role' : "server",  # "client", "server"
         'connectivity' : { 
             'type' : "udp",  # "udp", "local", 
              'ip_address' : "127.0.0.1", 
              'port' : 6789, 
         },       
    'extensions' : [
        { 'designation' : "lurk",
          'version' : "v1", 
          'type' : 'ping', 
        }, 
        { 'designation' : "lurk",
          'version' : "v1", 
          'type' : 'capabilities', 
        }, 
        { 'designation' : "tls12",
          'version' : "v1", 
          'type' : 'ping', 
        }, 
        { 'designation' : "tls12",
          'version' : "v1", 
          'type' : 'capabilities', 
        }, 

        { 'designation' : "tls12", 
          'version' : "v1", 
          'type' : "rsa_master",
          'key_id_type' : [  "sha256_32" ], 
          'tls_version' : [ "TLS1.2" ],
          'prf' : [ "sha256_null", "sha256_sha256" ], 
          'random_time_window' : 5, 
          'check_server_random' : True, 
          'check_client_random' : False,
          'cert' : [ join( data_dir, 'cert-rsa-enc.der' ) ], 
          'key' : [ join( data_dir, 'key-rsa-enc-pkcs8.der' ) ]
        }, 
        { 'designation' : "tls12", 
          'version' : "v1", 
          'type' : "rsa_extended_master",
          'key_id_type' : [  "sha256_32" ], 
          'tls_version' : [ "TLS1.2" ],
          'prf' : [ "intrinsic_null", "intrinsic_sha256" ], 
          'cert' : [ join( data_dir, 'cert-rsa-enc.der' ) ], 
          'key' : [ join( data_dir, 'key-rsa-enc-pkcs8.der' ) ]
        }, 
        { 'designation' : "tls12", 
          'version' : "v1", 
          'type' : "ecdhe",
          'key_id_type' : [  "sha256_32" ], 
          'tls_version' : [ "TLS1.2" ],
          'prf' : [ "intrinsic_null", "intrinsic_sha256" ], 
          'random_time_window' : 5, 
          'check_server_random' : True, 
          'check_client_random' : False,
          'cert' : [ join( data_dir, "cert-ecc-sig.der" ) ], 
          'key' : [ join( data_dir, "key-ecc-sig-pkcs8.der" ) ], 
          'sig_and_hash' : [ ( 'sha256', 'rsa' ),       ( 'sha512', 'rsa' ),\
                             ( 'sha256', 'ecdsa' ), ( 'sha512', 'ecdsa' ) ],
           ## acceptable ecdsa curves when 'ecdsa' is chosen in
           ## 'sig_andhahs'. This parameter must not be specified
           ## when 'rsa' is the only acceptable signature.  
          'ecdsa_curves' : ['secp256r1', 'secp384r1', 'secp512r1' ], 
           ## acceptable curves for ecdhe. This is used to check
           ## the provided ecdhe_params before signing those. It is
           ## only required for the server. Client only needs then
           ## when they generate the parameters and SHOULD be omitted
           ## in the configuration. 
          'ecdhe_curves' : ['secp256r1', 'secp384r1', 'secp512r1' ],
           ## defines how proo-of ownership is generated.
          'poo_prf' : [ "null", "sha256_128", "sha256_256" ]
        }
    ]
    }

