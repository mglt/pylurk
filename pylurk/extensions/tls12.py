from os.path import isfile, join
from pylurk.extensions.tls12_struct import *
from pylurk.core.lurk import Error, ConfError, ImplementationError, Payload,\
                 LurkConf, LINE_LEN
from pylurk.extensions.lurk import LurkVoidPayload
from time import time

from secrets import randbits, token_bytes
import tinyec.ec as ec
import tinyec.registry as reg

from Cryptodome.PublicKey import RSA, ECC
from Cryptodome.Hash import HMAC, SHA256, SHA512
from Cryptodome.Signature import pkcs1_15, DSS
from Cryptodome.Cipher import PKCS1_v1_5


## LURKTLS Errors
class UndefinedError(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "undefined_error"

class InvalidPayloadFormat(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_payload_format"

class InvalidKeyIDType(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_key_id_type"

class InvalidKeyID(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_key_id"

#class InvalidTLSVersion(Error):
#    def __init__(self, expression, message):
#        super().__init__(expression, message )
#        self.status = "invalid_tls_version"

class InvalidTLSRandom(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_tls_random"

class InvalidFreshnessFunct(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_freshness_funct"

class InvalidEncryptedPreMaster(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_encrypted_premaster"

class InvalidFinished(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_finished"

class InvalidECType(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_ec_type"

#class InvalidECBasisType(Error):
#    def __init__(self, expression, message):
#        super().__init__(expression, message )
#        self.status = "invalid_ec_basistype"

class InvalidECCurve(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_ec_curve"

#class InvalidECPointFormat(Error):
#    def __init__(self, expression, message):
#        super().__init__(expression, message )
#        self.status = "invalid_ec_point_format"

class InvalidPOOPRF(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_poo_prf"

class InvalidPOO(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_poo"

class InvalidSigAndHash(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_sig_and_hash"



class Tls12Payload(Payload):
    def __init__( self, conf ):
        self.conf = conf
        self.struct = None

    def treat_exception( self, e ):
         if type(e) == MappingError: 
             value = e.args[0].split()[4]
             msg = e.args[0]
             if "KeyPairIDType" in msg :
                 raise InvalidKeyIDType( value, "invalid key_id_type")
##             elif "ProtocolVersionMajor" in msg :
##                 raise InvalidTLSVersion( value, "invalid major version")
##             elif "ProtocolVersionMinor" in msg :
##                 raise InvalidTLSVersion( value, "invalid minor version")
             elif "FreshnessFunct" in msg :
                 raise InvalidFreshnessFunct( value, "invalid PRF")
             elif "ECCurveType" in msg : 
                 raise InvalidECType( value, "invalid EC Type "  +\
                     "Expected 'name_curve' " ) 
             elif "PointConversionForm" in msg:
                 raise InvalidECPointFormat( value, "invalid Point Format " +\
                     "Expected 'uncompress' ")
             elif "NameCurve" in msg :
                 raise InvalidECCurve( value, "invalid name_curve" )
             elif "POOPRF" in msg :
                 raise InvalidPOOPRF( value, "invalid  POO PRF" )
             else:
                 raise ImplementationError( "type(e): %s --- e.args: %s"%\
                     ( type(e),e.args ), "Mapping Error but non LURK Error" )
         elif type(e) in [ ConfError, ImplementationError,
                           UndefinedError, InvalidPayloadFormat, 
                           InvalidKeyIDType, InvalidKeyID,
                           InvalidTLSRandom, 
                           InvalidFreshnessFunct, InvalidECCurve,
                           InvalidECPointFormat, InvalidPOOPRF, InvalidPOO ] :
             pass
         else:
             raise ImplementationError( "type(e): %s --- e.args: %s"%\
                 ( type(e),e.args ), "non LURK Mapping Error" ) 


class Tls12RSAMasterConf:
    """ Provides configuration parameters as well as a set of functions 
    to operate the RSA master exchange. Behavior of these functions 
    depends on the configuration of the service. 
    """

    def __init__(self, conf=LurkConf().get_type_conf( 'tls12', 'v1',
                                              'rsa_master')[0] ):
        """ Provides tool function for the RSA master exchange based on
        the configuration. 
       
        Args:
            conf (:obj: `dict`, optional) the configuration parameters
                associated to the RSA master exchange. The dictionary has 
                the following format: { 'role' : , 'key_id_type' : , 
                'freshness_funct' : , 'random_time_window' : , 'cert' : ,
                'check_server_random' : , 'check_client_random' : , 'key'
                : }. By default the dictionary is provided from the main
                configuration core/conf.py.
        Raises: 
            ConfError if the object cannot be initialized.
       
        """
       
        self.conf_keys = [ 'role', 'key_id_type' , 'freshness_funct', \
                 'random_time_window', 'cert', 'check_server_random',\
                 'check_client_random' ]
        ## private variables, specify the type of key authorized
        self.key_classes = [ 'RsaKey' ]
        self.valid_ciphers = [ "TLS_RSA_WITH_AES_128_GCM_SHA256", \
                               "TLS_RSA_WITH_AES_256_GCM_SHA384" ]
                
        self.check_conf( conf ) 

        self.role = conf[ 'role' ]
        self.cert = conf[ 'cert' ]
        if self.role == "server":
            ## private keys
            self.key =  conf[ 'key' ]
        self.key_id_type = conf[ 'key_id_type' ] 
        self.freshness_funct = conf[ 'freshness_funct' ] 
        self.random_time_window = conf[ 'random_time_window' ]
        ## defines authorized certificates mostly concerns the server or
        ## public keys. X509, asn1 using pem/der are valid formats
        self.cert = conf[ 'cert' ]
        self.check_check_server_random = conf[ 'check_server_random' ]
        self.check_check_client_random = conf[ 'check_client_random' ]

        self.build_key_stores()

    def check_conf( self, conf ):
        """ check configuration parameters. This includes parameters
             associated to capabilities as well as those limited to 
             configuration only. 

            Args:
                conf (dict): the configuration parameters.
            Raises:
                ConfError: If the configuration provided is not valid
        """
        if type( conf ) is not dict:
            raise ConfError( conf, "Expected dictionary" )
        ## defining conf_keys depending on the role. 'server' needs to
        ## be provided a private key.
        if 'role' not in conf.keys():
            raise ConfError( conf, "Expected key 'role'.")
        if conf[ 'role' ] not in [ 'client', 'server' ]:
            raise ConfError( conf, "Expected role value 'client' or 'server' ")
        if conf[ 'role' ] == "server":
            self.conf_keys.append( 'key' )
        ## checking all conf_keys have been provided
        if set( conf.keys() ) != set( self.conf_keys ):
            raise ConfError( conf.keys(), "Conf keys mismatch. " + \
                      "Expected keys: %s"%self.conf_keys )
        ## checking value provided by conf for each key_conf
        try :
            for k in self.conf_keys:
                if k in [ 'key_id_type' , 'freshness_funct', 'cert', 'key']:
                    if type( conf[ k ] ) is not list:
                        raise ConfError( conf[ k ], "Expected list" )
                if k == 'key_id_type':
                    [ KeyPairIDType.build( i ) for i in conf[ k ] ]
                if k == 'freshness_funct': 
                    [ FreshnessFunct.build( i ) for i in conf[ k ] ]
                if k in [ 'cert', 'key' ]:
                    for f in conf[ k ]:
                        if isfile( f ) == False:
                            raise ConfError( cert, "Cannot find the file" )
                if k ==  'random_time_window':
                    conf[ k ] = int( conf[ k ] )
                if k in [ 'check_server_random', 'check_client_random' ]:
                    if type( conf[ k ] ) != bool :
                        raise ConfError( k, "Expected boolean value." )
        except :
            raise ConfError( conf, "Unexpected conf value" )
        
##    def check_conf_freshness_funct( self, freshness_funct ):
##        freshness_funct_values = [ "sha256_null", "sha256_sha256" ] 
##        if freshness_funct not in freshness_funct_values : 
##            raise ConfError( freshness_funct, "Expected %s"%freshness_funct_values )
        
##    ### conf  
##    def check_key_id_type( self, key_id_type):
##        if key_id_type not in self.key_id_type :
##            raise InvalidKeyIDType(key_id_type, "unsupported key_id_type")
         

    def read_key( self, key_source ):
        """ reads and generates key object
   
        Args:
            key_source: the file containing the key or an RsaKey or
                EccKey object.

        Returns:
            key: the RsaKey or EccKey when possible. 

        Raises:
            ConfError: when the class of the key is not permitted by the
                configuration.  

        """
        if key_source.__class__.__name__ in self.key_classes:
            return key_source
        elif type( key_source ) is bytes:
            pass
        elif isfile( str(key_source) ) :
            with open(key_source, 'rb' )  as f:
                key_source = f.read() 
        else:
            raise ConfError(key_source, "unable to read key [ %s ]"\
                      %self.key_classes )
        try:
            return RSA.import_key( key_source )
        except :
            return ECC.import_key( key_source )
##        elif key_source.__class__.__name__ in [ 'RsaKey', 'EccKey' ]:

    def build_key_id( self, key, key_id_type="sha256_32"):
        """ builds and return the key id structure.

        Args:
            key: file or key object (RsaKey or EccKey)
            key_id_type (str, optional): the type of id. Set to
                "sha256_32" by default. 

        Returns:
            dict: a dictionary that represents the key_id:
                {'key_id_type' : key_id_type, 'key_id': key_id }. Note
                that the key_id structure and the hash of the key are 
                represented as the key_id.   

        Raises:
            ConfError: when key_id_type or the key cannot be read.
        """

        self.check_key_id_type( key_id_type )

## if isfile( str( key) ) == True:
        key = self.read_key( key )
        key_type =  key.__class__.__name__  

        if key_type not in self.key_classes :
            raise ConfError(key_type, "unsupported key_type" +\
                  "Expecting %s"%self.key_classes )
        if key_type == 'RsaKey':
            bytes_key =  key.exportKey('DER') 
        elif key_type == 'EccKey':
            bytes_key =  key.export_key(format='DER')
        else:
            raise ConfError(key_type, "unsupported key_type" +\
                  "Expecting [ 'RsaKey', 'EccKey' ]")
        if key_id_type == "sha256_32":
            key_id = SHA256.new( bytes_key ).digest()[:4]
        else:
            raise ConfError(key_id_type, "unsupported key_id_type " +\
                                          "expected sha256_32")
        return  {'key_id_type' : key_id_type, 'key_id': key_id }

    def build_public_key_db(self):
        """ builds a database of available public keys. 

        Public Keys are read from self.cert and indexed by the binary 
        representation of the key_id structure (key_id_type, key_id)

        Returns: 
            db (dict): a dictionary { key_id : public_key } where key_id
                is the binary representation of the key_id.

        Raises:
            ConfError: when the key cannot be parsed or read or when the
                key is not public. 
        """
        db = {}
        for key_file in self.cert:
            public_key = self.read_key( key_file )
            if public_key.has_private() == True:
                raise ConfError( private, "only public keys are expected")
            for key_id_type in self.key_id_type:
                key_id = self.build_key_id( public_key, key_id_type=key_id_type )
                db[ KeyPairID.build(key_id) ] = public_key
        return db


    def build_private_key_db(self):
        """ builds a database to bind the key_id  with private key 

        Privates Keys are read from self.keys, checked against the
        corresponding Public Key and indexed with the binary format 
        of the key_id of the corresponding Public Key. 

        Returns:
            db (dict): the dictionary { key_id(public): private key },
                where key_id is the binary representation of the key_id 
                associated to the Public Key.
        Raises: 
            ConfError: when keys cannot be read properly, when public
                and private keys do not match...
        """
        db = {}
        for path in list( zip( self.cert, self.key ) ):
            public_key = self.read_key( path[0] )
            private_key = self.read_key( path[1] )
            ## checking key pair
            public_class = public_key.__class__.__name__
            private_class = private_key.__class__.__name__
             
            if public_class != private_class:
                raise ConfError( (public_class, private_type) ,\
                       "public / private key of different classes" )
            if public_class not in self.key_classes :
                raise ConfError( public_class  , "not acceptable key class" )

            message = b'test message to be signed'
            h = SHA256.new( message )
            if public_class == 'RsaKey':  
                signature = pkcs1_15.new(private_key).sign(h)
                try:
                    pkcs1_15.new(public_key).verify(h, signature)
                except (ValueError, TypeError):
                    raise ConfError( path , "non matching public / private key" )
            elif public_class == 'EccKey':
                signer = DSS.new(private_key, 'fips-186-3')
                signature = signer.sign( h )
                verifier = DSS.new( public_key, 'fips-186-3')
                try:
                    verifier.verify(h, signature)
                except (ValueError, TypeError):
                    raise ConfError( path , "non matching public / private key" )
            else:
                raise ConfError(key_type, "unsupported key_type expected" +\
                                          " 'RsaKey' and 'EccKey' ")
            for key_id_type in self.key_id_type:
                key_id = self.build_key_id( public_key )
                db[ KeyPairID.build(key_id) ] = private_key
        return db


    def get_private_key_from(self, key_id):
        """ Returns the private key from key_id of the corresponding
        public_key.

        Args:
           key_id (dict): the dictionary representing the key_id
               structure.         
 
        Returns:
           private_key (obj): the private key object (RsaKey or EccKey)
               that corresponds to the key_id. Note that key_id is the
               value associated to the public key. 

        Raises:
            InvalidKeyIDType: when the key_id_type is not supported.
            InvalidKeyID: when another error occurs.
        """
        try :
            self.check_key_id_type( key_id[ 'key_id_type' ] )
            return self.private_key_db[ KeyPairID.build( key_id) ]
        except MappingError as e:
            value = e.args[0].split()[4]
            if "KeyPairIDType" in  e.args[0] :
                raise InvalidKeyIDType(key_id_type, "unable to parse")
        except KeyError :
            raise InvalidKeyID()

    def build_key_stores(self):
        """ Builds the necessary key stores

        LURK Client will only have a a key store of public keys while 
        LURK Servers will have a key store for Public Keys as well as 
        a keystore for private keys. 

        """
        ## building key stores
        self.public_key_db = self.build_public_key_db() 
        if self.role == "server":
            ## binding between key_id (binary value) and corresponding
            ## private key 
            self.private_key_db = self.build_private_key_db()

    def check_key( self, payload, keys):
        """ Checks payload got the expected keys
       
        Args:
            payload (dict): a dictionary representing the structure.
            keys (list): the list of keys that are expected in payload
       
        Raises:
            InvalidPayloadFormat: when a mismatch occurs between payload
                and expected keys. 
        """
        if set( payload.keys() ) != set( keys ):
            raise InvalidPayloadFormat( payload.keys(),   \
                      "Missing or extra key found. Expected %s"%keys)

    def check_key_id_type( self, key_id_type ):
        """ Checks key_id_type is valid

        Args:
            key_id_type (str): the key_id_type value
            
        Returns:
            InvalidKeyIDType: when the key_id_type is not acceptable
        """
        if key_id_type not in self.key_id_type:
            raise InvalidKeyIDType( key_id_type, \
                      "Expected: %s"%self.key_id_type )


    def check_key_id(self, key_id ):
        """ Checks the key_id structure.

        Args:
            key_id (dict): the dictionary representing the key_id
                structure.

        Raises:
            InvalidKeyIDType: when the key_id_type is invalid.
            InvalidKeyID when the structure is not conform.
    
        """

        key_id_keys = [ 'key_id_type', 'key_id' ]
        self.check_key( key_id, key_id_keys )

        self.check_key_id_type( key_id[ 'key_id_type' ] )
        if  KeyPairID.build( key_id ) not in self.public_key_db.keys():
            raise InvalidKeyID( key_id, "Corresponding public key unavailable")

    def check_random(self, random ):
        """ Checks the random structure.

        Args:
            random (dict): dictionary representing the random structure
                { 'gmt_unix_time', gmt_unix_time, 'random': random }.

        Raises:
            InvalidTLSRandom: if the check fails.
        """

        random_keys = [ 'gmt_unix_time', 'random' ]
        self.check_key( random, random_keys )

        if self.random_time_window == 0:
            return True
        current_time = time()
        unix_time = int.from_bytes( random['gmt_unix_time'], byteorder='big' ) 
        if abs( unix_time -  current_time  ) >  self.random_time_window:
            raise InvalidTLSRandom( ( unix_time, current_time ), \
                  "out of time window - (unix time, current time)" +\
                  "delta: %s"%(current_time  - unix_time )+ \
                  "window_time: %s"%self.random_time_window )

    def check_client_random(self, random ):
        """ Checks the client_random

        Checks is performed according to the check_client_random
        parameter of the configuration

        Args:
            random (dict): dictionary representing the random structure
                { 'gmt_unix_time', gmt_unix_time, 'random': random }.

        Raises:
            InvalidTLSRandom: if the check fails.
        """
        if self.check_client_random == True:
            self.check_random( random )



    def check_server_random(self, random ):
        """ Checks the client_random

        Checks is performed according to the check_client_random
        parameter of the configuration

        Args:
            random (dict): dictionary representing the random structure
                { 'gmt_unix_time', gmt_unix_time, 'random': random }.

        Raises:
            InvalidTLSRandom: if the check fails.
        """
        if self.check_server_random == True:
            self.check_random( random )

    def check_tls_version(self, tls_version ):
        """ Checks the tls_version structure

            The tls version in this extension is expected to be TLS 1.2
            The TLS version is checked in the premaster secret.

        Args:
            tls_version (dict): dictionary representing the TLS Version
                structure { 'major': "TLS12M", 'minor' : "TLS12m" } 
        
        Raises: 
            InvalidTLSVersion: when a version mismatch occurs. 

        """
        version_keys = [ 'major', 'minor' ]
        self.check_key( tls_version, version_keys )
        if tls_version[ 'major' ] != "TLS12M" or \
           tls_version[ 'minor' ] != "TLS12m": 
            raise InvalidTLSVersion( tls_version, "expected %s"%self.tls_version )

    def check_freshness_funct( self, freshness_funct ):
        """ Checks the freshness function is valid 

        Args:
            freshness_funct (str): the value of the freshness function

        Raises:
            InvalidFreshnessFunct: when the freshness fucntion is not
                acceptable. 
        """
        if freshness_funct not in self.freshness_funct:
            raise InvalidFreshnessFunct( freshness_funct, \
                "Expected: %s"%self.freshness_funct )

    def check_encrypted_premaster( self, encrypted_master ):
        ## need to add checks on the encrypted_premaster
        ## TO BE DONE, maybe we should add the key as the arguments or
        ## key_id 
        ## if 'encrypted_premaster' not in payload.keys():
        ##    raise InvalidPayloadFormat( payload.keys(), \
        ##              "Expected 'encrypted_premaster'") 
        pass

    def check_session_id( self, session_id ):
        """ Checks the sessionID provides in the ClientHello, ServerHello 

        Args:
            session_id (bytes): the structure representing the SessionID
                structure.
        Raises:
            InvalidPayloadFormat: when the session id does not math the 
                expected structure.
        """
        l = len( session_id ) 
        if l > 32:
            raise InvalidPayloadFormat( session_id, "Expecting length in " +\
                "[0..32], got %s"%l )

    def check_cipher_suites( self, cipher_suites):
        """ Checks cipher_suites contains the appropriated cipher suites 

        Args: 
            cipher_suites (list): the list of cipher suites. 

        Raises:
            InvalidPayloadFormat: when expected cipher suite are not
                part of the list.
        """
        is_valid = False
        for c in cipher_suites:
            if c in self.valid_ciphers:
                is_valid = True
                break
        if is_valid == False:
            raise InvalidPayloadFormat( cipher_suites, "ClientHello " +\
                      "Expecting at least one cipher suite in %s"
                       %self.valid_ciphers )

    def check_compression_methodes( self, compression_methods):
        """ Checks compression_methods contains the appropriated cipher suites 

        Args: 
            cipher_suites (list): the list of cipher suites. 

        Raises:
            InvalidPayloadFormat: when expected cipher suite are not
                part of the list.
        """
        if compression_methods != [ 'null' ]:
            raise InvalidPayloadFormat( compression_methods, \
                      "Expected [ 'null' ]" )
        
    def check_extensions( self, extensions):
        """ Checks expected extensions are provided in the list of
            extensions

        Args:
            extensions (list) : list of extensions

        Raises: 
            InvalidPayloadFormat: when the session id does not math the 
                expected structure.
        """
        pass

    def check_client_hello( self, client_hello ):
        """ Checks the client_hello 

        Args:
            client_hello (dict): dictionary representing the ClientHello
                structure
        
        Raises:
            InvalidPayloadFormat: when an unexpected value is used in the
                structure.
        """
        try: 
            self.check_tls_version( client_hello[ 'client_version' ] )
            self.check_client_random( random = client_hello[ 'random' ] )
            self.check_session_id( client_hello[ 'session_id' ] )
            self.check_cipher_suites( client_hello[ 'cipher_suites' ] )
            self.check_compression_methodes( client_hello[ 'compression_methods' ] )
            self.check_extensions( client_hello[ 'extensions' ] )
        except KeyError:
            raise InvalidPayloadFormat( client_hello, "Expected keys: " +\
                "client_version, random, session_id, cipher_suites, " +\
                "extensions")


    def check_server_hello( self, server_hello ):
        """ Checks the server_hello 

        Args:
            server_hello (dict): dictionary representing the ServerHello
                structure
        
        Raises:
            InvalidPayloadFormat: when an unexpected value is used in the
                structure.
        """
        self.check_tls_version( server_hello[ 'server_version' ] )
        self.check_server_random( server_hello[ 'random' ] )
        if server_hello[ 'cipher_suite' ] not in self.valid_ciphers:
            raise InvalidPayloadFormat( cipher_suites, "ServerHello " +\
                      "Expecting cipher suite in %s"%valid_ciphers )

    def check_certificate( self, certificate):
        """ Checks the certificate 

        Args:
            certificate (dict): dictionary representing the Certificate
                structure
        
        Raises:
            InvalidPayloadFormat: when an unexpected value is used in the
                structure.
        """
        print( "certificate: %s"%certificate )
        cert =  certificate[ 0 ]
        key_id = self.build_key_id( cert, key_id_type=self.key_id_type[0])
        if KeyPairID.build( key_id ) not in self.public_key_db:
            raise InvalidPayloadFormat( certificate, "Invalid certificate")

    def check_client_key_exchange( self, client_key_exchange ):
        """ Checks the client_key_exchange 

        Args:
            client_key_exchange (dict): dictionary representing the
                ClientKeyExchange structure
        
        Raises:
            InvalidPayloadFormat: when an unexpected value is used in the
                structure.
        """
        self.check_encrypted_premaster( client_key_exchange )


    def check_handshake_messages( self, handshake_messages):
        """Checks the handshake messages 

        Args:
            handshake_messages (list): the representation of the handshake
                messages. handshake messages considered are defined in RFC5276 
                section 7.4.9.

        Raises:
            InvalidPayloadFormat: when an unexpected value is the
                handshake messages.
        """
        rsa_handshake = [ 'client_hello', 'server_hello', 'certificate',\
                          'server_hello_done', 'client_key_exchange' ]
        print( "-- check_handshake_messages: %s"%handshake_messages)
        handshake_types = [ m[ 'msg_type' ] for m in handshake_messages ]
        if handshake_types != rsa_handshake: 
            raise InvalidPayloadFormat( handshake_messages, "Invalid " +\
                "types. Expecting %s"%rsa_handshake )

        self.check_client_hello( handshake_messages[ 0 ][ 'body' ] )
        self.check_server_hello( handshake_messages[ 1 ][ 'body' ] )
        self.check_certificate( handshake_messages[ 2 ][ 'body' ] )
        ##self.check_server_hello_done( handshake_messages[ 3 ][ 'body' ] )
        self.check_client_key_exchange( handshake_messages[ 4 ][ 'body' ] )



    def default_public_key( self, **kwargs ):
        """ Takes the public key provided in kwarg and if not provided
            in kwargs than take the public key from the configuration 
            object.

            This is intended for LURK Clients in order to specify the
            public key while sending the request.  
      
       Args:
           kwargs: all arguments

       Returns:
           key (obj): a EccKey or an RsaKey object.
       """

        try:
            key = kwargs[ 'cert' ]
        except KeyError:
            key = self.cert[0]
        return self.read_key( key )


    def default_key_id( self, **kwargs ):
        """ Generates the key_id structure from kwargs. 

        The key_id structure may directly be provided from kwargs or
        generated from default values. 

        Args:
            kwargs: multiple arguments. Arguments are ignored except 
                key_id, or cert.
        Returns:
            key_id (dict) : a dictionary for the key_id structure

        Raises: 
            InvalidKeyID: when the key_id structure cannot be generated.
        """
        try:
            self.check_key_id( kwargs[ 'key_id' ] )
            return kwargs[ 'key_id' ]
        except ( InvalidKeyID, KeyError ) :
            try:
                key = self.default_public_key( **kwargs )
                key_id_type =  kwargs[ 'key_id' ][ 'key_id_type' ]
                return self.build_key_id( key, key_id_type=key_id_type )
            except KeyError:
            ## default value for key can be provided by 'cert'
            ## or read from the configuration 
                key = self.default_public_key( **kwargs )
                return self.build_key_id( key )
                    
    def default_random( self, **kwargs ):
        """ Generates a random structure
          
        this function is used client_random, server_random for LURK as
        well as the random value present in the ClientHello and ServerHello
        structure.  Each if these structures is composed of gmt_unix_time 
        and a random value. The function returns { gmt_unix_time, random}.
        As random may also designate a structure for ClientHello or
        ServerHello, random. This function also returns that structure
        when provided. 
        

        Args:
            kwargs: multiple arguments. Arguments are ignored except 
                random, or gmt_unix_time.
        Returns:
            random (dict): a dictionary for the random structure  
        
        """
        try:
            random = kwargs[ 'random' ]
            if type( random ) in [ dict, Container ]:
                return random
        except KeyError:
            pass
        try:
            gmt = kwargs[ 'gmt_unix_time' ]
        except KeyError:
            gmt = int( time() ).to_bytes(4, byteorder='big')
        try:
            random = kwargs[ 'random' ]
        except KeyError:
            random = token_bytes( 28 ) 
        return { 'gmt_unix_time' : gmt, 'random' : random } 

    def default_client_random(self, **kwargs ):
        """ Generates the client random 

        Args:
            kwargs: multiple arguments. Arguments are ignored except
                client_random. 
        
        Returns:
            client_random (dict): a dictionary of the client random 
                structure  
        """
        try:
            return kwargs[ 'client_random' ]
        except KeyError:
            return self.default_random()
        
    def default_server_random(self, **kwargs ):
        """ Generates the client random 

        Args:
            kwargs: multiple arguments. Arguments are ignored except
                server_random. 
        
        Returns:
            server_random (dict): a dictionary of the server random
                structure. 
        """
        try:
            return kwargs[ 'server_random' ]
        except KeyError:
            return self.default_random()

    def default_tls_version( self, **kwargs ):
        """ Returns the tls_version structure

            The tls version in this extension is expected to be TLS 1.2
            The TLS version is checked in the premaster secret.

        Args:
            kwargs: multiple arguments. Arguments are ignored except
                tls_version, minor, major. 
        Returns:
            tls_version (dict): dictionary representing the TLS Version
                structure { 'major': "TLS12M", 'minor' : "TLS12m" } 
        """
        try: 
            return kwargs[ 'tls_version' ]
        except KeyError:
            try: 
                major = kwargs[ 'major' ]
            except:
                major = "TLS12M"
            try: 
                minor = kwargs[ 'minor' ]
            except:
                minor = "TLS12m"
            return {'major' : major, 'minor' : minor }

    def default_freshness_funct(self, **kwargs ):
        """ Provides the freshness_funct
       
        Args:
            kwargs: multiple arguments. Arguments are ignored except
                freshness_funct.

        Returns:
            freshness_funct (str): the freshness_funct.

        """
        try:
            return  kwargs[ 'freshness_funct' ]
        except: 
            return self.freshness_funct[ 0 ]
        
    def default_encrypted_premaster(self, **kwargs ):
        """ Provides the encrypted master secret

        Args:
            kwargs: multiple arguments. Ignored except
                encrypted_premaster in the case the 'encrypted premaster' is 
                provided. Otherwise the encrypted premaster is generated with
               'premaster' and the public key. When not present the
                premaster is randomly generated. The public key is provided via
                'cert' or the configuration. 

        Returns:
            encrypted_premaster (bytes): the encrypted premaster
        """

        rsa_public_key = self.default_public_key( **kwargs )
         
        try:
            return kwargs[ 'encrypted_premaster' ]
        except KeyError:
            try:
                premaster =  kwargs[ 'premaster' ]
            except KeyError:
                tls_version = { 'major' : "TLS12M", 'minor' : "TLS12m"} 
                premaster = PreMaster.build(\
                    { 'tls_version' : tls_version, \
                      'random' : token_bytes( 46 ) } )
            cipher = PKCS1_v1_5.new(rsa_public_key)      
            return cipher.encrypt( premaster )

    def default_session_id( self, **kwargs ):
        """ Returns the session_id structure

        Args:
            kwargs: multiple arguments. Ignored except session_id.

        Returns: 
            session_id (dict): the dictionary representing the SessionID
                structure.
        """
        try: 
            return kwargs[ 'session_id' ]
        except KeyError:
            return token_bytes( 32 ) 

    def default_cipher_suites( self, **kwargs ):
        """ Returns the ciphers_suites 
        Args:
            kwargs: multiple arguments. Ignored except cipher_suites.

        Returns: 
            cipher_suites (dict): the dictionary representing the
                Ciphersuites structure.
        
        """
        try:
             return kwargs[ 'cipher_suites' ]
        except KeyError:
            return [ c  for c in self.valid_ciphers ]

    def default_extensions( self, **kwargs):
        """ Returns default extensiosn

        Args:
            kwargs: multiple arguments. Ignored except extensions.

        Returns: 
            extensions (dict): the dictionary representing the
                Extensions structure.
        """
        try:
            return kwargs[ 'extensions' ]
        except KeyError:
            return []

    def default_client_hello(self, **kwargs ):
        """ Generates a client_hello structure 

        Args:
            kwargs: multiple arguments. Ignored except
                tls_version, client_random, session_id, cipher_suites,
                compression_methods, extensions. 
      
        Returns:
            client_hello (dict): the dictionary representing the
                ClientHello structure
        """
        try:
            return kwargs[ 'client_hello' ]
        except KeyError:
            return { \
            'client_version' : self.default_tls_version( **kwargs ), \
            'random' : self.default_random( **kwargs ), \
            'session_id' : self.default_session_id( **kwargs ), \
            'cipher_suites' : self.default_cipher_suites( **kwargs ), \
            'compression_methods' : [ "null" ], \
            'extensions' : self.default_extensions( **kwargs ) }


    def default_server_hello(self, **kwargs ):
        """ Generates a server_hello structure 

        Args:
            kwargs: multiple arguments. Ignored except
                tls_version, server_random, session_id, cipher_suites,
                compression_methods, extensions. 
      
        Returns:
            server_hello (dict): the dictionary representing the
                ServerHello structure
        """
        try:
             return kwargs[ 'server_hello' ]
        except KeyError:
            return { \
            'server_version' : self.default_tls_version( **kwargs ), \
            'random' : self.default_random( **kwargs ), \
            'session_id' : self.default_session_id( **kwargs ), \
            'cipher_suite' : self.default_cipher_suites( **kwargs )[ 0 ], \
            'compression_method' : "null", \
            'extensions' : self.default_extensions( **kwargs ) }


    def default_certificate( self, **kwargs ):
        """ Provides a server_hello structure 

        Args:
            kwargs: multiple arguments. Ignored except
                cert 
        Returns:
            cert (bytes): the dictionary representing the
                ClientHello structure
        """
        try:
            cert = kwargs[ 'cert' ]
        except KeyError:
            cert = self.cert[ 0 ]
        if type( cert ) is  bytes: 
            return [ cert ]

        if isfile( cert ) :
            with open( cert, 'rb' )  as f:
                return [ f.read() ]


    def default_client_key_exchange( self, **kwargs):
        """ Generates a client_key_exchange structure 

        Args:
            kwargs: multiple arguments. Ignored except
                encrypted_premaster in the case the 'encrypted premaster' is 
                provided. Otherwise the encrypted premaster is generated with
               'premaster' and the public key. When not present the
                premaster is randomly generated. The public key is provided via
                'cert' or the configuration. 
      
        Returns:
            client_hello (dict): the dictionary representing the
                ClientHello structure
        """
        
        return self.default_encrypted_premaster( **kwargs )


    def default_handshake_messages( self, **kwargs ):
        """ Generates a HanshakeMessages structure 

        Args:
            kwargs: multiple arguments. Ignored except
                tls_version, client_random, session_id, cipher_suites,
                compression_methods, extensions, server_random, cipher_suite,
                compression_method, cert, premaster_secret,
                encrypted_premaster, client_hello, server_hello, certificate,
                client_key_exchange.  
      
        Returns:
            handshake_messages (list): the list representing the
                HandshakeMessages Array.
        """
        return [ { 'msg_type' : 'client_hello',  \
                   'body' :  self.default_client_hello( **kwargs ) }, \
                 { 'msg_type' : 'server_hello', \
                   'body' :  self.default_server_hello( **kwargs ) }, \
                 { 'msg_type' : 'certificate', \
                   'body' :  self.default_certificate( **kwargs ) }, \
                 { 'msg_type' : 'server_hello_done', \
                   'body' :  b'' }, \
                 { 'msg_type' : 'client_key_exchange', \
                   'body' :  self.default_client_key_exchange( **kwargs ) } ]
 

    
##?gc    def get_default_base( self, **kwargs ):
##?gc        """ builds a base payload given the provided arguments. keywords
##?gc            arguments can be 'key_id', 'client_random', 'server_random',
##?gc            'tls_version', 'freshness_funct'. 
##?gc            additional keywords may be provided:
##?gc            'cert' with a key, a certificate or a file which indicates
##?gc             the data to build teh key id.
##?gc
##?gc             Note that key_id = {'key_id_type' : xxx, 'key_id' : xxx }.
##?gc             keywords are only reserved for the first level domain and
##?gc             key_id designates the structure.  
##?gc        """
##?gc
##?gc        return { 'key_id' : key_id, \
##?gc                 'client_random' : client_random, \
##?gc                 'server_random' : server_random, \
##?gc                 'tls_version' : tls_version, \
##?gc                 'freshness_funct' : freshness_funct }
##
##    def get_pfs_prf_from_prf( self, prf ):
##        if prf == "sha256_null":
##            return 'null'
##        elif prf == "sha256_sha256":
##            return "sha256"
##        else:
##            raise InvalidFreshnessFunct( prf, 
##                "Expected 'sha256_sha256' or 'sha256_null' for RSA" )


    
    def pfs(self, server_random, freshness_funct):
        """ Perfect Forward Secrecy over the random structure
 
        Args:
            server_random (dict): the structure of the server random

        Returns:
            server_random (dict): the obfuscated random structure 

        Raises:
            InvalidFreshnessFunct: when the freshness_funct is not
                valid.
            InvalidRandom: when the random structure is not valid           

        """
        self.check_freshness_funct( freshness_funct )
        self.check_server_random( server_random )
        if freshness_funct == "null":
            return server_random
        elif freshness_funct == "sha256":
            bytes_random = Random.build( server_random )
            gmt_unix_time = bytes_random[0:4]
            bytes_random = bytes_random + str.encode( "tls12 pfs" ) 
            bytes_random = SHA256.new( data=bytes_random).digest()[:32]
            bytes_random = gmt_unix_time + bytes_random[4:]
            return Random.parse(bytes_random)



class Tls12RsaMasterRequestPayload(Tls12Payload):

    def __init__(self, conf=LurkConf().get_type_conf( 'tls12', 'v1',
                                              'rsa_master')[0] ):
        """ Builds and check a rsa master request

        Args:
            conf (dict): a dictionary that provides the necessary
                parameters to build and check a rsa master request 
                structure. 
        Attributes:
            conf (obj): the configuration object which contains the
                parameters as well as functions to ease the payload 
                handling.
            struct (obj): provides a structure description of the
                payload. This object is also responsible to convert 
                structure to binary rep and vise versa.
        """
       
        self.conf = Tls12RSAMasterConf( conf )
        self.struct = TLS12RSAMasterRequestPayload
        self.struct_name = 'TLS12RSAMasterRequestPayload'

    def build_payload(self, **kwargs ):
        """ Build the payload of the rsa master request 

         Arguments not provided are replaced by default values. 
         additional keys may be:
            cert: to indicate the rsa public key   
            premaster: the premaster

        Returns:
            request (dict): a dictionary that represents the structure 
                of the rsa master request.
        """
        return {\
            'key_id' : self.conf.default_key_id( **kwargs) ,\
            'freshness_funct' : self.conf.default_freshness_funct( **kwargs ) ,\
            'client_random' : self.conf.default_client_random( **kwargs ), \
            'server_random' : self.conf.default_server_random( **kwargs ), \
            'encrypted_premaster' : self.conf.default_encrypted_premaster( **kwargs ) }


    def check(self, payload ):
        """ checks the format of the rsa request structure is valid

        Args:
            payload (dict): a dictionary representing the structure of
                the rsa master request

        Raises:
            Error associated to the error field
            InvalidFormatPayload: for undetermined error 
        """
        keys = [ 'key_id', 'freshness_funct',
                 'client_random', 'server_random', 'encrypted_premaster' ]
        self.conf.check_key( payload, keys )
        self.conf.check_key_id( payload[ 'key_id' ] )
        self.conf.check_freshness_funct( payload[ 'freshness_funct' ] )
        self.conf.check_client_random( payload[ 'client_random' ] )
        self.conf.check_server_random( payload[ 'server_random' ] )
        self.conf.check_encrypted_premaster( payload[ 'encrypted_premaster' ] ) 

##        base = self.conf.extract_base( payload )
##        self.conf.check_base( base,\
##                              client_random=self.conf.check_client_random,\
##                              server_random=self.conf.check_server_random )

class Tls12RsaMasterResponsePayload(Tls12Payload):

    def __init__(self, conf=LurkConf().get_type_conf( 'tls12', 'v1',
                                             'rsa_master')[0] ):
        """ Builds and check a rsa master response

        The response can be built manually but also built from a rsa 
        master request.

        Args:
            conf (dict): a dictionary that provides the necessary
                parameters to build and check a rsa master request 
                structure. 
        Attributes:
            conf (obj): the configuration object which contains the
                parameters as well as functions to ease the payload 
                handling.
            struct (obj): provides a structure description of the
                payload. This object is also responsible to convert 
                structure to binary rep and vise versa.
        """
        self.conf = Tls12RSAMasterConf( conf )
        self.struct = TLS12RSAMasterResponsePayload
        self.struct_name = 'TLS12RSAMasterResponsePayload'

    # RFC5246 section 5
    def P_SHA256( self, secret, seed, length):
        """ Data expansion function 

        The data expansion function P_hash(secret, data) is defined in
        RFC 5246. It uses a single hash function to expand a secret and 
        seed into an arbitrary quantity of output

        P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                               HMAC_hash(secret, A(2) + seed) +
                               HMAC_hash(secret, A(3) + seed) + ...

        where + indicates concatenation.

        A() is defined as:
            A(0) = seed
            A(i) = HMAC_hash(secret, A(i-1))

        Args:
            secret (bin): the secret to be expanded
            seed (bin): the initial value A(0)
            length (int): the length in number of bytes of the expansion

        Returns: 
            output (bin): the extended data
        """
        out = b''
        A = seed
        while len(out) < length :  
            A_next = HMAC.new(secret, digestmod=SHA256)
            A_next.update( A )

            H = HMAC.new(secret, digestmod=SHA256)
            H.update( A_next.digest() + seed )
            out += H.digest()
            A = A_next.digest()
        return out[:length]


    def PRF12(self, secret, label, seed, length):
        """ TLS 12 PRF
       
        TLS 1.2 PRF is defined in RFC 5246 as:
        PRF(secret, label, seed) = P_<hash>(secret, label + seed)

        Args:
            secret (bin): the secret
            label (str): the ascii string
            seed (bin): the seed
            length (int): the length in number of bytes of the expansion

        Returns:
            output (bin): the extended data
            
        """
        return self.P_SHA256(secret, label + seed, length)
   
    def compute_master( self, request, premaster ):
        """ Computes master secret
 
        Args:
            request (dict): the dictionary representing the rsa master
                request. Note that only random, and freshness_funct are
                used from the request. In other words, the premaster is 
                not decrypted from the encrypted_premaster carried by 
                the request and is provided as a separate argument.
            premaster (bin): the premaster secret.

        Returns:
            master_secret (bin): the master secret.
        """
        try: 
            client_random = request[ 'hanshake_messages' ][ 0 ][ 'random' ]
            server_random = request[ 'hanshake_messages' ][ 1 ][ 'random' ]
        except KeyError:
            client_random = request [ 'client_random' ]
            server_random = request [ 'server_random' ]
            
        server_random = self.conf.pfs( server_random,\
                                       request[ 'freshness_funct' ] ) 
        # section 8.1 RFC5246 
        return self.PRF12(PreMaster.build(premaster), b'master secret',\
                            Random.build( client_random ) + \
                            Random.build( server_random ), 48  )
    
    def serve(self, request ):
        """ Serves the rsa master request

        Args:
            request (dict): a dictionary representing the rsa master
                request.

        Returns:
            response (dict): a dictionary representing the rsa master 
                response.

        """

        if 'key_id' not in request.keys():
           raise InvalidKeyID( key_id, "No key ID found")
        self.conf.check_key_id( request[ 'key_id' ] )
        private_key = self.conf.get_private_key_from( request[ 'key_id' ] )
        try:
            cipher = PKCS1_v1_5.new(private_key)
            try:
                encrypted_premaster = request[ 'handshake_messages'][4][ 'body' ]
            except KeyError:
                encrypted_premaster = request[ 'encrypted_premaster' ]
            premaster = cipher.decrypt( encrypted_premaster, None )
            premaster = PreMaster.parse( premaster )
            premaster_keys = [ 'tls_version', 'random' ]
            if set( premaster.keys() ) != set( premaster_keys ):
                raise InvalidPayloadFormat( premaster.keys(), 
                          "Expected %s"%premaster_keys )
            self.conf.check_tls_version( premaster[ 'tls_version' ]) 
        except:
            ### if any error occurs generate a random master
            return { 'master' : token_bytes( 48 * 8 ) }

        master = self.compute_master( request, premaster)
        return { 'master' : master }

    
    def build_payload(self, **kwargs ):
        """ Builds a master secret response

        Args:
            kwargs: multiple arguments. Only the 'master' is considered. 

        Returns:
            response (dict): a dictionary representing the rsa master 
                response.
        """
        if 'master' in kwargs.keys():
            master = kwargs[ 'master' ]
        else:
            master = randbits( 48 * 8 ) 
        return { 'master' : master } 

    def check(self, payload):
        """ Checks the rsa master response payload is valid

        Args:
            payload (dict): a dictionary representing the structure of
                the rsa master request

        Raises:
            InvalidFormatPayload: when format error on the master
                happens.
        """
        if 'master' not in payload.keys() :
            raise InvalidPayloadFormat( payload.keys(), \
                                        "expecting 'master'") 
        if len( payload[ 'master' ] ) != 48:
            raise InvalidPayloadFormat( len( payload[ 'master' ] ), \
                          "invalid master size. Expecting 48" )

class Tls12RSAExtendedMasterConf( Tls12RSAMasterConf ):

    def __init__( self, conf=LurkConf().get_type_conf('tls12', 'v1', \
                                             'rsa_extended_master' )[0] ):
        super().__init__( conf )

    def check_extensions( self, extensions):
        """ Checks expected extensions are provided in the list of
            extensions

        Args:
            extensions (list) : list of extensions

        Raises: 
            InvalidPayloadFormat: when the session id does not math the 
                expected structure.
        """
        is_valid = False
        for ext in extensions:
            if ext[ 'extension_type' ] == 'extended_master_secret' and \
               ext[ 'extension_data' ] == b'':
                is_valid = True
                break

    def default_extensions( self, **kwargs):
        """ Returns default extensiosn

        Args:
            kwargs: multiple arguments. Ignored except extensions.

        Returns: 
            extensions (dict): the dictionary representing the
                Extensions structure.
        """
        try:
            return kwargs[ 'extensions' ]
        except KeyError:
            return [ {'extension_type': 'extended_master_secret', \
                      'extension_data': b'' }]

class Tls12ExtMasterRequestPayload(Tls12RsaMasterRequestPayload):

    def __init__(self, conf=LurkConf().get_type_conf( 'tls12', 'v1',
                                             'rsa_extended_master')[0] ):
        self.conf =  Tls12RSAExtendedMasterConf( conf )
        self.struct = TLS12ExtendedRSAMasterRequestPayload
        self.struct_name = 'TLS12ExtendedRSAMasterRequestPayload'

    def build_payload( self, **kwargs ):

        return {\
            'key_id' : self.conf.default_key_id( **kwargs) ,\
            'freshness_funct' : self.conf.default_freshness_funct( **kwargs ) ,\
            'handshake_messages' : self.conf.default_handshake_messages( **kwargs )
        }

#        payload = super( Tls12ExtMasterRequestPayload, self ).build_payload( **kwargs )
#        del payload[ 'client_random' ]
#        del payload[ 'server_random' ]
#        if 'handshake_messages' in kwargs:
#            payload[ 'handshake_messages' ] = kwargs[ 'handshake_messages' ]
#        else:
#            payload[ 'session_hash' ] = SessionHash.build( token_bytes(32) )
#        return payload

    def check(self, payload ):
        keys = [ 'key_id', 'freshness_funct', 'handshake_messages' ]
        self.conf.check_key( payload, keys )
        self.conf.check_key_id( payload[ 'key_id' ] )
        self.conf.check_freshness_funct( payload[ 'freshness_funct' ] )
        self.conf.check_handshake_messages( payload[ 'handshake_messages' ] ) 
    

class Tls12ExtMasterResponsePayload(Tls12RsaMasterResponsePayload):

    def __init__(self, conf=LurkConf().get_type_conf( 'tls12', 'v1',
                                             'rsa_extended_master')[0] ):
        self.conf = Tls12RSAExtendedMasterConf( conf )
        self.struct = TLS12RSAMasterResponsePayload
        self.struct_name = 'TLS12RSAMasterResponsePayload'

    def compute_master( self, request, premaster ):
        handshake_messages = HandshakeMessages.build( \
            request[ 'handshake_messages' ] )
        session_hash = SHA256.new( handshake_messages ).digest()
        # section 4 RFC7627 
        return self.PRF12(PreMaster.build(premaster), b'extended master secret',\
                            session_hash, 48  )

class Tls12ECDHEConf ( Tls12RSAMasterConf ):

    def __init__(self, conf=LurkConf().get_type_conf('tls12', 'v1', 'ecdhe' )[0] ):
        """ Provides tool function for the ECDHE master exchange based on
        the configuration. 
       
        Args:
            conf (:obj: `dict`, optional) the configuration parameters
                associated to the RSA master exchange. The dictionary has 
                the following format: { 'role' : , 'key_id_type' : , 
                'freshness_funct' : , 'random_time_window' : , 'cert' : ,
                'check_server_random' : , 'check_client_random' : , 'key'
                :, 'ecdsa_curves' :, 'ecdhe_curves', 'poo_prf' }. By 
                default the dictionary is provided from the main
                configuration core/conf.py.
        Raises: 
            ConfError if the object cannot be initialized.
       
        """
        self.conf_keys = [ 'role', 'key_id_type' , 'freshness_funct', \
                      'random_time_window', 'cert', 'check_server_random',\
                      'check_client_random', 'sig_and_hash', 'ecdsa_curves', \
                      'ecdhe_curves', 'poo_prf' ]
        ## private variables, specify the type of key authorized
        self.key_classes = [  'RsaKey', 'EccKey' ] 

        self.check_conf( conf ) 
        self.role = conf[ 'role' ]
        self.cert =  conf[ 'cert' ]
        if self.role == "server":
            ## private keys
            self.key =  conf[ 'key' ]
        self.key_id_type = conf[ 'key_id_type' ]
        self.freshness_funct = conf[ 'freshness_funct' ] 
        self.random_time_window = conf[ 'random_time_window' ]
        self.sig_and_hash = conf[ 'sig_and_hash' ] 
        self.ecdsa_curves = conf[ 'ecdsa_curves' ]
        self.ecdhe_curves = conf[ 'ecdhe_curves' ] 
        self.poo_prf = conf[ 'poo_prf' ]


        ## defines authorized certificates mostly concerns the server or
        ## public keys. X509, asn1 using pem/der are valid formats
        self.build_key_stores()

##    def check_conf_prf( self, prf ):
##        prf_values = [ "intrinsic_null", "intrinsic_sha256" ] 
##        if prf not in prf_values : 
##            raise ConfError( prf, "Expected %s"%prf_values )

    def check_conf( self, conf):
        """ Checks the configuration 

        Performs check_conf from Tls12RSAMasterConf and adds checks for
        the additional arguments of teh configuration sig_and_hash', 
        'ecdsa_curves', 'ecdhe_curves', 'poo_prf' 

        Args:
            conf (dict): the configuration parameters presented as a
                dictionary.
    
        Raises:
            ConfError: when the parameters are not appropriated. 
        """
        super().check_conf( conf )
        try :
            for k in [ 'sig_and_hash', 'ecdsa_curves', 'ecdhe_curves', 'poo_prf' ]: 
                if type( conf[ k ] ) is not list:
                    raise ConfError( conf[ k ], "Expecting list" )
            for h, s in conf[ 'sig_and_hash' ]:
                try:
                    SignatureAndHashAlgorithm.build( { 'sig' : s, 'hash' : h } )
                except:
                    raise ConfError( conf[ 'sig_and_hash' ], "Expected values" )
            for curve in conf[ 'ecdsa_curves' ]:
                try:
                    NameCurve.build( curve )
                except:
                    raise ConfError( conf[ 'ecdsa_curves' ], "Expected values" )
            for curve in conf[ 'ecdhe_curves' ]:
                try:
                    NameCurve.build( curve )
                except:
                    raise ConfError( conf[ 'ecdhe_curves' ], "Expected values" )
            for poo_prf in conf[ 'poo_prf' ]:
                try:
                    POOPRF.build( poo_prf )
                except:
                    raise ConfError( conf[ 'poo_prf' ], "Expected values" )
        except KeyError:
            raise ConfError( conf, "Missing key. Expecting %s"%\
                [ 'sig_and_hash', 'ecdsa_curves', 'ecdhe_curves', 'poo_prf' ] )

    def check_sig_and_hash( self, sig_and_hash ):
        """ Check signature and hash algorithms

        Signature and hash are also checked against available keys.

        Args:
            sig_and_hash (dict): the dictionary representing the
                sig_and_hash structure
        
        Raises:
            InvalidSigAndHash: if sig or hash value are not acceptable
        """
        sig_and_hash_keys = [ 'hash', 'sig' ]
        self.check_key( sig_and_hash, sig_and_hash_keys )  
        
        if ( sig_and_hash[ 'hash' ], sig_and_hash[ 'sig' ] ) not in self.sig_and_hash :
            raise InvalidSigAndHash( sig_and_hash, \
                        "Expecting %s"%self.sig_and_hash )
        ## checking compatibility betwen sig / key
        for cert in self.cert :
            self.default_sig_and_hash( cert=cert )


    def get_ec_point_len( self, name_curve ): 
        """ returns the len in bits for the x and y. according to the
            curve name 

        Args:
            name_curve: the name of the curve  

        Raises:
            InvalidECCurve: when the curve name is not supported
        """
        if name_curve == 'secp256r1' :
            k = 256
        elif name_curve == 'secp384r1' :
            k = 384
        elif name_curve == 'secp512r1' :
            k = 512
        else: 
            raise InvalidECCurve( name_curve, 
                      "Expected %s "%self.ecdhe_curves )
        return k

    def check_ec_point(self, ec_point, ec_len=512):
        """ check the EC Point format. 

        The EC Point is used to carry a signature or a ECDHE. Its format
        is define din RFC8422.

        Args:
            ec_point (dict): the dictionnary representing the EC Point
                structure 
            ec_len designates in bits the expected len of x and the 
                expected len of y. The length is provided by the curve. 

        Raises:
            InvalidECPointFormat: when the ECPoint structure cannot be
                validated. 
        """ 
        ec_point_keys = [ 'form', 'x', 'y' ]
        self.check_key( ec_point, ec_point_keys )  
        if ec_point[ 'form' ] != "uncompressed" :
            raise InvalidECPointFormat( ec_point[ 'form' ], \
                      "expected 'uncompressed' " )
        if ec_point[ 'x' ] > 2 ** ec_len or ec_point[ 'y' ] > 2 ** ec_len:
            raise InvalidECPointFormat( ( ec_point[ 'x' ], ec_point['y'] ) , \
                "Unexpected large values" )


    def check_ecdhe_params(self, ecdhe_params):
        """ Checks the ecdhe_params structure

        The ecdhe_params structure checks the ecdhe_curves as well as
        the corresponding ec point

        Args:
            echde_params (dict): the dictionary representing the
                ecdhe_params structure as described in RFC8422  

        Raises:
            InvalidECType: when the type of the name curve is not a
                'name_curve'
            InvalidECCurve: when the curve is not supported

        """
        ecdhe_params_keys = [ 'curve_param', 'public' ]
        self.check_key( ecdhe_params, ecdhe_params_keys )

        ec_params =  ecdhe_params[ 'curve_param']
        ec_params_keys = [ 'curve_type', 'curve' ]
        self.check_key( ec_params, ec_params_keys )  

        if ec_params[ 'curve_type' ] != "name_curve":
           raise  InvalidECType( ec_params[ 'curve_type' ],\
                           "expecting 'name_curve' " )
        if ec_params[ 'curve' ] not in self.ecdhe_curves:
            raise InvalidECCurve( name_curve, "supported curves are " + \
                         "%s"%self.ecdhe_curves )
        ec_point = ecdhe_params[ 'public' ]
        ec_len = self.get_ec_point_len( ec_params[ 'curve' ] )
        self.check_ec_point( ec_point, ec_len=ec_len)


    def check_poo_prf( self, poo_prf):
        """ Check the pseudo random function used for the proof of
                ownership

        Args:
            poo_prf (str): the prf used to generate the poo

        Raises:
            InvalidPOOPRF: when the prf is not recognized.
        
        """
        if poo_prf not in self.poo_prf:
            raise InvalidPOOPRF( poo_prf, "Expected %s"%self.poo_prf)

    def check_poo_params( self, poo_params, ec_len ):
        """ Checks the structure of the poo_params

        Args:
            poo_params (dict): the structure representing the proof of
                ownership parameters (poo_params)

        Raises:
            InvalidPOO: when the parameters are not valid

        """
        ## the current version includes always the rG / tG these keys
        ## are empty when associated with 'null'. future version should
        ## remove these fields completely. 
        print( "poo_param :%s"%poo_params )
        poo_keys = [ 'poo_prf', 'rG', 'tG' ]
        self.check_key( poo_params, poo_keys )
        poo_prf = poo_params[ 'poo_prf' ]
        self.check_poo_prf( poo_prf )
        if poo_prf == 'null' :
            if poo_params[ 'rG' ] != None or poo_params[ 'tG' ] != None:
                raise InvalidPOO(poo_prf, "Expected void 'rG' and 'tG'" )
            
        if poo_prf in [ "sha256_128", "sha256_256" ]:
            ec_point_keys = [ 'form', 'x', 'y' ]
            rG = poo_params[ 'rG' ]
            tG = poo_params[ 'tG' ]
            for ec_point in [ rG, tG ]:
                self.check_ec_point( ec_point, ec_len=ec_len)

##    def get_pfs_prf_from_prf( self, prf ):
##        if prf == "intrinsic_null":
##            return 'null'
##
## elif prf == "intrinsic_sha256":
##            return "sha256"
##        else:
##            raise InvalidFreshnessFunct( prf, 
##                "Expected 'intrinsic_sha256' or 'intrinsic_null' for ECDSA" )

    def default_sig_and_hash( self, **kwargs ):
        """ Default value for sig_and_hash

       The default sig_and_hash must be compatible with the public key 
       determined by the key_id indicated by the packet. The function
       retrieves the class of the public key and take sthe first compatible
       sig_and_hash value found in the list of self.sig_and_hash. 

        Args:
            kwargs: many arguments ignored excepted 'cert'

        Returns:
            s, h (str): signatuire and hash algorithm

        Raises:
            InvalidSigAndHash: when signature and hash algorithm cannot
                be provided. 
        """
        key = self.default_public_key( **kwargs )
        key_type = key.__class__.__name__ 
        if key_type == 'RsaKey' :
            target_sig = 'rsa'
        elif key_type == 'EccKey':
            target_sig = 'ecdsa'
        for h, s in self.sig_and_hash :
            if s == target_sig :
                return { 'hash' : h, 'sig' : s }
        raise InvalidSigAndHash( ( key_type, self.sig_and_hash), \
                           "Non compatible signature and key")

    def default_ecdhe_curve( self, **kwargs):
        """ Provides the default ecdhe_curve name

        Args:
            kwrags: multiple arguments. Ignored except 'ecdhe_curve' 

        """
        try:
            return kwargs[ 'ecdhe_curve' ]
        except KeyError:
            return self.ecdhe_curves[0]

    def default_ecdhe_private( self, **kwargs ):
        """ Returns echde private key
 
        Args:
            kwarg: multiple argument. Ignored except 'curve_name' to
                indicate the curve and 'ecdhe_private' which is the
                returned key. 
        Returns:
            ecdhe_private (bits): the private part of the ecdhe key
        """
        try:
            return kwargs[ 'ecdhe_private' ]
        except KeyError:
            name_curve = self.default_ecdhe_curve( **kwargs )
            curve = reg.get_curve( name_curve )
            k = self.get_ec_point_len( name_curve )
            return randbits( k )

    def default_ecdhe_params(self, **kwargs):
        """ Provides default ecdhe_params structure
           
        Notes: ecdhe illustration  can be found here:
        https://wiki.osdev.org/TLS_Handshake

        Args:
            kwargs: multiple arguments. Ignored except: 'ecdhe_params'
                'ecdhe_curves', 'ecdhe_private'
 
        Returns:
            ecdhe_params (dict): the dictionary representing the ecdhe_param
                structure
        """
        try:
            return kwargs[ 'ecdhe_params' ]
        except KeyError:
            b = self.default_ecdhe_private( **kwargs )
            name_curve = self.default_ecdhe_curve( **kwargs )
            curve = reg.get_curve( name_curve )
            client_public_key = curve.g * b
            ec_params = { 'curve_type' : "name_curve", 'curve' : name_curve }
            ec_point = { 'form' : "uncompressed", \
                         'x' : client_public_key.x, \
                         'y' : client_public_key.y }
            k = self.get_ec_point_len( name_curve )
            self.check_ec_point( ec_point, k)

            return { 'curve_param' : ec_params,  'public' : ec_point } 

    def default_poo_prf(self, **kwargs ):
        """ provides the default poo prf

        Args: 
            kwargs: multiple arguments. Ignored except 'poo_prf'

        Returns:
            poo_prf: the poo_prf
        """
        try: 
            return kwargs[ 'poo_prf' ]
        except KeyError:
            return self.poo_prf[0]

    def build_poo_params(self, poo_prf, base, ecdhe_params, ecdhe_private ):
        """ builds poo_params for Proof of Ownership

        Args:
            poo_prf (str): the pseudo random function used for the poof
                of ownership.
            base (dict): dictionary representing { key_id,
                freshness_funct, client_random, server_random }. These
                 are relatively common parameters for the different requests.  
            ecdhe_params (dict): the dictionnary representing teh
                echde_params structure. 
            echde_private (bin): the private key used for the ecdhe
                exchange.
        Returns: 
            poo_params (dict): the dictionary representing the poo
                (proof of ownership) parameters. 

        Raises:
            InvalidPOO: when poo cannot be built.
            InvalidPOOPRF: when the ppo_prf is not recognized
        """
        self.check_poo_prf( poo_prf )
        if poo_prf == 'null': ## woudl be better to remove the rG, tG
            return { 'poo_prf' : "null" , 'rG' : None, 'tG' : None}
        elif poo_prf in [ "sha256_128", "sha256_256" ]:
            ## needs to know the secret b so can only be
            ## generated if the ecdhe parameters have been 
            ## generated 
            try : 
               c = self.compute_c( poo_prf, base, ecdhe_params )
               r = randbits( k / 2 ) 
               t = c * b + r
               rG = r * curve.g
               tG = t * curve.g
               return { 'poo_prf' : poo_prf, \
                        'rG' : { 'x' : rG.x, 'y' : rG.y }, 
                        'tG' : { 'x' : tG.x, 'y' : tG.y } }
            except NameError:
                raise InvalidPOO( kwargs, "cannot generate poo " +\
                          "generating echde_params. Please either " +\
                          "provide both of them or none." )
        else:
            raise InvalidPOOPRF( poo_prf, "supported poo_prf are" +
                                 "null, sha256_128, sha256_256" )


    def compute_c( self, poo_prf, base, ecdhe_params):
        """ computes the value that proves the ownership of the private
        key.

        Args: 
            poo_prf (str): the pseudo random function used for the poof
                of ownership.
            base (dict): dictionary representing { key_id,
                freshness_funct, client_random, server_random }. These
                 are relatively common parameters for the different requests.  
            ecdhe_params (dict): the dictionnary representing teh
                echde_params structure. 
        Returns:
            c: the value that proves ownership 

        Raises:
            InvalidPOOPRF: when the ppo_prf is not recognized
        """
        
        data = TLS12Base.build( base ) + \
                ServerECDHParams.build( ecdhe_params ) + "tls12 poo"
        c = SHA256.new( data=data ).digest()
        if poo_prf == "sha256_128":
            c = c[ : 128 ]
        elif poo_prf == "sha256_256":
            c = c[ : 256 ]
        else:
            raise InvalidPOOPRF( poo_prf, "supported poo_prf are" +
                                            "null, sha256_128, sha256_256" )


class Tls12ECDHERequestPayload(Tls12Payload):

    def __init__(self, conf=LurkConf().get_type_conf('tls12', 'v1', 'ecdhe' )[0] ):
        self.conf = Tls12ECDHEConf( conf )
        self.struct = TLS12ECDHERequestPayload
        self.struct_name = 'TLS12ECDHERequestPayload'


    def build_payload( self, **kwargs):
        """ generates the ECDHE request structure

        ecdhe_params and poo_params shares multiple variables such as
        ecdhe_private, ecdhe_params itself. In addition poo_params 
        uses parameters carried in the request (base). In order to avoid kwargs
        carrying too many arguments, the synchronization is handled by this
        function and we did not create a default_poo_params function
        
        Args:
            kwargs: multiple parameters. Ignored except 
        """

        ecdhe_private  = self.conf.default_ecdhe_private( **kwargs )
        ecdhe_params = self.conf.default_ecdhe_params( **kwargs )
        base = { 'key_id' : self.conf.default_key_id( **kwargs) ,\
                 'freshness_funct' : self.conf.default_freshness_funct( **kwargs ) ,\
                  'client_random' : self.conf.default_client_random( **kwargs ), \
                  'server_random' : self.conf.default_server_random( **kwargs ) }
        try:
            poo_params = kwargs[ 'poo_params' ]
        except KeyError:
            poo_prf = self.conf.default_poo_prf( **kwargs )
            poo_params = self.conf.build_poo_params( poo_prf, base, \
                                                    ecdhe_params, ecdhe_private )
            print("build_payload - poo_params: %s"%poo_params)
        return  { **base, \
            'sig_and_hash' : self.conf.default_sig_and_hash( **kwargs ), \
            'ecdhe_params' : ecdhe_params, \
            'poo_params' : poo_params }
        

    def check( self, payload):
        """ check the payload
 
        Args:
            payload (dict): the dictionary representing the structure of
                a ecdhe request.

        Raises:
            Error: any encountered error
        """
        keys = [ 'key_id', 'freshness_funct', 'client_random', \
                 'server_random', 'sig_and_hash', 'ecdhe_params', 'poo_params' ]
        self.conf.check_key( payload, keys )
        self.conf.check_key_id( payload[ 'key_id' ] )
        self.conf.check_freshness_funct( payload[ 'freshness_funct' ] )
        self.conf.check_client_random( payload[ 'client_random' ] )
        self.conf.check_server_random( payload[ 'server_random' ] )
        self.conf.check_sig_and_hash( payload[ 'sig_and_hash' ] )
        self.conf.check_ecdhe_params( payload[ 'ecdhe_params' ] )
        name_curve = payload[ 'ecdhe_params' ][ 'curve_param' ][ 'curve' ]
        ec_len = self.conf.get_ec_point_len( name_curve )
        self.conf.check_poo_params( payload[ 'poo_params' ], ec_len )

    

class Tls12ECDHEResponsePayload(Tls12Payload):

    def __init__(self, conf=LurkConf().get_type_conf('tls12', 'v1', 'ecdhe' )[0] ):
        self.conf = Tls12ECDHEConf( conf )
        self.struct = TLS12ECDHEResponsePayload
        self.struct_name = 'TLS12ECDHEResponsePayload'

    def serve(self, request ):
        key_id = request[ 'key_id' ]
        self.conf.check_key_id( key_id )
        private_key = self.conf.get_private_key_from( key_id )
        sig_algo = request[ 'sig_and_hash' ][ 'sig' ]
        h_algo = request[ 'sig_and_hash' ][ 'hash' ]
        key_class = private_key.__class__.__name__
        if key_class == "RsaKey" and sig_algo == 'rsa' or \
           key_class == "EccKey" and sig_algo == 'ecdsa' :
            pass
        else:
            raise InvalidPayloadFormat( ( key_class, sig_algo ), \
                      "Incompatible key and expected signature" )
        poo_prf = request[ 'poo_params' ][ 'poo_prf' ]
        if poo_prf == 'null':
            pass
        else:
            ecdhe_params = request[ 'echde_params' ]
            name_curve = ecdhe_params[ 'curve_params' ][ 'curve' ]
            curve = reg.get_curve( name_curve )
            public_key = ecdhe_params[ 'public' ]
            bG = ec.Point( curve, public_key[ 'x'],  public_key[ 'y' ] )
            rG = ec.Point( curve, request[ 'rG' ][ 'x' ], request[ 'rG'][ 'y' ] )
            rG = ec.Point( curve, request[ 'rG' ][ 'x' ], request[ 'rG'][ 'y' ] )
            base = self.conf.extract_base( request )
            c = self.conf.compute_c( poo_prf, base, ecdhe_params )
            if c.bG + rG != tG :
                raise InvalidPOO( ( c.bG + rG, tG ), "Expected Equals" ) 

        server_random = self.conf.pfs( request[ 'server_random' ],\
                                       request['freshness_funct'] ) 

        message = Random.build( request[ 'client_random' ] ) + \
                  Random.build( server_random ) + \
                  ServerECDHParams.build( request[ 'ecdhe_params' ] )
        if h_algo == 'sha256' :
            h = SHA256.new(message)
        elif h_algo == 'sha512':
            h = SHA512.new(message)
        else:
            raise InvalidSigAndHash( h_algo, 
                "expected hash in %s"%self.conf.sig_and_hash ) 
         
        if sig_algo == 'rsa':
            sig = pkcs1_15.new( private_key ).sign( h )
        elif sig_algo == 'ecdsa':
            signer = DSS.new( private_key, 'fips-186-3', encoding='der')
            sig = signer.sign( h )
        else:
            raise InvalidSigAndHash( h_algo, 
                "expected hash in %s"%self.conf.sig_and_hash ) 
        return { "signed_params" : sig }
         
    def build_payload(self, **kwargs ):
        if 'signed_params' in kwargs:
            sig = kwargs[ 'signed_params' ] 
        else :
            sig = randbits(256)
        return { 'signed_params' : sig }


    def check( self, payload ):
        self.conf.check_key( payload, [ 'signed_params' ] )
     
    def verify( self, message, payload, cert=None ):
        signature = payload[ 'signed_params' ] 
        if cert != None:
            key = kwargs[ 'cert' ]
        else:
            key = self.conf.cert[0]
        public_key = self.conf.read_key( key )
        key_class = public_key.__class__.__name__
        if key_class == "RsaKey":
            try:
                pkcs1_15.new(public_key).verify( message, signature )
            except ( ValueError, TypeError ):
                print( "The signature is not valid." )
        elif key_class == "EccKey":
             verifier = DSS.new( public_key, 'fips-186-3')
             try:
                 verifier.verify( message , signature)
             except ( ValueError, TypeError ):
                 print( "The signature is not valid." )
        else:
             raise ConfError( key_class, "Expected 'RsaKey or 'EccKey' " )


class Tls12CapabilitiesConf:


    ## All configuration parameters are not related to capabilities.
    ## get_ext_conf excludes those parameters.

    def __init__( self, conf=LurkConf().get_ext_conf( 'tls12', 'v1',\
            exclude=[ 'role', 'designation', 'version', 'type', 'key', \
                      'random_time_window',  'check_server_random',\
                      'check_client_random'  ] ) ):
        self.check_conf( conf )
        self.conf = conf


    def check_conf( self, conf): 
        for k in conf.keys():
            keys  = [ 'ping', 'rsa_master', 'rsa_extended_master', \
                      'ecdhe', 'capabilities' ]
            if k not in keys: 
                raise ConfError( conf, "UnExpected key %s. Expecting %s"%\
                    ( k, keys) )
            if type( conf[ k ] ) is not list:
                raise ConfError( conf[ k ], "Expected list")
            if len( conf[ k ] ) > 1:
                raise ConfError( conf[ k ], "Only len = 1 is currently " +\
                                            "supported")
        for k in conf.keys():
            if k == "rsa_master":
                for type_conf in conf[ 'rsa_master' ]:
                     Tls12RSAMasterConf().check_conf( type_conf )    
            elif k == "rsa_extended_master":
                for type_conf in conf[ 'rsa_extended_master' ]:
                     Tls12RSAExtendedMasterConf().check_conf( type_conf )    
            elif k == "ecdhe" :
                for type_conf in conf[ 'ecdhe' ]:
                     Tls12ECDHEConf().check_conf( type_conf )    
            

    
class Tls12CapabilitiesResponsePayload(Tls12Payload):

    def __init__(self, conf=LurkConf().get_ext_conf( 'tls12', 'v1' ) ):
        self.conf = Tls12CapabilitiesConf( conf=conf )
        self.capabilities = self.set_capabilities()
        self.struct = TLS12CapabilitiesResponsePayload 
        self.struct_name = 'TLS12CapabilitiesResponsePayload' 


    def serve( self, request ):
       if request != {} :
            raise InvalidPayloadFormat( request, "empty bytes request " +\
                                          "payload expected")
       return self.build_payload()

    def build_payload(self, **kwargs ):
        return self.capabilities

    def set_capabilities(self):
        payload = {}
        payload[ 'capabilities' ] = []
        for mtype in self.conf.conf:
            capability = {}
            capability[ 'type' ] = mtype
            ## currently conf[ mtype ] is a single conf but we may have
            ## multiple ones
            for type_conf in self.conf.conf[ mtype ] :
                if mtype == 'ping' :
                    pass
                elif mtype == 'capabilities' :
                    pass
                elif mtype in [ 'rsa_master', 'rsa_extended_master', 'ecdhe' ] :
                    capability[ 'key_id_type' ] = type_conf[ 'key_id_type' ]
                    capability[ 'tls_version' ] = []
#                    for v in type_conf[ 'tls_version' ]:
#                        if v == "TLS1.2":
#                            capability[ 'tls_version' ].append( { 'major' : "TLS12M", \
#                                                              'minor' : "TLS12m" } )
#                        else:
#                            raise ConfError( type_conf[ 'tls_version' ], "Expecting TLS12" ) 
                    capability[ 'freshness_funct' ] = type_conf[ 'freshness_funct' ]
                    capability[ 'cert' ] = []
                    for cert in type_conf[ 'cert' ]:
                        try:
                            with open( cert, 'rb') as f:
                                
                                capability[ 'cert' ].append( f.read( ) )
                        except IOError:
                            raise ConfError( cert, "Cannot open file" )
               
                if mtype == 'ecdhe' :
                    capability[ 'sig_and_hash' ] = []
                    for h,s in type_conf[ 'sig_and_hash' ]:
                        capability[ 'sig_and_hash' ].append( { 'hash' : h, 'sig' : s } ) 
                    capability[ 'ecdsa_curves' ] = type_conf[ 'ecdsa_curves' ]
                    capability[ 'ecdhe_curves' ] = type_conf[ 'ecdhe_curves' ]
                    capability[ 'poo_prf' ] = type_conf[ 'poo_prf' ]
                    
                payload[ 'capabilities' ].append( capability )
        lurk_state = SHA256.new( str.encode( str( payload ) ) ).digest()[ :4 ]
        payload[ 'lurk_state' ] = lurk_state 
        return payload



class LurkExt:
    ## conf = { 'ping' : [  []. ...  [] ], 
    ##          'rsa_master' : [ { conf1_rsa }, { conf2_rsa }, ... ] }
    ## By default ALL configuration parameters are provided except: type
    ## already provided as in a key, 9designation, version) that are
    ## implied by the module.
    def __init__(self, role, conf=LurkConf().get_ext_conf( 'tls12', 'v1' ) ):
        Tls12CapabilitiesConf( conf=conf ).check_conf( conf )
        self.conf = conf
        self.ext_class = self.get_ext_class()  

    def get_ext_class(self):
        ext_class = {}
        if  'ping' in self.conf.keys() :
            ext_class[ ( 'request', 'ping' ) ] = LurkVoidPayload()
            ext_class[ ( 'success', 'ping' ) ] = LurkVoidPayload()
        if  'capabilities' in self.conf.keys() :
            ext_class[ ( 'request', 'capabilities' ) ] = LurkVoidPayload()
            ext_class[ ( 'success', 'capabilities' ) ] =\
                Tls12CapabilitiesResponsePayload( conf=self.conf )
        if 'rsa_master' in self.conf.keys() :
            ext_class[ ( 'request', 'rsa_master' ) ] = \
                Tls12RsaMasterRequestPayload( conf=self.conf[ 'rsa_master' ][0] )
            ext_class[ ( 'success', 'rsa_master' ) ] = \
                Tls12RsaMasterResponsePayload( conf=self.conf[ 'rsa_master' ][0] )
        if 'ecdhe' in self.conf.keys() :
           ext_class[ ( 'request', 'ecdhe' ) ] = \
               Tls12ECDHERequestPayload( conf=self.conf[ 'ecdhe' ][0] )
           ext_class[ ( 'success', 'ecdhe' ) ] = \
               Tls12ECDHEResponsePayload( conf=self.conf[ 'ecdhe' ][0] )
        if 'rsa_extended_master' in self.conf.keys():
            ext_class[ ( 'request', 'rsa_extended_master' ) ] = \
                Tls12ExtMasterRequestPayload( \
                    conf=self.conf[ 'rsa_extended_master' ][0] )
            ext_class[ ( 'success', 'rsa_extended_master' ) ] = \
                Tls12ExtMasterResponsePayload(\
                    conf=self.conf[ 'rsa_extended_master' ][0])
        return ext_class 

    def check_conf( self, conf): 
        for k in conf.keys():
            if k is 'role' :
                if conf[ k ] not in [ 'client', 'server' ]:
                    raise ConfError( conf, "Expecting role in  'client'" +\
                                           "'server'")
            elif k in [ 'ping', 'rsa_master', 'rsa_extended_master', 'ecdhe' ]:
                if type( conf[ k ] ) is not list:
                    raise ConfError( conf[ k ], "Expected list")
                if len( conf[ k ] ) > 1:
                    raise ConfError( conf[ k ], "Only len = 1 is currently " +\
                                                "supported")
            else:
                raise ConfError( conf, "unexpected key %s"%k )

    def parse( self, status, mtype, pkt_bytes ):
        """ parse the byte array into containers. The same status code
            is used are used and response is indicated by "success" """
        return self.ext_class[ ( status, mtype ) ].parse( pkt_bytes )

    def build( self, status, mtype, **kwargs):
        return self.ext_class[ ( status, mtype ) ].build( **kwargs )

    def serve( self, mtype, request  ):
        return self.ext_class[ ( 'success' , mtype ) ].serve( request )

    def check( self, status, mtype, payload ):
        return self.ext_class[ ( status, mtype ) ].check( payload )

    def show( self, status, mtype, pkt_bytes, prefix="", line_len=LINE_LEN ):
        return self.ext_class[ ( status, mtype ) ].show( pkt_bytes, \
                   prefix=prefix, line_len=line_len )

    def build_payload( self, status, mtype, payload ):
        return self.ext_class[ ( status, mtype ) ].build_payload( **kwargs )

