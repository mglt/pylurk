from os.path import isfile, join
from pylurk.extensions.tls12_struct import *
from pylurk.core.lurk import Error, ConfError, ImplementationError, Payload,\
                 LurkConf, LINE_LEN
from pylurk.extensions.lurk import LurkVoidPayload
from time import time

from secrets import randbits, token_bytes
from math import ceil
import tinyec.ec as ec
import tinyec.registry as reg

from Cryptodome.PublicKey import RSA, ECC
from Cryptodome.Hash import HMAC, SHA256, SHA384, SHA512
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

class InvalidCipherOrPRFHash(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_cipher_or_prf_hash"

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


class Tls12RsaMasterConf:
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
                 'random_time_window', 'cert', \
                 'check_server_random', 'check_client_random',\
                 'cipher_suites', 'prf_hash']
        ## private variables, specify the type of key authorized
        self.key_classes = [ 'RsaKey' ]
                
        self.check_conf( conf ) 

        self.role = conf[ 'role' ]
        self.cert = conf[ 'cert' ]
        if self.role == "server":
            ## private keys
            self.key =  conf[ 'key' ]
        self.key_id_type = conf[ 'key_id_type' ] 
        self.freshness_funct = conf[ 'freshness_funct' ] 
        self.prf_hash = conf[ 'prf_hash' ] 
        self.cipher_suites = conf[ 'cipher_suites' ]
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
            print("The following conf keys have been provided")
            print("and are not expected")
            for k in conf.keys():
                if k not in self.conf_keys:
                    print("    - %s"%k)
            print("The following conf keys have not been provided")
            print("and are expected")
            for k in self.conf_keys:
                if k not in conf.keys():
                    print("    - %s"%k)
            raise ConfError( conf.keys(), "Conf keys mismatch. " + \
                      "Expected keys: %s"%self.conf_keys )
        ## checking value provided by conf for each key_conf
        try :
            for k in self.conf_keys:
                if k in [ 'key_id_type' , 'freshness_funct', 'cert', \
                          'key', 'prf_hash', 'cipher_suites']:
                    if type( conf[ k ] ) is not list:
                        raise ConfError( conf[ k ], "Expected list" )
                if k == 'key_id_type':
                    [ KeyPairIDType.build( i ) for i in conf[ k ] ]
                if k == 'freshness_funct': 
                    [ FreshnessFunct.build( i ) for i in conf[ k ] ]
                if k == 'prf_hash': 
                    [ PRFHash.build( i ) for i in conf[ k ] ]
                if k == 'cipher_suites': 
                    [ CipherSuite.build( i ) for i in conf[ k ] ]
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

    def check_prf_hash( self, prf_hash ):
        """ Checks the prf hash is valid 

        Args:
            prf_hash (str): the value of the prf hash function

        Raises: 
            InvalidCipherOrPRFHash : when the prf_hash is not acceptable.
        """
        ##print("prf_hash: %s / self.prf_hash: %s"%(prf_hash, self.prf_hash) )
        if prf_hash not in self.prf_hash:
            raise InvalidCipherOrPRFHash( prf_hash, +\
                      "Expecting prf hash in %s"%self.prf_hash )

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
            if c in self.cipher_suites:
                is_valid = True
                break
        if is_valid == False:
            raise InvalidCipherOrPRFHash( cipher_suites, "ClientHello " +\
                      "Expecting at least one cipher suite in %s"
                       %self.cipher_suites )

    def check_compression_methods( self, compression_methods):
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
            self.check_compression_methods( client_hello[ 'compression_methods' ] )
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
        if server_hello[ 'cipher_suite' ] not in self.cipher_suites:
            raise InvalidCipherOrPRFHash( cipher_suites, "ServerHello " +\
                      "Expecting cipher suite in %s"%cipher_suites )

    def check_certificate( self, certificate):
        """ Checks the certificate 

        Args:
            certificate (dict): dictionary representing the Certificate
                structure
        
        Raises:
            InvalidPayloadFormat: when an unexpected value is used in the
                structure.
        """
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

    def default_prf_hash(self, **kwargs ):
        """ Provides the prf_hash
       
        Args:
            kwargs: multiple arguments. Arguments are ignored except
                prf_hash.

        Returns:
            prf_hash (str): the PRF hash function (string
                representation)

        """
        try:
            return  kwargs[ 'prf_hash' ]
        except: 
            return self.prf_hash[ 0 ]


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
                byte_premaster =  PreMaster.build( kwargs[ 'premaster' ] )
            except KeyError:
                tls_version = { 'major' : "TLS12M", 'minor' : "TLS12m"} 
                byte_premaster = PreMaster.build(\
                    { 'tls_version' : tls_version, \
                      'random' : token_bytes( 46 ) } )
            cipher = PKCS1_v1_5.new(rsa_public_key)      
            return cipher.encrypt( byte_premaster )

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
            return [ c  for c in self.cipher_suites ]

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
            kwargs: multiple arguments. Ignored except handshake_messages 
                or the necessary parameters to build handshake_messages
                tls_version, client_random, session_id, cipher_suites,
                compression_methods, extensions, server_random, cipher_suite,
                compression_method, cert, premaster_secret,
                encrypted_premaster, client_hello, server_hello, certificate,
                client_key_exchange.  
      
        Returns:
            handshake_messages (list): the list representing the
                HandshakeMessages Array.
        """
        try:
            return kwargs[ 'handshake_messages' ]
        except KeyError:
            return [ \
                 { 'msg_type' : 'client_hello',  \
                   'body' :  self.default_client_hello( **kwargs ) }, \
                 { 'msg_type' : 'server_hello', \
                   'body' :  self.default_server_hello( **kwargs ) }, \
                 { 'msg_type' : 'certificate', \
                   'body' :  self.default_certificate( **kwargs ) }, \
                 { 'msg_type' : 'server_hello_done', \
                   'body' :  b'' }, \
                 { 'msg_type' : 'client_key_exchange', \
                   'body' :  self.default_client_key_exchange( **kwargs ) } ]



    def prf_hash_from_cipher( self, cipher_suite):
        """ Returns the prf_hahs associated to the cipher suite

        Args:
            cipher_suite (str): the string representation of the
                cipher suite
    
        Returns:
            prf_hash (str): the prf hash function
        """
        self.check_cipher_suites( [ cipher_suite ] )
        
        if 'SHA512' in cipher_suite:
            return SHA512
        elif 'SHA384' in cipher_suite:
            return SHA384
        else:
            return SHA256

    def prf_hash_from_value( self, prf_hash_value):
        """ Returns the prf_hash associated to the value

        Args:
            prf_hash_value (str): the string representing the prf_hash
                fucntion
    
        Returns:
            prf_hash_funct: the prf hash function
        """
        self.check_prf_hash( prf_hash_value )
        if prf_hash_value == 'sha256':
            return SHA256
        elif prf_hash_value == 'sha384':
            return SHA384
        elif prf_hash_value == 'sha512':
            return SHA512


    # RFC5246 section 5
    def P_hash( self, secret, seed, length, prf_hash):
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
            prf_hash (str): the hash function SHA256, SHA384, SHA512
               from Cryptodome.HASH 

        Returns: 
            output (bin): the extended data
        """
        out = b''
        A = seed
        while len(out) < length :  
            A_next = HMAC.new(secret, digestmod=prf_hash)
            A_next.update( A )

            H = HMAC.new(secret, digestmod=prf_hash)
            H.update( A_next.digest() + seed )
            out += H.digest()
            A = A_next.digest()
        return out[:length]


    def PRF12(self, secret, label, seed, length, prf_hash):
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
        return self.P_hash(secret, label + seed, length, prf_hash)

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

        try: # with poh 
            client_random = request[ 'handshake_messages' ][ 0 ][ 'body' ][ 'random' ]
            server_random = request[ 'handshake_messages' ][ 1 ][ 'body' ][ 'random' ]
            prf_hash = self.prf_hash_from_cipher( \
                 request[ 'handshake_messages' ][ 1 ][ 'body' ]['cipher_suite' ] )
        except KeyError:
            client_random = request [ 'client_random' ]
            server_random = request [ 'server_random' ]
            prf_hash = self.prf_hash_from_value( request [ 'prf_hash' ] )

        server_random = self.pfs( server_random,\
                                       request[ 'freshness_funct' ] )
        
        # section 8.1 RFC5246 
        master = self.PRF12(PreMaster.build(premaster), b'master secret',\
                            Random.build( client_random ) + \
                            Random.build( server_random ), 48, prf_hash )
        return master 


    def compute_finished( self, handshake_messages, master_secret ):
        """ Generates the Finished message

        Args:
            handshake_message (list): array of handshake message
                structures.  
            master_secret (bytes): the master secret

        Returns:
            verify_data (bytes): the byte stream of the Finished message
        """
        finished_label =b'finished_client'
        bytes_handshake = HandshakeMessages.build( handshake_messages )
        cipher_suite = handshake_messages[1][ 'body' ][ 'cipher_suite' ]
        prf_hash = self.prf_hash_from_cipher( cipher_suite ) 
        h = prf_hash.new( bytes_handshake ).digest()
        verify_data_len = 96

        return  self.PRF12( master_secret, finished_label, h,\
                        verify_data_len, prf_hash )

    def check_finished( self, finished, handshake_messages, master_secret ):
        """ Check the value of the Finished message

        Args:
            finished (dict): the dictionary representing the finished
                message structure
            handshake (list): the list of handshake message. Each of
                them represented by their structure as a dictionary. 
            master_secret (bytes): the binary representation of the
                master_secret.

        Raises: 
            InvalidFinished when the computed and the provided
                verify_Data do not match. 
        """
        self.check_key( finished, [ 'verify_data' ])
        l = len( finished[ 'verify_data' ] ) 
        if l != 12 * 8:
            raise InvalidFinished( finished, "Expected len 96, found: %s"%l)
        try:
            # cipher_suite = handshake_messages[ 1 ][ 'body' ][ 'cipher_suite' ]
            ## bytes_handshake = HandshakeMessages.build( handshake_messages )
            c_finished = self.compute_finished( handshake_messages, \
                             master_secret )
            if finished[ 'verify_data' ] != c_finished:
                raise InvalidFinished( finished, "computed finished: %s"%c_finished ) 
        except NameError:
            pass
    
    def default_finished( self, **kwargs ):
        """ Generates a Finished message

        Args:
           kwargs can have multiple arguments. However, some of them are
               mandatory as inputs are necessary to generate the
               finished message. The following cases are considered: 
                   * finished structure is provided, in which case no other  
                       parameters are required.
                   * handshake_messages with (master or premaster)
                      mandatory. freshness_funct is also requires to generate 
                      the finished payload, but the default value is taken. 
                   
            finished (dict): the dictionary representing the Finished
                structure.
        """
        try:
            return kwargs[ 'finished' ]
        except KeyError:
            try:
                handshake_msgs = kwargs[ 'handshake_messages' ]
                cipher = handshake_msgs[ 1 ][ 'body' ][ 'cipher_suite' ]
                prf_hash = self.prf_hash_from_cipher( cipher ) 
            except KeyError:
                raise ImplementationError( kwargs, "Expecting handshake_messages." +\
                     "Not found in kwargs." )

            try:
               master = kwargs[ 'master' ]
            except KeyError:
                try:
                    premaster = kwargs[ 'premaster' ]
                    kwargs[ 'freshness_funct' ] = self.default_freshness_funct( **kwargs )
                    ## freshness_funct is provideed in the request and
                    ## necessary to generate the server_random value.
                    master = self.compute_master( kwargs, premaster )
                except KeyError:
                    raise ImplementationError( kwargs, "unable to generate a valid" +\
                        "Finished message. Arguments 'master' or " +\
                        " 'premaster' and freshness_funct are required.")
            verify_data = self.compute_finished(\
                kwargs[ 'handshake_messages' ] , master)
            return { 'verify_data' : verify_data }

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
       
        self.conf = Tls12RsaMasterConf( conf )
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
            'prf_hash' : self.conf.default_prf_hash( **kwargs ) ,\
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
        keys = [ 'key_id', 'freshness_funct', 'prf_hash', \
                 'client_random', 'server_random', 'encrypted_premaster' ]
        self.conf.check_key( payload, keys )
        self.conf.check_key_id( payload[ 'key_id' ] )
        self.conf.check_freshness_funct( payload[ 'freshness_funct' ] )
        self.conf.check_prf_hash( payload[ 'prf_hash' ] )
        self.conf.check_client_random( payload[ 'client_random' ] )
        self.conf.check_server_random( payload[ 'server_random' ] )
        self.conf.check_encrypted_premaster( payload[ 'encrypted_premaster' ] ) 


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
        self.conf = Tls12RsaMasterConf( conf )
        self.struct = TLS12RSAMasterResponsePayload
        self.struct_name = 'TLS12RSAMasterResponsePayload'

   
    
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

        master = self.conf.compute_master( request, premaster)
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

class Tls12RsaMasterWithPoHRequestPayload(Tls12RsaMasterRequestPayload):

    def __init__(self, conf=LurkConf().get_type_conf( 'tls12', 'v1',
                                             'rsa_master_with_poh')[0] ):
        self.conf =  Tls12RsaMasterConf( conf )
        self.struct = TLS12RSAMasterWithPoHRequestPayload
        self.struct_name = 'TLS12RSAMasterWithPoHRequestPayload'

    def build_payload( self, **kwargs ):
        """ build the RSA master request payload with Proof of Handshake

        Args:
            kwargs may contain multiple arguments

        Returns:
            payload dict) the description of the request

        The generation of the finished message requires:
        either finished to be provided OR premaster and handshake to be
        provided. As these parameters are provided in the packet. They
        cannot be generated independently. 
        * master is generated to be used for both the generation of
            handshake and finished.
        * handshake message is generated so it can be used to generate
        the finished. Note that server_random MUST be updated before
        proceeding to the finished. This is performed in computation of
        the finished
        """
        if 'premaster' not in kwargs.keys() and \
           'master' not in kwargs.keys():
            
            tls_version = { 'major' : "TLS12M", 'minor' : "TLS12m"} 
            premaster = { 'tls_version' : tls_version,\
                          'random' : token_bytes( 46 ) } 
            kwargs[ 'premaster' ] = premaster
        if 'handshake_messages' not in kwargs.keys():
            kwargs[ 'handshake_messages' ]  = self.conf.default_handshake_messages( **kwargs )
           
        return {\
           'key_id' : self.conf.default_key_id( **kwargs) ,\
           'freshness_funct' : self.conf.default_freshness_funct( **kwargs ) ,\
           'handshake_messages' : self.conf.default_handshake_messages( **kwargs ), \
           'finished' : self.conf.default_finished( **kwargs  ) \
        }

    def check( self, payload, crypto_check=False):
        keys = [ 'key_id', 'freshness_funct', 'handshake_messages', 'finished' ]
        self.conf.check_key( payload, keys )
        self.conf.check_key_id( payload[ 'key_id' ] )
        self.conf.check_freshness_funct( payload[ 'freshness_funct' ] )
        self.conf.check_handshake_messages( payload[ 'handshake_messages' ] ) 
##        self.conf.check_finished( payload[ 'finished' ], payload[
##           'handshake_messages' ], master_secret)


class Tls12RsaMasterWithPoHResponsePayload(Tls12RsaMasterResponsePayload):

    def __init__(self, conf=LurkConf().get_type_conf( 'tls12', 'v1',
                                             'rsa_master_with_poh')[0] ):
        self.conf = Tls12RsaMasterConf( conf )
        self.struct = TLS12RSAMasterResponsePayload
        self.struct_name = 'TLS12RSAMasterWithPoHResponsePayload'

    def serve(self, request ):
        master_secret = super().serve( request)[ 'master' ]
        self.conf.check_finished( request[ 'finished' ], \
            request[ 'handshake_messages' ], master_secret)
        return { 'master' : master_secret }
   



class Tls12ExtRsaMasterConf( Tls12RsaMasterConf ):

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

    def compute_master( self, request, premaster):
        """ Computes master secret
 
        Args:
            request (dict): the dictionary representing the rsa master
                request. Note that the request requires to contain the
                freshness_funct as well as the handshake_messages. The 
                latest is used to derive the cipher_suite and the 
                prf_hash as well as the session_hash. Note also that the 
                session hash uses the hash of the server random. The 
                premaster is not decrypted from the encrypted_premaster 
                carried the request and is provided as a separate argument.
                premaster (bin): the premaster secret.

        Returns:
            master_secret (bin): the master secret.
        """
        server_hello = request[ 'handshake_messages' ][ 1 ][ 'body' ]
        prf_hash = self.prf_hash_from_cipher( server_hello[ 'cipher_suite' ] )
        server_random = self.pfs( server_hello[ 'random' ], \
            request[ 'freshness_funct' ] )  
        request[ 'handshake_messages' ][ 1 ][ 'body' ][ 'random' ] = server_random 

        handshake_msgs = HandshakeMessages.build( request[ 'handshake_messages' ] )
        session_hash = prf_hash.new( handshake_msgs ).digest()
        # section 4 RFC7627 
        return self.PRF12(PreMaster.build(premaster), b'extended master secret',\
                            session_hash, 48, prf_hash )


class Tls12ExtRsaMasterRequestPayload(Tls12RsaMasterRequestPayload):

    def __init__(self, conf=LurkConf().get_type_conf( 'tls12', 'v1',
                                             'rsa_extended_master')[0] ):
        self.conf =  Tls12ExtRsaMasterConf( conf )
        self.struct = TLS12ExtendedRSAMasterRequestPayload
        self.struct_name = 'TLS12ExtendedRSAMasterRequestPayload'

    def build_payload( self, **kwargs ):

        return {\
            'key_id' : self.conf.default_key_id( **kwargs) ,\
            'freshness_funct' : self.conf.default_freshness_funct( **kwargs ) ,\
            'handshake_messages' : self.conf.default_handshake_messages( **kwargs )
        }

    def check(self, payload ):
        keys = [ 'key_id', 'freshness_funct', 'handshake_messages' ]
        self.conf.check_key( payload, keys )
        self.conf.check_key_id( payload[ 'key_id' ] )
        self.conf.check_freshness_funct( payload[ 'freshness_funct' ] )
        self.conf.check_handshake_messages( payload[ 'handshake_messages' ] ) 


class Tls12ExtRsaMasterResponsePayload(Tls12RsaMasterResponsePayload):

    def __init__(self, conf=LurkConf().get_type_conf( 'tls12', 'v1',
                                             'rsa_extended_master')[0] ):
        self.conf = Tls12ExtRsaMasterConf( conf )
        self.struct = TLS12RSAMasterResponsePayload
        self.struct_name = 'TLS12RSAMasterResponsePayload'


class Tls12ExtRsaMasterWithPoHRequestPayload(Tls12ExtRsaMasterRequestPayload):

    def __init__(self, conf=LurkConf().get_type_conf( 'tls12', 'v1',
                                             'rsa_extended_master_with_poh')[0] ):
        self.conf =  Tls12ExtRsaMasterConf( conf )
        self.struct = TLS12ExtendedRSAMasterWithPoHRequestPayload
        self.struct_name = 'TLS12ExtendedRSAMasterWithPoHRequestPayload'

    def build_payload( self, **kwargs ):

        if 'premaster' not in kwargs.keys() and \
           'master' not in kwargs.keys():
            tls_version = { 'major' : "TLS12M", 'minor' : "TLS12m"} 
            premaster = PreMaster.build(\
                    { 'tls_version' : tls_version, 'random' : token_bytes( 46 ) } )
            kwargs[ 'premaster' ] = premaster
        payload = super(Tls12ExtMasterRequestPayload, self ).build_payload( **kwargs )
        payload[ 'finished' ] = self.conf.default_finished( self, **kwargs )
        return payload

    def check( self, payload, crypto_check=False):
        keys = [ 'key_id', 'freshness_funct', 'handshake_messages', 'finished' ]
        self.conf.check_key( payload, keys )
        self.conf.check_key_id( payload[ 'key_id' ] )
        self.conf.check_freshness_funct( payload[ 'freshness_funct' ] )
        self.conf.check_handshake_messages( payload[ 'handshake_messages' ] ) 
        self.conf.check_finished( payload[ 'finished' ] )


class Tls12ExtRsaMasterWithPoHResponsePayload(Tls12ExtRsaMasterResponsePayload):

    def __init__(self, conf=LurkConf().get_type_conf( 'tls12', 'v1',
                                             'rsa_extended_master')[0] ):
        self.conf = Tls12ExtRsaMasterConf( conf )
        self.struct = TLS12RSAMasterResponsePayload
        self.struct_name = 'TLS12RSAMasterResponsePayload'

    def serve(self, request ):
        master_secret = super().serve( request)[ 'master' ]
        self.conf.check_finished( request[ 'finished' ], \
            request[ 'handshake_messages' ], master_secret )
        return { 'master' : master }
   


class Tls12EcdheConf ( Tls12RsaMasterConf ):

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
                      'ecdhe_curves', 'poo_prf', 'cipher_suites']
        ## private variables, specify the type of key authorized
        self.key_classes = [  'RsaKey', 'EccKey' ] 

        self.check_conf( conf )

        ## all parameters in the conf are registered in the object
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
        self.cipher_suites = conf[ 'cipher_suites' ]


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
        elif name_curve == 'secp521r1' :
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
            client_public_key = b * curve.g
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
               name_curve = ecdhe_params['curve_param']['curve']
               k = self.get_ec_point_len( name_curve)
               r = randbits(ceil(k/2))
               ##
               ecdhe_public = ecdhe_params['public']
               b = ecdhe_private
               t = c * b + r
               curve = reg.get_curve( name_curve )
               rG = r * curve.g
               tG = t * curve.g
               return { 'poo_prf' : poo_prf, \
                        'rG' : {'form': 'uncompressed', 'x' : rG.x, 'y' : rG.y }, 
                        'tG' : {'form':'uncompressed', 'x' : tG.x, 'y' : tG.y } }

            except NameError:
                raise InvalidPOO( (poo_prf, base, ecdhe_params, ecdhe_private ),\
                          "cannot generate poo " +\
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
        
        data = KeyPairID.build(base['key_id']) +\
               FreshnessFunct.build(base['freshness_funct']) +\
               Random.build(base['client_random']) +\
               Random.build(base['server_random']) +\
               ServerECDHParams.build( ecdhe_params ) + str.encode("tls12 poo")
        c = SHA256.new( data=data ).digest()
        if poo_prf == "sha256_128":
            c = c[ : 128 ]
        elif poo_prf == "sha256_256":
            c = c[ : 256 ]
        else:
            raise InvalidPOOPRF( poo_prf, "supported poo_prf are" +
                                            "null, sha256_128, sha256_256" )
        return int.from_bytes(c, byteorder='big')

class Tls12EcdheRequestPayload(Tls12Payload):

    def __init__(self, conf=LurkConf().get_type_conf('tls12', 'v1', 'ecdhe' )[0] ):
        self.conf = Tls12EcdheConf( conf )
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

    

class Tls12EcdheResponsePayload(Tls12Payload):

    def __init__(self, conf=LurkConf().get_type_conf('tls12', 'v1', 'ecdhe' )[0] ):
        self.conf = Tls12EcdheConf( conf )
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
            ecdhe_params = request[ 'ecdhe_params' ]
            name_curve = ecdhe_params[ 'curve_param' ][ 'curve' ]
            curve = reg.get_curve( name_curve )
            public_key = ecdhe_params[ 'public' ]
            bG = ec.Point( curve, public_key[ 'x'],  public_key[ 'y' ] )
            poo_params = request['poo_params']
            rG = ec.Point( curve, poo_params['rG']['x'], poo_params['rG']['y'] )
            tG = ec.Point( curve, poo_params['tG']['x'], poo_params['tG']['y'] )
            base = { 'key_id' : request['key_id'] ,\
                     'freshness_funct' : request['freshness_funct'] ,\
                     'client_random' : request['client_random'], \
                     'server_random' : request['server_random']}
            c = self.conf.compute_c( poo_prf, base, ecdhe_params )
            if c * bG + rG != tG :
                raise InvalidPOO( ( c * bG + rG, tG ), "Expected Equals" ) 

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

    def __init__( self, conf=LurkConf().get_ext_conf( 'tls12', 'v1') ):
        """ Configuration for Capabilities exchanges

        Args:
            conf (dict): configuration parameters for each extension

        """
        self.check_conf( conf )
        self.conf = conf

    def check_conf( self, conf):
        """ check the configurations
        
        Args:
            conf (dict): configuration diction nary
           
        Raises:
            ConfError when an error occurs.
        """
        for k in conf.keys():
            keys  = [ 'ping', 'rsa_master', 'rsa_master_with_poh', \
                      'rsa_extended_master', 'rsa_extended_master_with_poh', \
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
            if k in [ 'rsa_master', 'rsa_extended_master' ]:
                for type_conf in conf[ k ]:
                ## conf[ k ] is a list of configuration elements
                     Tls12RsaMasterConf().check_conf( type_conf )    
            elif k in [ 'rsa_extended_master', 'rsa_extended_master' ]:
                for type_conf in conf[ k ]:
                     Tls12ExtRsaMasterConf().check_conf( type_conf )    
            elif k in [ 'ecdhe' ] :
                for type_conf in conf[ k ]:
                     Tls12EcdheConf().check_conf( type_conf )    
            

    
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
        """ builds the capabilities response
        
        """
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
                elif mtype in [ 'rsa_master', 'rsa_master_with_poh', \
                                'rsa_extended_master', \
                                 'rsa_extended_master_with_poh', 'ecdhe' ] :
                    capability[ 'key_id_type_list' ] = type_conf[ 'key_id_type' ]
                    capability[ 'cert_list' ] = []
                    for cert in type_conf[ 'cert' ]:
                        try:
                            with open( cert, 'rb') as f:
                                if "key" in cert:
                                    cert_type = "raw_public_key"
                                elif "cert" in cert:
                                    cert_type = "x509"
                                else: 
                                    cert_type = "x509"
                                typed_cert = {'certificate_type' : cert_type, \
                                              'certificate_data' : f.read( ) }
                                capability[ 'cert_list' ].append( typed_cert )
                        except IOError:
                            raise ConfError( cert, "Cannot open file" )
                    capability[ 'freshness_funct_list' ] = type_conf[ 'freshness_funct' ]
                    capability[ 'cipher_suite_list' ] = type_conf[ 'cipher_suites' ]
                    if mtype in [ 'rsa_master', 'rsa_master_with_poh', \
                                  'rsa_extended_master', \
                                  'rsa_extended_master_with_poh' ] :
                        capability[ 'prf_hash_list' ] = type_conf[ 'prf_hash' ]
                        
                    elif mtype == 'ecdhe' :
                        capability[ 'sig_and_hash_list' ] = []
                        for h,s in type_conf[ 'sig_and_hash' ]:
                            capability[ 'sig_and_hash_list' ].append( { 'hash' : h, 'sig' : s } ) 
                        capability[ 'ecdsa_curve_list' ] = type_conf[ 'ecdsa_curves' ]
                        capability[ 'ecdhe_curve_list' ] = type_conf[ 'ecdhe_curves' ]
                        capability[ 'poo_prf_list' ] = type_conf[ 'poo_prf' ]
                    
                payload[ 'capabilities' ].append( capability )
        lurk_state = SHA256.new( str.encode( str( payload ) ) ).digest()[ :4 ]
        payload[ 'lurk_state' ] = lurk_state 
        return payload



class LurkExt:
    def __init__(self, role, conf=LurkConf().get_ext_conf( 'tls12', 'v1' ) ):
        """ Plugs the TLS 1.2 extension into the Lurk framework

        Args:
            conf (dict): the configuration associated to the extension.

        The LurkExt class can be seen as an indirection to the main
        LurkMessage class. The LurkServer receives packets and 
        responds packets. Operations on packets are performed by the 
        LurkMessage class with operations such as parse, build, serve, 
        check, show, build_payload. These modular architecture of Lurk
        requires that LurkMessage operations are delegated to the 
        extensions, that is operations provided by LurkMessage are 
        delegated by the LurkExt for the packet payloads. This class 
        instantiates the necessary functions that LurkMessage needs 
        to delegate to each extensions, that is parse, build, serve,  
        check, show, build_payload.    

        The format of the extension conf is closed to the format of the
        configuration file, but is different. The conf object is derived
        from the configuration file using the get_ext_conf function. 

        The expected configuration object has the following format conf = {
        'ping' : [  {}. ...  {} ], ..., 
        'rsa_master' : [ { conf1_rsa }, { conf2_rsa }, ... ] }. The conf
        object takes the types (i.e. 'rsa_master', 'ecdhe') as key. Each
        type is associated a list of configuration parameters associated 
        to the type. By default ALL configuration parameters of the conf 
        file are provided except: type already provided as in a key as 
        well as (designation, version) that are implied by the module.

        The conf object contains a list of dictionary, so that a given
        lurk server may treat differently different queries. In other 
        words, a 'rsa,master' master request may be treated by one key 
        or the other. The current implementation does not enable this 
        and it is left for future development. 
        """
        Tls12CapabilitiesConf( conf=conf ).check_conf( conf )
        self.conf = conf
        self.ext_class = self.get_ext_class()  

    def get_ext_class(self):
        """ reads the LurkExt.conf object and instantiates the 
            necessary classes of the extension
    
        Returns:
            ext_class (dict): the dictionary that associates the
            appropriated class. In other words, a class that 
            corresponds to the (type, request) and (type, response) 
            is instantiated so incoming packet and outgoing packets 
            can be treated.  
        """
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
        if 'rsa_master_with_poh' in self.conf.keys() :
            ext_class[ ( 'request', 'rsa_master_with_poh' ) ] = \
                Tls12RsaMasterWithPoHRequestPayload( conf=self.conf[ 'rsa_master_with_poh' ][0] )
            ext_class[ ( 'success', 'rsa_master_with_poh' ) ] = \
                Tls12RsaMasterWithPoHResponsePayload( conf=self.conf[ 'rsa_master_with_poh' ][0] )
        if 'ecdhe' in self.conf.keys() :
           ext_class[ ( 'request', 'ecdhe' ) ] = \
               Tls12EcdheRequestPayload( conf=self.conf[ 'ecdhe' ][0] )
           ext_class[ ( 'success', 'ecdhe' ) ] = \
               Tls12EcdheResponsePayload( conf=self.conf[ 'ecdhe' ][0] )
        if 'rsa_extended_master' in self.conf.keys():
            ext_class[ ( 'request', 'rsa_extended_master' ) ] = \
                Tls12ExtRsaMasterRequestPayload( \
                    conf=self.conf[ 'rsa_extended_master' ][0] )
            ext_class[ ( 'success', 'rsa_extended_master' ) ] = \
                Tls12ExtRsaMasterResponsePayload(\
                    conf=self.conf[ 'rsa_extended_master' ][0])
        if 'rsa_extended_master_with_poh' in self.conf.keys():
            ext_class[ ( 'request', 'rsa_extended_master_with_poh' ) ] = \
                Tls12ExtRsaMasterRequestPayload( \
                    conf=self.conf[ 'rsa_extended_master_with_poh' ][0] )
            ext_class[ ( 'success', 'rsa_extended_master_with_poh' ) ] = \
                Tls12ExtRsaMasterResponsePayload(\
                    conf=self.conf[ 'rsa_extended_master_with_poh' ][0])
        return ext_class 

    def check_conf( self, conf):
        """ checks the format of conf
        
        Args:
            conf (dict): the configuration passed to the LurkExt

        Raises:
            ConfError if checks do not pass
        
        """
        for k in conf.keys():
            if k is 'role' :
                if conf[ k ] not in [ 'client', 'server' ]:
                    raise ConfError( conf, "Expecting role in  'client'" +\
                                           "'server'")
            elif k in [ 'ping', 'rsa_master', 'rsa_master_with_poh', \
                        'rsa_extended_master', 'rsa_extended_master_with_poh', \
                        'ecdhe' ]:
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

