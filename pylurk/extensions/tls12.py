from os.path import isfile, join
from pylurk.extensions.tls12_struct import *
from pylurk.core.lurk import Error, ConfError, ImplementationError, Payload,\
                 LurkConf
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

class InvalidTLSVersion(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_tls_version"

class InvalidTLSRandom(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_tls_random"

class InvalidPRF(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_prf"

class InvalidEncryptedPreMaster(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_encrypted_premaster"

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

class InvalidECPointFormat(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_ec_point_format"

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
             elif "ProtocolVersionMajor" in msg :
                 raise InvalidTLSVersion( value, "invalid major version")
             elif "ProtocolVersionMinor" in msg :
                 raise InvalidTLSVersion( value, "invalid minor version")
             elif "PRFAlgorithm" in msg :
                 raise InvalidPRF( value, "invalid PRF")
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
                           InvalidTLSVersion, InvalidTLSRandom, 
                           InvalidPRF, InvalidECCurve,
                           InvalidECPointFormat, InvalidPOOPRF, InvalidPOO ] :
             pass
         else:
             raise ImplementationError( "type(e): %s --- e.args: %s"%\
                 ( type(e),e.args ), "non LURK Mapping Error" ) 


class Tls12RSAMasterConf:
    ## conf is a dictionary { 'role' : , 'key_id_type' : , 
    ## 'tls_version' :, 'prf' : , 'random_time_window' : , 'cert' : , 
    ## 'check_server_random' : , 'check_client_random' : , 'key' : }
    def __init__(self, conf=LurkConf().get_type_conf( 'tls12', 'v1',
                                              'rsa_master')[0] ):
        self.keys = [ 'role', 'key_id_type' , 'tls_version', 'prf', \
                 'random_time_window', 'cert', 'check_server_random',\
                 'check_client_random' ]
        self.keys = self.get_keys( conf )
        self.check_conf( conf ) 

        self.role = conf[ 'role' ]
        self.cert = conf[ 'cert' ]
        if self.role == "server":
            ## private keys
            self.key =  conf[ 'key' ]

        self.key_id_type = conf[ 'key_id_type' ] 
        self.tls_version = conf[ 'tls_version' ]
        self.prf = conf[ 'prf' ] 
        self.random_time_window = conf[ 'random_time_window' ]
        ## defines authorized certificates mostly concerns the server or
        ## public keys. X509, asn1 using pem/der are valid formats
        self.cert = conf[ 'cert' ]
        self.check_server_random = conf[ 'check_server_random' ]
        self.check_client_random = conf[ 'check_client_random' ]
        ## private variables, specify the type of key authorized
        self.key_classes = [ 'RsaKey' ]
        self.build_key_stores()

    def get_keys( self, conf ):
        if type( conf ) is not dict:
            raise ConfError( conf, "expecting dictionary")
        if 'role' not in conf.keys():
            raise ConfError( conf, "Expected key 'role'.")
        if conf[ 'role' ] == "server":
            self.keys.append( 'key' )
        return self.keys

    def build_key_stores(self ):
        """ building public_key_db and when possible private_key_db """
        ## list of authorized public keys
        self.public_key_db = self.build_public_key_db() 
        if self.role == 'client':
            pass 
        elif self.role == "server":
            ## binding between key_id (binary value) and corresponding
            ## private key 
            self.private_key_db = self.build_private_key_db()
        else: 
            raise ConfError(self.role, "unsupported role expected" +\
                                      " 'client' and 'server' ")
    def check_conf( self, conf ):
        """ check configuration parameters. Thi sincludes parameters
             associated to capabilities as well as those limited to 
             configuration only. """
        if type( conf ) is not dict:
            raise ConfError( conf, "Expected dict" )
        if set( conf.keys() ) != set( self.keys ):
            raise ConfError( conf, "Expected keys: %s"%self.keys )
        self.check_capabilities( conf )
        if conf[ 'role' ] not in [ 'client', 'server' ]:
            raise ConfError( conf, "Expected role value 'client' or 'server' ")
        if conf[ 'role' ] == "server" :
            for key in conf[ 'key' ]:
                 if isfile( key ) == False:
                     raise ConfError( key, "Cannot find the file" )
        for k in [ 'check_server_random', 'check_client_random' ]:
            if conf[ k ] not in [ True, False ]:
                raise ConfError( conf[ k ], "Expected True / False" )

    def check_capabilities( self, conf ):
        """ check the capabilities parameters of the configuration.""" 
        if type( conf ) is not dict:
            raise ConfError( conf, "Expected dict" )
        try :
            for k in [ 'key_id_type' , 'tls_version', 'prf', 'cert']:
                if type( conf[ k ] ) is not list:
                    raise ConfError( conf[ k ], "Expected list" )
            for key_id_type in conf[ 'key_id_type' ] :
                KeyPairIDType.build( key_id_type )
            for tls_version in conf[ 'tls_version' ]:
                if tls_version != 'TLS1.2' :
                    raise ConfError( tls_version, "Expected TLS1.2" )
            for prf in conf[ 'prf' ]:
                self.check_conf_prf( prf ) 
            for cert in conf[ 'cert' ]:
                if isfile( cert ) == False:
                    raise ConfError( cert, "Cannot find the file" )
        except:
            raise ConfError( conf, "Missing parameter. Expected %s"%\
                [ 'key_id_type' , 'tls_version', 'prf', 'cert'] )

    def check_conf_prf( self, prf ):
        prf_values = [ "sha256_null", "sha256_sha256" ] 
        if prf not in prf_values : 
            raise ConfError( prf, "Expected %s"%prf_values )
        
    ### conf  
    def check_key_id_type( self, key_id_type):
        if key_id_type not in self.key_id_type :
            raise InvalidKeyIDType(key_id_type, "unsupported key_id_type")
         

    def read_key( self, key_source ):
        """ return the key object from a file key_source. if key_source is a key
             object return the key.
        """
        
        if isfile( key_source ) :
            try:
                with open(key_source, 'rb' )  as f:
                    return RSA.import_key( f.read() )
            except :
                with open(key_source, 'rb' )  as f:
                    return ECC.import_key( f.read() )
        elif key_source.__class__.__name__ in [ 'RsaKey', 'EccKey' ]:
            return key_source
        else:
            raise ConfError(key_source, "unable to read key from file or" +\
                      " unexpected class -- different from 'RsaKey' and 'EccKey' ")

    def build_key_id( self, key, key_id_type="sha256_32"):
        """ builds and return the key id structure. key can be a file or
            a key object """

        self.check_key_id_type( key_id_type )

        if isfile( str( key) ) == True:
            key = self.read_key( key )
        key_type =  key.__class__.__name__  

        if key_type == 'RsaKey':
            bytes_key =  key.exportKey('DER') 
        elif key_type == 'EccKey':
            bytes_key =  key.export_key(format='DER')
        else:
            raise ConfError(key_type, "unsupported key_type expected" +\
                                      " 'RsaKey' and 'EccKey' ")
        if key_id_type == "sha256_32":
            h = SHA256.new( bytes_key ).digest()[:4]
        else:
            raise ConfError(key_id_type, "unsupported key_id_type " +\
                                          "expected sha256_32")
        return  {'key_id_type' : key_id_type, 'key_id': h }

    def build_public_key_db(self):
        """ builds a database of available public keys for the client
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
        """ builds a database to bind key_id (bytes) with private key """
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
        """ return the private key and the expected length of the
        encrypted premaster """  
        try :
            self.check_key_id_type( key_id[ 'key_id_type' ] )
            return self.private_key_db[ KeyPairID.build( key_id) ]
        except MappingError as e:
            value = e.args[0].split()[4]
            if "KeyPairIDType" in  e.args[0] :
                raise InvalidKeyIDType(key_id_type, "unable to parse")
        except KeyError :
            raise InvalidKeyID()

    def check_key( self, payload, keys):
        """ checks payload got the expected keys"""
        if set( payload.keys() ) != set( keys ):
            raise InvalidPayloadFormat( payload.keys(),   \
                      "Missing or extra key found. Expected %s"%keys)

    def check_key_id(self, key_id ):
        key_id_keys = [ 'key_id_type', 'key_id' ]
        self.check_key( key_id, key_id_keys )

        self.check_key_id_type( key_id[ 'key_id_type' ] )
        if  KeyPairID.build( key_id ) not in self.public_key_db.keys():
            raise InvalidKeyID( key_id, "Corresponding public key unavailable")

    def get_random( self):
        return { 'gmt_unix_time' : int( time() ).to_bytes(4, byteorder='big'), \
                 'random' : token_bytes( 28 ) } 

    def check_random(self, random ):
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

    def check_tls_version(self, tls_version ):
        version_keys = [ 'major', 'minor' ]
        self.check_key( tls_version, version_keys )
        version_db = []
        if "TLS1.2" in self.tls_version:
            version_db.append( ( "TLS12M", "TLS12m" ) )
        if ( tls_version[ 'major' ], tls_version[ 'minor' ] ) not in version_db: 
            raise InvalidTLSVersion( tls_version, "expected %s"%self.tls_version )

    def check_prf( self, prf ):
        if prf not in self.prf:
            raise InvalidPRF( prf, "expected: %s"%self.prf )

    def extract_base( self, payload ):
        """ extract and returns base from payload """
        base_keys = [ 'key_id', 'client_random', 'server_random',
                      'tls_version', 'prf' ]
        base = {}
        try: 
            for k in base_keys :
                base [ k ] = payload[ k ]
            return base
        except KeyError:
            raise InvalidPayloadFormat( payload.keys(), \
                  "Expected keys %s"%base_keys) 

    def check_base( self, payload, key_id=True, client_random=False,
               server_random=True, tls_version=True, prf=True):
        """ pkt is provided as a container with key/value, unless set to
            'False', the value is checked.
        """
        base_keys = [ 'key_id', 'client_random', 'server_random',
                 'tls_version', 'prf' ] 
        self.check_key( payload, base_keys )

        if key_id == True  :
            self.check_key_id( payload[ 'key_id' ] )
        if client_random == True :
            self.check_random( payload[ 'client_random' ] )
        if server_random == True :
            self.check_random( payload[ 'server_random' ] )
        if tls_version == True :
            self.check_tls_version( payload[ 'tls_version' ] )
        if prf == True :
            self.check_prf( payload[ 'prf' ] )

    def get_default_cert( self, **kwargs ):
        if 'cert' in kwargs.keys():
            key = kwargs[ 'cert' ]
        else:
            key = self.cert[0]
        return self.read_key( key )

        
             
    def get_default_base( self, **kwargs ):
        """ builds a base payload given the provided arguments. keywords
            arguments can be 'key_id', 'client_random', 'server_random',
            'tls_version', 'prf'. 
            additional keywords may be provided:
            'cert' with a key, a certificate or a file which indicates
             the data to build teh key id.

             Note that key_id = {'key_id_type' : xxx, 'key_id' : xxx }.
             keywords are only reserved for the first level domain and
             key_id designates the structure.  
        """
        if 'key_id' in kwargs.keys():
             try:
                 self.check_key_id( kwargs[ 'key_id' ] )
                 key_id = kwargs[ 'key_id' ]
             except ( InvalidKeyID, KeyError ) :
                 try:
                     key_id_type =  kwargs[ 'key_id' ][ 'key_id_type' ]
                 except KeyError:
                     key_id_type = "sha256_32"
                 ## default value for key can be provided by 'cert'
                 ## or read from the configuration 
                 if 'cert' in kwargs.keys():
                     key = kwargs[ 'cert' ]
                 else:
                     key = self.get_default_key( **kwargs )
                 key_id = self.build_key_id( key, key_id_type=key_id_type )
        else: 
            key_id_type = "sha256_32"
            ## default value for key can be provided by 'cert'
            ## or read from the configuration 
            if 'cert' in kwargs.keys():
                key = kwargs[ 'cert' ]
            else:
                key = self.cert[0]
            key_id = self.build_key_id( key, key_id_type=key_id_type )

        if 'client_random' in kwargs.keys():
            client_random = kwargs[ 'client_random' ]
        else:
            client_random = self.get_random()
        if 'server_random' in kwargs.keys():
            server_random = kwargs[ 'client_random' ]
        else:
            server_random = self.get_random()
        if 'tls_version' in kwargs.keys():
            tls_version = kwargs[ 'tls_version' ]
        else: 
            tls_version = ProtocolVersion.parse( ProtocolVersion.build( {} ) )
        if 'prf' in kwargs.keys():
            prf = kwargs[ 'prf' ]
        else: 
            prf = self.prf[ 0 ]
        return { 'key_id' : key_id, \
                 'client_random' : client_random, \
                 'server_random' : server_random, \
                 'tls_version' : tls_version, \
                 'prf' : prf }

    def get_pfs_prf_from_prf( self, prf ):
        if prf == "sha256_null":
            return 'null'
        elif prf == "sha256_sha256":
            return "sha256"
        else:
            raise InvalidPRF( prf, 
                "Expected 'sha256_sha256' or 'sha256_null' for RSA" )

    def pfs(self, server_random, prf):
        self.check_prf( prf )
        prf = self.get_pfs_prf_from_prf( prf ) 
        self.check_random( server_random )
        if prf == "null":
            return server_random
        elif prf == "sha256":
            bytes_random = Random.build( server_random )
            gmt_unix_time = bytes_random[0:4]
            bytes_random = bytes_random + str.encode( "tls12 pfs" ) 
            bytes_random = SHA256.new( data=bytes_random).digest()[:32]
            bytes_random = gmt_unix_time + bytes_random[4:]
            return Random.parse(bytes_random)


class Tls12RsaMasterRequestPayload(Tls12Payload):

    def __init__(self, conf=LurkConf().get_type_conf( 'tls12', 'v1',
                                              'rsa_master')[0] ):
        self.conf = Tls12RSAMasterConf( conf )
        self.struct = TLS12RSAMasterRequestPayload

    def build_payload(self, **kwargs ):
        """ build the payload. Arguments not
            provided are replaced by default values. 
            additional keys may be:
            cert: to indicate the rsa public key   
            premaster: the premaster
        """

        ## default value for key can be provided by 'cert'
        ## or read from the configuration 
        if 'cert' in kwargs.keys():
            key_source = kwargs[ 'cert' ]
        else:
            key_source = self.conf.cert[0]
        rsa_public_key = self.conf.read_key( key_source )
         
        if 'encrypted_premaster' in kwargs.keys():
            encrypted_premaster = kwargs[ 'encrypted_premaster' ]
        else:
            if 'premaster' in kwargs.keys():
                premaster =  kwargs[ 'premaster' ]
            else:
                tls_version = ProtocolVersion.parse( ProtocolVersion.build( {} ) )
                premaster = PreMaster.build( { 'tls_version' : tls_version } )
            cipher = PKCS1_v1_5.new(rsa_public_key)      
            encrypted_premaster = cipher.encrypt( premaster )

        base = self.conf.get_default_base( **kwargs )
        return { **base, 'encrypted_premaster' : encrypted_premaster }

    def check_encrypted_master( self, payload):
        ## need to add checks on the encrypted_premaster
        if 'encrypted_premaster' not in payload.keys():
            raise InvalidPayloadFormat( payload.keys(), \
                      "Expected 'encrypted_premaster'") 


    def check(self, payload ):
        base = self.conf.extract_base( payload )
        self.conf.check_base( base,\
                              client_random=self.conf.check_client_random,\
                              server_random=self.conf.check_server_random )
        self.check_encrypted_master( payload) 

class Tls12RsaMasterResponsePayload(Tls12Payload):

    def __init__(self, conf=LurkConf().get_type_conf( 'tls12', 'v1',
                                             'rsa_master')[0] ):
        self.conf = Tls12RSAMasterConf( conf )
        self.struct = TLS12RSAMasterResponsePayload

    # RFC5246 section 5
    def P_SHA256( self, secret, seed, length):
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
        return self.P_SHA256(secret, label + seed, length)
   
    def compute_master( self, request, premaster ):
        server_random = self.conf.pfs( request[ 'server_random' ], request[ 'prf' ] ) 
        # section 8.1 RFC5246 
        return self.PRF12(PreMaster.build(premaster), b'master secret',\
                            Random.build( request [ 'client_random' ] ) + \
                            Random.build( server_random ), 48  )
    
    def serve(self, request ):
        if 'key_id' not in request.keys():
           raise InvalidKeyID( key_id, "No key ID found")
        self.conf.check_key_id( request[ 'key_id' ] )
        private_key = self.conf.get_private_key_from( request[ 'key_id' ] )
        try:
            cipher = PKCS1_v1_5.new(private_key)
            premaster = cipher.decrypt( request[ 'encrypted_premaster' ], None )
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
        if 'master' in kwargs.keys():
            master = kwargs[ 'master' ]
        else:
            master = randbits( 48 * 8 ) 
        return { 'master' : master } 

    def check(self, payload):
        if 'master' not in payload.keys() :
            raise InvalidPayloadFormat( payload.keys(), \
                                        "expecting 'master'") 
        if len( payload[ 'master' ] ) != 48:
            raise InvalidPayloadFormat( len( payload[ 'master' ] ), \
                          "invalid master size. Expecting 48" )

class Tls12RSAExtendedMasterConf( Tls12RSAMasterConf ):

    def __init__( self, conf=LurkConf().get_type_conf('tls12', 'v1', \
                                             'rsa_extended_master' )[0] ):
        conf[ 'check_server_random' ] = False
        conf[ 'check_client_random' ] = False
        conf[ 'random_time_window' ] = 0
        super().__init__( conf )

    def check_conf_prf( self, prf ):
        prf_values = [ "intrinsic_null", "intrinsic_sha256" ] 
        if prf not in prf_values : 
            raise ConfError( prf, "Expected %s"%prf_values )

class Tls12ExtMasterRequestPayload(Tls12RsaMasterRequestPayload):

    def __init__(self, conf=LurkConf().get_type_conf( 'tls12', 'v1',
                                             'rsa_extended_master')[0] ):
        self.conf =  Tls12RSAExtendedMasterConf( conf )
        self.struct = TLS12ExtendedRSAMasterRequestPayload

    def build_payload( self, **kwargs ):
        payload = super( Tls12ExtMasterRequestPayload, self ).build_payload( **kwargs )
        del payload[ 'client_random' ]
        del payload[ 'server_random' ]
        if 'session_hash' in kwargs:
            payload[ 'session_hash' ] = kwargs[ 'session_hash' ]
        else:
            payload[ 'session_hash' ] = SessionHash.build( token_bytes(32) )
        return payload

    def check(self, payload ):
        base_keys = [ 'key_id', 'tls_version', 'prf', 'session_hash']
        base = {}
        try: 
            for k in base_keys :
                base [ k ] = payload[ k ]
            return base
        except KeyError:
            raise InvalidPayloadFormat( payload.keys(), \
                  "Expected keys %s"%base_keys) 
        self.conf.check_base( base,\
                              client_random=self.conf.check_client_random,\
                              server_random=self.conf.check_server_Random )
        self.check_encrypted_master( payload ) 
    

class Tls12ExtMasterResponsePayload(Tls12RsaMasterResponsePayload):

    def __init__(self, conf=LurkConf().get_type_conf( 'tls12', 'v1',
                                             'rsa_extended_master')[0] ):
        self.conf = Tls12RSAExtendedMasterConf( conf )
        self.struct = TLS12RSAMasterResponsePayload

    def compute_master( self, request, premaster ):
        # section 4 RFC7627 
        return self.PRF12(PreMaster.build(premaster), b'extended master secret',\
                            request [ 'session_hash' ], 48  )

class Tls12ECDHEConf ( Tls12RSAMasterConf ):

    def __init__(self, conf=LurkConf().get_type_conf('tls12', 'v1', 'ecdhe' )[0] ):
        self.keys = [ 'role', 'key_id_type' , 'tls_version', 'prf', \
                      'random_time_window', 'cert', 'check_server_random',\
                      'check_client_random', 'sig_and_hash', 'ecdsa_curves', \
                      'ecdhe_curves', 'poo_prf' ]
        self.keys = self.get_keys( conf )
        self.check_conf( conf ) 
        self.role = conf[ 'role' ]
        self.cert =  conf[ 'cert' ]
        if self.role == "server":
            ## private keys
            self.key =  conf[ 'key' ]
        self.key_id_type = conf[ 'key_id_type' ]
        self.tls_version = conf[ 'tls_version' ]
        self.prf = conf[ 'prf' ] 
        self.random_time_window = conf[ 'random_time_window' ]
        self.sig_and_hash = conf[ 'sig_and_hash' ] 
        self.ecdsa_curves = conf[ 'ecdsa_curves' ]
        self.ecdhe_curves = conf[ 'ecdhe_curves' ] 
        self.poo_prf = conf[ 'poo_prf' ]


        ## private variables, specify the type of key authorized
        self.key_classes = [  'RsaKey', 'EccKey' ] 
        ## defines authorized certificates mostly concerns the server or
        ## public keys. X509, asn1 using pem/der are valid formats
        self.build_key_stores()

    def check_conf_prf( self, prf ):
        prf_values = [ "intrinsic_null", "intrinsic_sha256" ] 
        if prf not in prf_values : 
            raise ConfError( prf, "Expected %s"%prf_values )

    def check_conf( self, conf):
        super().check_conf( conf )

    def check_capabilities(self, conf ):
        super().check_capabilities( conf )
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
        sig_and_hash_keys = [ 'hash', 'sig' ]
        self.check_key( sig_and_hash, sig_and_hash_keys )  
        
        if ( sig_and_hash[ 'hash' ], sig_and_hash[ 'sig' ] ) not in self.sig_and_hash :
            raise InvalidSigAndHash( sig_and_hash, \
                        "Expecting %s"%self.sig_and_hash )
        ## checking compatibility betwen sig / key
        for cert in self.cert :
            self.get_default_sig_and_hash( cert=cert )

    def get_default_sig_and_hash( self, **kwargs ):
        key = self.get_default_cert( **kwargs )
        key_type = key.__class__.__name__ 
        if key_type == 'RsaKey' :
            target_sig = 'rsa'
        elif key_type == 'EccKey':
            target_sig = 'ecdsa'
        for h, s in self.sig_and_hash :
            if s == target_sig :
                return  s, h
        raise ConfError( ( key_type, self.sig_and_hash), \
                           "Non compatible signature and key")

    def get_ec_point_len( self, name_curve ): 
        """ returns the len in bits for the x and y. """
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
        """ check the EC Point format. ec_len designates in bits the
             expected len of x and the expected len of y. The length 
             is provided by the curve. """ 
        ec_point_keys = [ 'form', 'x', 'y' ]
        self.check_key( ec_point, ec_point_keys )  
        if ec_point[ 'form' ] != "uncompressed" :
            raise InvalidECPointFormat( ec_point[ 'form' ], \
                      "expected 'uncompressed' " )
        if ec_point[ 'x' ] > 2 ** ec_len or ec_point[ 'y' ] > 2 ** ec_len:
            raise InvalidECPointFormat( ( ec_point[ 'x' ], ec_point['y'] ) , \
                "Unexpected large values" )


    def check_ecdhe_params(self, ecdhe_params):
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


    def check_poo_params( self, poo_params, ec_len=512 ):
        ## the current version includes always the rG / tG these keys
        ## are empty when associated with 'null'. future version should
        ## remove these fields completely. 
        poo_keys = [ 'poo_prf', 'rG', 'tG' ]
        self.check_key( poo_params, poo_keys )
        poo_prf = poo_params[ 'poo_prf' ]
        if poo_prf not in self.poo_prf:
            raise InvalidPOOPRF( poo_prf, "Expected %s"%self.poo_prf)
        if poo_prf == 'null' :
            if poo_params[ 'rG' ] != None or poo_params[ 'tG' ] != None:
                raise InvalidPOO(poo_prf, "Expected void 'rG' and 'tG'" )
            
        if poo_prf in [ "sha256_128", "sha256_256" ]:
            ec_point_keys = [ 'form', 'x', 'y' ]
            rG = poo_params[ 'rG' ]
            tG = poo_params[ 'tG' ]
            for ec_point in [ rG, tG ]:
                self.check_ec_point( ec_point, ec_len=ec_len)

    def get_pfs_prf_from_prf( self, prf ):
        if prf == "intrinsic_null":
            return 'null'
        elif prf == "intrinsic_sha256":
            return "sha256"
        else:
            raise InvalidPRF( prf, 
                "Expected 'intrinsic_sha256' or 'intrinsic_null' for ECDSA" )

    def compute_c( self, poo_prf, base, ecdhe_params):
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


    def build_payload( self, **kwargs):
        base = self.conf.get_default_base( **kwargs )
        if 'ecdhe_params' in kwargs.keys():
            ecdhe_params = kwargs[ 'ecdhe_params' ]
        else:
            ## ecdhe illustration  https://wiki.osdev.org/TLS_Handshake
            name_curve = self.conf.ecdhe_curves[ 0 ] 
            curve = reg.get_curve( name_curve )
            k = self.conf.get_ec_point_len( name_curve )
            b = randbits( k )
            client_public_key = curve.g * b
            ec_params = { 'curve_type' : "name_curve", 'curve' : name_curve }
            ec_point = { 'form' : "uncompressed", \
                         'x' : client_public_key.x, \
                         'y' : client_public_key.y }

            ecdhe_params = { 'curve_param' : ec_params, \
                             'public' : ec_point } 
        if 'sig_and_hash' in kwargs.keys():
            sig_and_hash = kwargs[ 'sig_and_hash' ]
        else:
            ## taking the same key as in base
            s, h = self.conf.get_default_sig_and_hash( **kwargs ) 
            sig_and_hash = { 'hash' : h, 'sig' : s }
        if 'poo_params' in kwargs.keys():
            poo_params = kwargs[ 'poo_params' ]
        else:
            poo_prf = self.conf.poo_prf[0]
            if poo_prf == 'null': ## woudl be better to remove the rG, tG
                poo_params = { 'poo_prf' : "null" , 'rG' : None, 'tG' : None}
            elif poo_prf in [ "sha256_128", "sha256_256" ]:
                ## needs to know the secret b so can only be
                ## generated if the ecdhe parameters have been 
                ## generated 
                try : 
                   c = self.conf.compute_c( poo_prf, base, ecdhe_params )
                   r = randbits( k / 2 ) 
                   t = c * b + r
                   rG = r * curve.g
                   tG = t * curve.g
                   poo_param = { 'poo_prf' : poo_prf, \
                                 'rG' : { 'x' : rG.x, 'y' : rG.y }, 
                                 'tG' : { 'x' : tG.x, 'y' : tG.y } }
                except NameError:
                    raise InvalidPOO( kwargs, "cannot generate poo " +\
                              "generating echde_params. Please either " +\
                              "provide both of them or none." )
            else:
                raise InvalidPOOPRF( poo_prf, "supported poo_prf are" +
                                     "null, sha256_128, sha256_256" )
        return  { **base, \
                 'sig_and_hash' : sig_and_hash, \
                 'ecdhe_params' : ecdhe_params, \
                 'poo_params' : poo_params }
        

    def check( self, payload):
        base = self.conf.extract_base( payload)
        self.conf.check_base( base )
        self.conf.check_sig_and_hash( payload[ 'sig_and_hash' ] )
        name_curve = payload[ 'ecdhe_params' ][ 'curve_param' ][ 'curve' ]
        ec_len = self.conf.get_ec_point_len( name_curve )
        self.conf.check_ecdhe_params( payload[ 'ecdhe_params' ] )
        self.conf.check_poo_params( payload[ 'poo_params' ] )

    

class Tls12ECDHEResponsePayload(Tls12Payload):

    def __init__(self, conf=LurkConf().get_type_conf('tls12', 'v1', 'ecdhe' )[0] ):
        self.conf = Tls12ECDHEConf( conf )
        self.struct = TLS12ECDHEResponsePayload

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

        server_random = self.conf.pfs( request[ 'server_random' ], request['prf'] ) 

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
                     Tls12RSAMasterConf().check_capabilities( type_conf )    
            elif k == "rsa_extended_master":
                for type_conf in conf[ 'rsa_extended_master' ]:
                     Tls12RSAExtendedMasterConf().check_capabilities( type_conf )    
            elif k == "ecdhe" :
                for type_conf in conf[ 'ecdhe' ]:
                     Tls12ECDHEConf().check_capabilities( type_conf )    
            

    
class Tls12CapabilitiesResponsePayload(Tls12Payload):

    def __init__(self, conf=LurkConf().get_ext_conf( 'tls12', 'v1' ) ):
        self.conf = Tls12CapabilitiesConf( conf=conf )
        self.capabilities = self.set_capabilities()
        self.struct = TLS12CapabilitiesResponsePayload 


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
                    for v in type_conf[ 'tls_version' ]:
                        if v == "TLS1.2":
                            capability[ 'tls_version' ].append( { 'major' : "TLS12M", \
                                                              'minor' : "TLS12m" } )
                        else:
                            raise ConfError( type_conf[ 'tls_version' ], "Expecting TLS12" ) 
                    capability[ 'prf' ] = type_conf[ 'prf' ]
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

    def show( self, status, mtype, pkt_bytes ):
        return self.ext_class[ ( status, mtype ) ].show( pkt_bytes )

    def build_payload( self, status, mtype, payload ):
        return self.ext_class[ ( status, mtype ) ].build_payload( **kwargs )

