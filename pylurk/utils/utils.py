import sys
import os
##sys.path.append(os.path.abspath("../"))

from os.path import isfile
from pylurk.core.lurk import *
from Cryptodome.PublicKey import RSA, DSA, ECC
from Cryptodome.Hash import HMAC, SHA256, SHA512
from Cryptodome.Signature import pkcs1_15, DSS
from Cryptodome.Cipher import PKCS1_v1_5


import binascii


## client server high level testing


def check_request_response( request, response, designation, \
                            version, mtype ):
    if request[ 'designation' ] != designation : 
        raise ImplementationError( request, \
            "Expected designation : %s."%designation )
    if request[ 'version' ] != version : 
        raise ImplementationError( request, \
            "Expected version : %s."%version )
    if request[ 'status' ] != 'request' :\
        raise ImplementationError( request, \
            "Expected status : 'request'")
    if request[ 'type' ] != mtype :\
        raise ImplementationError( request, \
            "Expected type : %s"%mtype)
    if response[ 'designation' ] != designation : 
        raise ImplementationError( response, \
            "Expected designation : %s."%designation )
    if response[ 'version' ] != version : 
        raise ImplementationError( response, \
            "Expected version : %s."%version )
    if response[ 'status' ] != 'success' :\
        raise ImplementationError( response, \
            "Expected status : 'success'")
    if request[ 'type' ] != mtype :\
        raise ImplementationError( response, \
            "Expected type : %s"%mtype)
    #converting id to int
    for message in [ request, response ]:
        if type( message[ 'id' ] ) == bytes:
            message[ 'id' ] = int.from_bytes( message[ 'id' ], 'big' )

    if request[ 'id' ] != response[ 'id' ] :
        raise ImplementationError( (request[ 'id'], response[ 'id' ] ),\
            "Expected matching id" )

def message_exchange( designation, version, mtype,  \
                 payload={} ):
    """ generates an prints a valid query / response using LurkMessage  """
    print("\n-- testing: desig.: %s, vers.: %s "%(designation, version) +\
          "mtype: %s"%(mtype))
    print( ">> Request")
    msg = LurkMessage()
    header = {}
    header[ 'designation' ]  = designation
    header[ 'version' ] = version
    header[ 'type' ] = mtype
    header[ 'status' ]  = "request"
    print( " basic_exchange: header : %s"%header )
    request_bytes = msg.build( **header, payload=payload   ) 
    msg.show( request_bytes )
    request = msg.parse( request_bytes )
    
    print("<< Response")
    response = msg.serve( request )
    response_bytes = msg.build( **response )
    msg.show( response_bytes )
    
    check_request_response( request, response, designation, \
                            version, mtype )

def resolve_exchange( client, server, designation, version, mtype,  \
                 payload={} ):
    """ generates an prints a valid query / response using resolve  """
    print("-- testing: desig.: %s, vers.: %s "%(designation, version) +
          "mtype: %s"%(mtype))
    request, response = client.resolve( designation=designation, \
                                      version=version,\
                                      status="request", \
                                      type=mtype, payload=payload ) 
    msg = LurkMessage()
    print( ">> Request")
    msg.show( request )
    print( "<< Response")
    msg.show( response )
    print( "\n" )

    check_request_response( request, response, designation, \
                            version, mtype )



## server byte level testing


def bytes_error( bytes_ref, error_index, error_value='\xf0'):
   last_index = len( bytes_ref )
   if error_index == last_index:
        return bytes_ref[: last_index ] + value
   elif error_index >= 0 and error_index < last_index:
        return bytes_ref[: error_index] + value + bytes_ref[ error_index + 1 : ] 



def bytes_error_testing( server,  bytes_query_ref, error_table):
    msg = LurkMessage()
    for e in error_table:
        print("--- %s Error Testing"%e[0])
        for byte_index in  range(e[1] - e[2] ):
            response_bytes = server.byte_serve( bytes_error( bytes_query_ref,\
                                           byte_index ) ) 
            response = msg.parse( response_bytes ) 
            if response[ 'status' ] != error_status:
                raise ImplementationError( msg.show( response_bytes ), "expected %s"%e[3] )
               

def get_key_files( key_type, key_scope, key_format='der' ):
    """ check parameters for generate_keys and generate_x509 and returns
        key file names public, private """

    key_types  = [ 'rsa', 'dsa', 'ecc' ]
    if key_type not in [ 'rsa', 'dsa', 'ecc' ]:
        raise ConfError( key_type, "Expecting %s"%key_types )
    key_formats = [ 'der', 'pem' ]
    if key_format not in key_formats:
        raise ConfError( key_format, "Expecting %s"%key_formats )
    key_scopes = [ 'sig', 'enc' ]
    if key_scope not in key_scopes:
        raise ConfError( key_scope, "Expecting %s"%key_scope )
    file_pbl = "key-%s-%s-asn1.%s"%( key_type, key_scope, key_format)
    file_prv = "key-%s-%s-pkcs8.%s"%( key_type, key_scope, key_format)
    return file_pbl, file_prv

def generate_keys( key_type, key_scope, key_format='der' ):
    """ generates private and public keys:
        - key_type designates the type of the key: 'rsa', 'dsa', 'ecc'
        - key_format designates the key representation 'der' or 'pem'
        - key_scope designates the scope of the key: 'sig', 'enc' -- this is
          mostly for naming convention
        output files are:
            key-<key_type>-<key_scope>-{pkcs8,asn1}.<key_format>
    """
    pbl, prv = get_key_files( key_type, key_scope, key_format=key_format )

    if key_format == 'der':
        key_format = 'DER' 
    if key_format == 'pem':
        key_format = 'PEM'

    if key_type == 'rsa':
        key = RSA.generate(2048)
        bytes_prv = key.exportKey( key_format, pkcs=8)
        bytes_pbl = key.publickey().exportKey( key_format )
    elif key_type == 'dsa':
        key = DSA.generate(2048)
        bytes_prv = key.exportKey( key_format, pkcs8=True)
        bytes_pbl = key.publickey().exportKey( key_format)
    elif key_type == 'ecc':
        key = ECC.generate(curve='P-256')
        bytes_prv = key.export_key( format=key_format, use_pkcs8=True ) 
        bytes_pbl = key.public_key().export_key( format=key_format )
    else:
        raise ImplementationError( key_type, "Unknown key type" )

    with open( prv, 'wb' )  as f:
        f.write( bytes_prv )
    with open( pbl, 'wb' )  as f:
        f.write( bytes_pbl )

def get_keys(  key_type, key_scope, key_format='der' ):

    from cryptography.hazmat.primitives.serialization import \
        load_der_private_key, load_der_public_key, load_pem_private_key,\
        load_pem_public_key
    from cryptography.hazmat.backends import default_backend
    pbl, prv = get_key_files( key_type, key_scope, key_format=key_format )

    for file_name in [ pbl, prv ]:
        if isfile( file_name ) == False:
            generate_keys( key_type, key_scope, key_format=key_format )

    if key_format == 'der' :
        with open( prv, 'rb' )  as f:
            private_key = load_der_private_key( f.read(), \
                          password=None, backend=default_backend() )
        with open( pbl, 'rb' )  as f:
            public_key = load_der_public_key( f.read(), \
                          backend=default_backend() )
    elif key_format == 'pem' :
        with open( prv, 'rb' )  as f:
            privet_key = load_pem_private_key( f.read(), \
                          password=None, backend=default_backend() )
        with open( pbl, 'rb' )  as f:
            public_key = load_pem_public_key( f.read(), \
                          backend=default_backend() )
    
    return public_key, private_key


def generate_x509( key_type, key_scope, key_format='der' ):

    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime
    from cryptography.hazmat.primitives import serialization


    public_key, private_key = get_keys( key_type, key_scope, \
                                        key_format=key_format )

    subject = x509.Name([\
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CA"),\
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"QC"),\
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Montreal"),\
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),\
        x509.NameAttribute(NameOID.COMMON_NAME, u"www.example.com"),\
      ])

    issuer = subject
    builder = x509.CertificateBuilder()
    builder = builder.subject_name( subject )
    builder = builder.issuer_name( issuer )
    #builder.public_key( public_key.public_key() )
    builder = builder.public_key( public_key )
    builder = builder.serial_number( x509.random_serial_number() )
    builder = builder.not_valid_before( datetime.datetime.utcnow() )
    builder = builder.not_valid_after( 
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=365 * 100 ) )
    builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"www.example.com")]),
            critical=False )
    # Sign our certificate with our private key
    cert = builder.sign( private_key, hashes.SHA256(), default_backend())
    # Write our certificate out to disk.
    cert_file = "cert-%s-%s.%s"%( key_type, key_scope, key_format)

    with open(cert_file, "wb") as f:
        if key_format == 'pem' :
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        if key_format == 'der' :
            f.write(cert.public_bytes(serialization.Encoding.DER))


## we are missing the edge_server
def vector_rsa_master( _cert, _premaster, _encrypted_premaster,\
                       _client_random, _server_random, _master,  \
                        key, lurk_rsa_conf ):
    """ test vector for rsa_master. "_" designates the measured
        informations by for example an ngnix / apache implementation. 
            - _cert:  public key or certificate used by the TLS Client
            - _premaster generated by the TLS client
            - _encrypted_premaster encrypted premaster provided by the 
              TLS Client
            - {_client, _server}_random : random used
            - key : private key used by the TLS Server
            - lurk_rsa_conf : 
    """

    print("\n --- checking compatibility between key / _cert" )
    lurk_rsa_conf.cert = [ _cert ]
    lurk_rsa_conf.key = [ key ]
    conf = Tls12RSAMasterConf( conf=lurk_rsa_conf)
    public_key = conf.read_key( _cert )
    private_key = conf.read_key( key )
    
    print("\n --- RSA Public / Private Keys" )
    for k in [ public_key, private_key ]:
        if k.has_private() == False:
           print( "    Public Key: %s"%{'n': k.n, 'e': k.e} )
        else:
           print("    Private Key: %s"%\
               {'n' : k.n, 'e' : k.e, 'd' : k.d, 'p' : k.p, 'q' : k.q} )

    print("\n --- checking encrypted premaster / premaster" )
    rsa_cipher = PKCS1_v1_5.new(public_key) 
    encrypted_premaster = rsa_cipher.encrypt( _premaster_secret ) 
    if encrypted_premaster != _encrytped_premaster:
        raise ImplementationError( (encrypted_premaster,_encrytped_premaster), \
            "Encrypting premaster with key does not result in measured " + \
            "_encrypted_premaster")

    rsa_cipher = PKCS1_v1_5.new(private_key)
    premaster = rsa_cipher.decrypt(_encrypted_premaster, b'\x00')
    if premaster != _premaster:
        raise ImplementationError( (premaster,_premaster), \
            "Decrypting _encrypted_premaster with key does not result " +\
            "in measured _premaster")

    
    print("\n --- parameters")
    premaster = Premaster.parse(_premaster )
    print("\n    - Premaster : %s"%binascii.hexlify(_premaster) )
    print("\n    - Premaster : %s"%premaster )
    print("\n    - EncryptedPremaster : %s"%binascii.hexlify(_encrypted_premaster) )
    client_random = Random.parse( _client_random )
    server_random = Random.parse( _server_random )
    print("\v    - Client Random: %s"%binascii.hexlify(_client_random ) )
    print("\v    - Client Random: %s"%client_random )
    print("\v    - Server Random: %s"%binascii.hexlify(_server_random ) )
    print("\v    - Server Random: %s"%server_random )

    ## would be good to also test with edge server... 
    payload_args = { 'cert' : _cert,\
                     'client_random' : client_random, \
                     'server_random' : server_random, \
                     'tls_version' : tls_version, \
                     'prf' : "sha256_null",
                     'encrypted_premaster' : encrypted_premaster }
    query, response = client.resolve( designation='tls12', \
                                  version='v1', \
                                  type='rsa_master', \
                                  payload=payload_args )

    master = binascii.hexlify( response[ 'master' ] )

    if master != _master:
        raise ImplementationError( (master,_master), \
            "ERROR: _master and master do not match!")
    print("\v    - Master: %s"%binascii.hexlify(_server_random ) )
    print("\v    - Server Random: %s"%server_random )


    print("LURK Query >>>>")
    msg.show( query )
    print("LURK Response <<<<")
    msg.show( response )




