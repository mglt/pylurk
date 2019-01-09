from construct.core import *
from construct.lib import *
from os import urandom
from time import time



### structures from TLS 1.2 




## The necessary structure for the handshake are defined 
## in RFC5246
##
## Client                                               Server
## 
## ClientHello                  -------->
##                                                 ServerHello
##                                                Certificate*
##                                          ServerKeyExchange*
##                                         CertificateRequest*
##                              <--------      ServerHelloDone
## Certificate*
## ClientKeyExchange
## CertificateVerify*
## [ChangeCipherSpec]
## Finished                     -------->
##                                          [ChangeCipherSpec]
##                              <--------             Finished
## Application Data             <------->     Application Data
## 
##              Figure 1.  Message flow for a full handshake

### ClientHello

ProtocolVersionMajor = Enum( BytesInteger(1),
    TLS11M = 3,
    TLS12M = 3,
)
ProtocolVersionMinor = Enum( BytesInteger(1),
    TLS11m = 2,
    TLS12m = 3,
)

ProtocolVersion = Struct(
    "major" / Default( ProtocolVersionMajor, "TLS12M"),
    "minor" / Default( ProtocolVersionMinor, "TLS12m")
)

Random = Struct(
    "gmt_unix_time" / Default(Bytes(4),
                              Computed( lambda ctx: int(time())
                                       ).parse(b""), \
                      ), 
    "random" / Default( Bytes(28),
                        Computed( lambda ctx: urandom(28)
                                ).parse(b"") ),
)

SessionID = Prefixed( 
    BytesInteger(1),
    GreedyBytes
)

CipherSuite = Enum ( BytesInteger(2),
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 156, #9c, 
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 157, #9d,
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 158, #9e, 
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 159, #9f, 
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 49195, #c0 2b, 
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 49196, #c0 2c, 
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 =  49197, #c0 2f,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 =  49212, #c0 3c, 
)

CipherSuites = Prefixed(
    BytesInteger(2),
    GreedyRange(CipherSuite)
)

CompressionMethod = Enum ( BytesInteger(2),
    null = 0,
)

CompressionMethods = Prefixed(
    BytesInteger(2),
    GreedyRange(CompressionMethod)
)

ExtensionType = Enum ( BytesInteger(2),
    elliptic_curves = 10, 
    ec_point_formats = 11,
    extended_master_secret = 23,
)

ExtensionData = Prefixed(
    BytesInteger(2),
    GreedyBytes
)

Extension = Struct(
    "extension_type" / ExtensionType,
    "extension_data" / ExtensionData
)

Extensions = Prefixed(
    BytesInteger(2),
    GreedyRange( Extension )
)

ClientHello = Struct(
    "client_version" / ProtocolVersion,
    "random" / Random, 
    "session_id" / SessionID,
    "cipher_suites" / CipherSuites,
    "compression_methods" / CompressionMethods, 
    "extensions" / Extensions
)

### ServerHello

ServerHello = Struct(
    "server_version" / ProtocolVersion, 
    "random" / Random, 
    "session_id" / SessionID, 
    "cipher_suite" / CipherSuite, 
    "compression_method" / CompressionMethod, 
    "extensions" / GreedyRange( Extension )
)

## Certificate 
## already defined 

## ServerKeyExchange
## not sent in the case of RSA
ServerKeyExchange = Const(b"")

## CertificateRequest*
## not provides when the client is not authenticated.
#CertificateRequest = Const(b"")

ServerHelloDone = Const(b"")

### Client Key Exchange

##Certificate*
ASN1Cert = Prefixed(
        BytesInteger(3),
        GreedyBytes,
)

Certificate = Prefixed (
        BytesInteger(3),
        GreedyRange(ASN1Cert)
)

## ClientKeyExchange
## rsa: greedyBytes for EncryptedPremaster
ClientKeyExchange = GreedyBytes

PreMaster = Struct(
    "tls_version" / Default( ProtocolVersion, {} ), 
    "random"  / Default( Bytes(46),
                        Computed( lambda ctx: urandom(46)
                                ).parse(b"") )
)


##CertificateVerify*
## client authentication

Finished = Struct(
    "verify_data" / GreedyBytes
)

HelloRequest = Const(b"")


HandshakeType = Enum( Byte , 
    hello_request = 0, 
    client_hello = 1, 
    server_hello = 2,
    certificate = 11, 
    server_key_exchange = 12,
    certificate_request = 13, 
    server_hello_done = 14,
    certificate_verify = 15, 
    client_key_exchange = 16,
    finished = 20,
)

## this is a bit different from the specification of the RFC as the
## length is included into the body structure. This enable the use of
## the Prefixed structure. The specification has a field "length" that
## is that indicates the size of the body. This was hard to implement 
## as teh length is expressed in bytes.

Handshake = Struct(
    "msg_type" / HandshakeType, 
    "body" / Prefixed(
          BytesInteger(3),
          Switch( this.msg_type, 
          { 
              "hello_request" : HelloRequest,  
              "client_hello" : ClientHello, 
              "server_hello" : ServerHello,
              "certificate" : Certificate,
              "server_key_exchange" : ServerKeyExchange, 
##             "certificate_request" : CertificateRequest, 
              "server_hello_done" : ServerHelloDone, 
##             "certificate_verify" : CertificateVerify, 
              "client_key_exchange" : ClientKeyExchange,
              "finished" : Finished
          } )
          )
    
) 

HandshakeMessages = Array( 5, Handshake ) 
#HandshakeMessagesRSA = Stuct(
#    "client_hello" / ClientHello, 
#    "server_hello" / ServerHello, 
#    "Certificate" / Certificate, 
#    "server_hello_done" / ServerHelloDone, 
#    "client_key_exchange" / ClientKeyExchange
#)



### generic structures for TLS 1.2 Lurk extension

TLS12Status = Enum( Byte, 
    request = 0, 
    success = 1, 
    undefined_error = 2, 
    invalid_payload_format = 3, 
    ## code points for rsa authentication
    invalid_key_id_type = 4, 
    invalid_key_id = 5, 
    invalid_tls_random = 6, 
    invalid_freshness_funct = 7, 
    invalid_encrypted_premaster = 8,
    invalid_finished = 9,
    ## code points for ecdhe authentication
    invalid_ec_type = 10,
    invalid_ec_curve = 11,
    invalid_poo_prf = 12,
    invalid_poo = 13, 
    invalid_cipher_or_prf_hash = 14 
)

TLS12Type = Enum( Byte, 
       capabilities = 0, 
       ping = 1, 
       rsa_master = 2, 
       rsa_master_with_poh = 3, 
       rsa_extended_master = 4, 
       rsa_extended_master_with_poh = 5, 
       ecdhe = 6
)

### structures for RSA Master

KeyPairIDType = Enum( BytesInteger(1),
    sha256_32 = 0
)

KeyPairID = Struct( 
    "key_id_type" / Default( KeyPairIDType, "sha256_32"),
    "key_id" / Switch( this.key_id_type,
        {
        "sha256_32" : Bytes(4)
        }
    )
)

FreshnessFunct = Enum( BytesInteger(1),
    sha256 = 0,
    null = 255, 
)

PRFHash = Enum( BytesInteger(1),
    sha256 = 0,
    sha384 = 1, 
    sha512 = 2
)

TLS12RSAMasterRequestPayload = Struct(
##    Embedded(TLS12Base),
    "key_id" / KeyPairID, 
    "freshness_funct" / FreshnessFunct,
    "prf_hash" / PRFHash,
    "client_random" / Random,
    "server_random" / Random,
    "encrypted_premaster" / GreedyBytes
)

TLS12RSAMasterResponsePayload = Struct( 
    "master" / Default ( Bytes(48), 
                        Computed( lambda ctx: urandom(48)
                                ).parse(b"") )
)

### structure for RSA Master with Proof of Handshake

TLS12RSAMasterWithPoHRequestPayload = Struct(
    "key_id" / KeyPairID , 
    "freshness_funct" / FreshnessFunct,
    "handshake_messages" / HandshakeMessages,
    "finished" / Finished,
)


### structure for Extended RSA

TLS12ExtendedRSAMasterRequestPayload = Struct(
    "key_id" / KeyPairID , 
    "freshness_funct" / FreshnessFunct,
    "handshake_messages" / HandshakeMessages,
)

### structure for Extended RSA with Proof of 

TLS12ExtendedRSAMasterWithPoHRequestPayload = Struct(
    "key_id" / KeyPairID , 
    "freshness_funct" / FreshnessFunct,
    "handshake_messages" / HandshakeMessages,
    "finished" / Finished,
)

### structure for ECDHE

HashAlgorithm = Enum( Byte, 
    none = 0, 
    md5 = 1, 
    sha1 = 2,
    sha224 = 3, 
    sha256 = 4, 
    sha384 = 5, 
    sha512 = 6, 
)

SignatureAlgorithm = Enum( Byte, 
    anonymous = 0, 
    rsa = 1, 
    dsa = 2, 
    ecdsa = 3, 
    ed25519 = 7,
    ed448 = 8
)

SignatureAndHashAlgorithm = Struct(
    "hash" / HashAlgorithm, 
    "sig" / SignatureAlgorithm 
)

SignatureAndHashAlgorithmList = Prefixed(
        BytesInteger(2),
        GreedyRange(SignatureAndHashAlgorithm)
)

NameCurve = Enum ( BytesInteger(1), 
    secp256r1 = 23,
    secp384r1 = 24, 
    secp521r1 = 25,
    x25519 = 29,
    x448 = 30
)


POOPRF = Enum ( BytesInteger( 1 ), 
    null = 0, 
    sha256_128 = 1,
    sha256_256 = 2
)

ECCurveType = Enum ( BytesInteger( 1 ), 
    name_curve = 3
)


# draft-ietf-tls-rfc4492bis section 5.4.1
PointConversionForm = Enum ( BytesInteger( 1 ),
    uncompressed = 4
)

## does not apply for x25519, x448
UncompressedPointRepresentation_256 = Struct(
    "form" / Default( PointConversionForm , "uncompressed"),
    "x" / BytesInteger(32),
    "y" / BytesInteger(32),
)

UncompressedPointRepresentation_384 = Struct(
    "form" / Default( PointConversionForm , "uncompressed"),
    "x" / BytesInteger(48),
    "y" / BytesInteger(48),
)

UncompressedPointRepresentation_512 = Struct(
    "form" / Default( PointConversionForm , "uncompressed"),
    "x" / BytesInteger(64),
    "y" / BytesInteger(64),
)

ECParameters = Struct(
    "curve_type" / Default( ECCurveType, "name_curve"), 
    "curve" / Switch( this.curve_type, 
        {
        "name_curve" : NameCurve
        }
    )
)

ServerECDHParams = Struct(
    "curve_param" / ECParameters,
    "public" / Switch( this.curve_param.curve, 
     { 
         "secp256r1" : UncompressedPointRepresentation_256, 
         "secp384r1" : UncompressedPointRepresentation_384,
         "secp512r1" : UncompressedPointRepresentation_512
     } )
)


TLS12ECDHERequestPayload = Struct(
    "key_id" / KeyPairID , 
    "freshness_funct" / FreshnessFunct,
    "client_random" / Random,
    "server_random" / Random,
    "sig_and_hash" / SignatureAndHashAlgorithm,
    "ecdhe_params" / ServerECDHParams, 
    "poo_params" / Struct( 
        "poo_prf" / Default( POOPRF, "null" ),
        "rG" / IfThenElse( this.poo_prf == 'null', 
             Pass, 
             Switch(this._.ecdhe_params.curve_param.curve, 
                {
                "secp256r1" : UncompressedPointRepresentation_256, 
                "secp384r1" : UncompressedPointRepresentation_384,
                "secp512r1" : UncompressedPointRepresentation_512

               }) ), 
        "tG" / IfThenElse( this.poo_prf == 'null',
              Pass, 
              Switch(this._.ecdhe_params.curve_param.curve, 
                  {
                  "secp256r1" : UncompressedPointRepresentation_256, 
                  "secp384r1" : UncompressedPointRepresentation_384,
                  "secp512r1" : UncompressedPointRepresentation_512

               }) ),
    )    
)

SignedParams = Prefixed(
         BytesInteger(2),
         "signed_params" / GreedyBytes
)

TLS12ECDHEResponsePayload = Struct(
         "signed_params" / SignedParams
)




############# LURKTLSCapabilitiesResponse



KeyPairIDTypeList = Prefixed( 
    BytesInteger(1),
    GreedyRange(KeyPairIDType)
)

CertificateType = Enum ( BytesInteger(2),
    x509 = 0,
    raw_public_key = 2
)

ASN1_subjectPublicKeyInfo = Prefixed(
        BytesInteger(3),
        GreedyBytes,
)


TypedCertificate = Struct(
    "certificate_type" / CertificateType, 
    "certificate_data" / Switch( this.certificate_type, 
        {
        "x509" : ASN1Cert,
        "raw_public_key" :  ASN1_subjectPublicKeyInfo
        })
)

TypedCertificateList = Prefixed(
    BytesInteger(1),
    GreedyRange(TypedCertificate)
)


FreshnessFunctList = Prefixed(
    BytesInteger(1),
    GreedyRange(FreshnessFunct)
)


PRFHashList = Prefixed(
    BytesInteger(1),
    GreedyRange(PRFHash)
)


#CipherSuiteList 
# defined as CipherSuites

TLS12RSACapability = Struct( 
    "key_id_type_list" / KeyPairIDTypeList, 
    "cert_list" / TypedCertificateList,
    "freshness_funct_list" / FreshnessFunctList,
    "cipher_suite_list" / CipherSuites,
    "prf_hash_list" / PRFHashList, 
)


NameCurveList = Prefixed(
    BytesInteger(1),
    GreedyRange(NameCurve)
)



POOPRFList = Prefixed(
    BytesInteger(1),
    GreedyRange(POOPRF)
)


TLS12ECDHECapability = Struct(
    "key_id_type_list" / KeyPairIDTypeList, 
    "cert_list" / TypedCertificateList,
    "freshness_funct_list" / FreshnessFunctList,
    "cipher_suite_list" / CipherSuites,
    "sig_and_hash_list" / SignatureAndHashAlgorithmList,
    "ecdsa_curve_list" / NameCurveList, 
    "ecdhe_curve_list" / NameCurveList, 
    "poo_prf_list" / POOPRFList
)

#Void = Struct()


TLS12Capability = Prefixed( 
    BytesInteger(4),
    Struct(
    "type" / TLS12Type,
     Embedded( Switch( this.type, 
         { 'rsa_master' : TLS12RSACapability, 
           'rsa_master_with_poh' : TLS12RSACapability, 
           'rsa_extended_master' : TLS12RSACapability, 
           'rsa_extended_master_with_poh' : TLS12RSACapability, 
           'ecdhe' : TLS12ECDHECapability  
         }, default=Pass
    ) )
    )
)


TLS12CapabilitiesResponsePayload = Struct( 
    "capabilities" /  GreedyRange( TLS12Capability ), 
    "lurk_state" / Bytes(4)
)
    



