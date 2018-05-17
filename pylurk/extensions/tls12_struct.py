from construct.core import *
from construct.lib import *
from os import urandom
from time import time



TLS12Status = Enum( Byte, 
    request = 0, 
    success = 1, 
    undefined_error = 3, 
    invalid_payload_format = 3, 
    ## code points for rsa authentication
    invalid_key_id_type = 4, 
    invalid_key_id = 5, 
    invalid_tls_version = 6, 
    invalid_tls_random = 7, 
    invalid_prf = 8, 
    invalid_encrypted_premaster = 9, 
    ## code points for ecdhe authentication
    invalid_ec_type = 10,
    invalid_ec_basistype = 11, 
    invalid_ec_curve = 12,
    invalid_ec_point_format = 13,
    invalid_poo_prf = 138,
    invalid_poo = 139
)


TLS12Type = Enum( Byte, 
       capabilities = 0, 
       ping = 1, 
       rsa_master = 2, 
       rsa_extended_master = 3, 
       ecdhe = 4
)

############# LURKTLSCapabilitiesResponse


ASN1Cert = Prefixed(
        BytesInteger(3),
        GreedyBytes,
)

Certificate = Prefixed (
        BytesInteger(3),
        GreedyRange(ASN1Cert)
)

KeyPairIDType = Enum( BytesInteger(1),
    sha256_32 = 0
)

KeyPairIDTypeList = Prefixed( 
    BytesInteger(1),
    GreedyRange(KeyPairIDType)
)

ProtocolVersionMajor = Enum( BytesInteger(1),
    TLS11M = 3,
    TLS12M = 3,
)
ProtocolVersionMinor = Enum( BytesInteger(1),
    TLS11m = 3,
    TLS12m = 3,
)

ProtocolVersion = Struct(
    "major" / Default( ProtocolVersionMajor, "TLS12M"),
    "minor" / Default( ProtocolVersionMinor, "TLS12m")
)

ProtocolVersionList = Prefixed(
    BytesInteger(1),
    GreedyRange(ProtocolVersion)    
)

PRFAlgorithm = Enum( BytesInteger(1),
    sha256_null = 0,
    sha256_sha256 = 1, 
    intrinsic_null = 2, 
    intrinsic_sha256 = 2, 
)

PRFAlgorithmList = Prefixed(
    BytesInteger(1),
    GreedyRange(PRFAlgorithm)
)

TLS12RSACapability = Struct( 
    "key_id_type" / KeyPairIDTypeList, 
    "tls_version" / ProtocolVersionList,
    "prf" / PRFAlgorithmList,
    "cert" / Certificate, 
)




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
    secp512r1 = 25,
    x25519 = 29,
    x448 = 30
)

NameCurveList = Prefixed(
    BytesInteger(1),
    GreedyRange(NameCurve)
)

POOPRF = Enum ( BytesInteger( 1 ), 
    null = 0, 
    sha256_128 = 1,
    sha256_256 = 2
)

POOPRFList = Prefixed(
    BytesInteger(1),
    GreedyRange(POOPRF)
)


TLS12ECDHECapability = Struct(
    Embedded( TLS12RSACapability ), 
    "sig_and_hash" / SignatureAndHashAlgorithmList,
    "ecdsa_curves" / NameCurveList, 
    "ecdhe_curves" / NameCurveList, 
    "poo_prf" / POOPRFList
)

Void = Struct()


TLS12Capability = Prefixed( 
    BytesInteger(4),
    Struct(
    "type" / TLS12Type,
     Embedded( Switch( this.type, 
         { 'rsa_master' : TLS12RSACapability, 
           'rsa_extended_master' : TLS12RSACapability, 
           'ecdhe' : TLS12ECDHECapability  
         }, default=Pass
    ) )
    )
)


TLS12CapabilitiesResponsePayload = Struct( 
    "capabilities" /  GreedyRange( TLS12Capability ), 
    "lurk_state" / Bytes(4)
)
    

############# LURKTLSRSAMasterRequest




KeyPairID = Struct( 
    "key_id_type" / Default( KeyPairIDType, "sha256_32"),
    "key_id" / Switch( this.key_id_type,
        {
        "sha256_32" : Bytes(4)
        }
    )
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


PreMaster = Struct(
    "tls_version" / Default( ProtocolVersion, {} ), 
    "random"  / Default( Bytes(46),
                        Computed( lambda ctx: urandom(46)
                                ).parse(b"") )
)



TLS12Base = Struct(
    "key_id" / KeyPairID , 
    "client_random" / Random,
    "server_random" / Random,
    "tls_version" /  ProtocolVersion, 
    "prf" / PRFAlgorithm
)

TLS12RSAMasterRequestPayload = Struct(
    Embedded(TLS12Base),
    "encrypted_premaster" / GreedyBytes
)

TLS12RSAMasterResponsePayload = Struct( 
    "master" / Default ( Bytes(48), 
                        Computed( lambda ctx: urandom(48)
                                ).parse(b"") )
)

## Extended master

SessionHash = Prefixed(
         BytesInteger(2),
         "session_hash" / GreedyBytes
)


TLS12ExtendedRSAMasterRequestPayload = Struct(
    "key_id" / KeyPairID , 
    "tls_version" /  ProtocolVersion, 
    "prf" / PRFAlgorithm,
    "session_hash" / SessionHash,
    "encrypted_premaster" / GreedyBytes
)




## ServerECDHParams is described in order to enable format validation.


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
    Embedded(TLS12Base),
    "sig_and_hash" / SignatureAndHashAlgorithm,
    "ecdhe_params" / ServerECDHParams, 
    "poo_params" / Struct( 
        "poo_prf" / Default( POOPRF, "null" ),
        "rG" / IfThenElse( this.poo_prf == 'null', 
             Pass, 
             Switch( this.ecdhe_params.curve_param.curve, 
                {
                "secp256r1" : UncompressedPointRepresentation_256, 
                "secp384r1" : UncompressedPointRepresentation_384,
                "secp512r1" : UncompressedPointRepresentation_512

               }) ), 
        "tG" / IfThenElse( this.poo_prf == 'null',
              Pass, 
              Switch( this.ecdhe_params.curve_param.curve, 
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


