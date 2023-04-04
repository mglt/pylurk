This module is the LURK implementation in Python

The current branch implements LURK as specified in  [draft-mglt-lurk-lurk](https://datatracker.ietf.org/doc/draft-mglt-lurk-lurk/) as well as its TLS 1.3 extension specified in [draft-mglt-lurk-tls13](https://datatracker.ietf.org/doc/draft-mglt-lurk-tls13/).


The TLS 1.3 extension describes a TLS 1.3 Cryptographic Service (CS) that performs all TLS 1.3 related cryptographic operations. 
`pylurk` enables the CS to run in a TEE with a full EPID attestation using Gramine
 
Please check [`pytls13`]() for a more complete example on how to use it. 


