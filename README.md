`pylurk` implements the Limited Use of Remote Keys (LURK) framework as well as it extension for TLS 1.3.

LURK is a generic protocol whose purpose is to support specific interactions with a given cryptographic material, which is also known as Cryptographic Service (CS).
This module provides a framework for LURK as well as defines the CS for TLS 1.3 - including both a TLS client and a TLS server. 
The current module doesn't integrate the LURK extension that was defined for TLS 1.2 and while the two LURK framework do share a number of lines of codes, this version of LURK has undergone a major rewrite. 

This module implements the specifications detailed in  [draft-mglt-lurk-lurk](https://datatracker.ietf.org/doc/draft-mglt-lurk-lurk/) for LURK as well as in [draft-mglt-lurk-tls13](https://datatracker.ietf.org/doc/draft-mglt-lurk-tls13/) for its TLS 1.3 extension.

It has been proven that splitting the TLS 1.3 into to sub services namely a TLS Engine (E) and a CS interacting via LURK does not weaken the TLS 1.3 security.
As result, running the CS into a TEE environment provides hardware base protection to the authentication credentials and is perceived as a way to enforce additional trusted to TLS. In particular, it enables a service provider to run an infrastructure on a public cloud while keeping the authentication  credential private - that is not sharing them with the cloud provider. 


```
+----------------------------+
|       TLS Engine (E)       |
+------------^---------------+
             | (LURK/TLS 1.3)
+------------v---------------+
| Cryptographic Service (CS) |
| private_keys               |
+----------------------------+

TLS being split into a CS and an Engine 
```


`pylurk` implements the CS as a library, a TCP server or a persistent TCP server.
Both TCP servers are able to run into an SGX enclave using Gramine.    

`pylurk` provides in `examples/cli` the `crypto_service` to start the CS in various modes. 
The CS can be started with all default parameters by simply typing:

```
$ cd example/cli
$ ./crypto_service
 --- Executing: pylurk.git/example/cli/./crypto_service with Namespace(connectivity="'tcp'", host="'127.0.0.1'", port=9400, sig_scheme="'ed25519'", key=None, cert=None, debug=False, test_vector_mode=None, test_vector_file=None, gramine_sgx=False, gramine_direct=False, gramine_build=False)
cmd: ./start_cs.py --connectivity tcp --host 127.0.0.1 --port 9400 --sig_scheme ed25519 --key pylurk.git/example/cli/sig_key_dir --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir
mglt@nuc:pylurk.git/example/cli$  --- Executing: pylurk.git/example/cli/./start_cs.py with Namespace(connectivity="'tcp'", host="'127.0.0.1'", port=9400, sig_scheme="'ed25519'", key=PosixPath('pylurk.git/example/cli/sig_key_dir'), cert=PosixPath('pylurk.git/example/cli/sig_key_dir'), debug=False, test_vector_mode=None, test_vector_file=None, gramine_sgx=False, gramine_direct=False, gramine_build=False)
cs_template_conf: {'log': None, 'connectivity': {'type': 'tcp', 'ip': '127.0.0.1', 'port': 9400}, ('tls13', 'v1'): {'sig_scheme': ['ed25519'], 'public_key': [PosixPath('pylurk.git/example/cli/sig_key_dir')], 'private_key': PosixPath('pylurk.git/example/cli/sig_key_dir'), 'debug': {'trace': False}}}
pylurk.git/example/cli/sig_key_dir is not a file but a directory
WARNING: Generating new keys
  - private_file: pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der
  - public_file: pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der
Configuration Template (from end user arguments ):
```

By default, the CS is started as a TCP server on port 9400. 
Unless detected, the key is automatically generated, by default following the signature scheme ed25519. 

To start the CS in a SGX enclave, one need first to make sure Gramine is installed, then build the enclave (with `--gramine_build`) and then start the enclave (with `--gramine_direct`).

For a complete detail of the options type `./crypto_service --help`.    


`pylurk` depends on `pytls13` that defines all the necessary TLS 1.3 message structures and in return implements all TLS 1.3 cryptographic operations. 
As a result the usage of the CS is extensively described in the documentation of the `pytls13` module where the EPID attestation is described in a step-by-step approach.
   
## Installation

Currently there is no pip3 package, so one need to install it manually.

1. Install Gramine (if you want to use SGX)
2. Install `pytls13`. `pylurk` is highly depend on `pytls13` so `pytls13` needs to be installed. This is currently done by git clone the repository `git clone https://github.com/mglt/pytls13`
3. Git clone the repository `git clone https://github.com/mglt/pylurk tls13`
4. Update in `crypto_service`, `lurk_ping`, `start_cs.py`, `secret_prov_service` the following environment variables:
  * `CS_GRAMINE_DIR`: the location of the `pylurk.git/example/cli` directory
  * `GRAMINE_DIR` the directory of the Gramine directory
  * The path of the `pylurk` and `pytls13` modules indicated by the `sys.path.insert` directive.


## TODO:

* Build a proper packages that we can install using `pip3 install pylurk`. Thi s includes:
  * integrating the example/cli in the package and having the `crypto_service`, `lurk_ping`, `sercret_prov_service`  installed in a ./local/bin directory.
  * ensuring there is a directory that contains the keys - which can be read by gramine. 
  * REMOVE the source/pytls13 directory that contains a version of pytls13 - that version is only used to generate the documentation.  
* Include the `client` and `secret_prov_service` into a `pylurk.gramine` module. This consists in integrating a compile c code into a Python module as well as providing an python binding.
* Refine the `python.template`. Currently this file is designed to be unmodified. 
  * We should try first limiting the python packages to be embedded. Maybe these could be defined by the `pipreqs` package.
  * The key file is currently below the gramine directory, there is probably some means to make that directory more flexible and dynamically configure the template with it. 
  * Define  a class that generates the template 
* The public key is currently configured via a list of files. We may consider having a single file with all certificate chain.
* Logging may be configured via the CLI and we may introduce a log_level
* ECDHE keys have their own ECDHE class in the crypto_suite module while signature keys are handled in the conf module. We may consider harmonizing the API between ECDHE and SIG keys and have them in a single place. 
* lurk_tls13 is a bit too long, so we may consider splitting the TLS client and TLS server messages in distinct modules.  

