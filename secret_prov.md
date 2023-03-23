# Testing RA TLS attestation with Gramine
```
make app epid RA_TYPE=epid RA_CLIENT_SPID=3A2053D125F7AB3642C3FAC6A22BABFD RA_CLIENT_LINKABLE=0
cd secret_prov_minimal && \
gramine-manifest \
        -Dlog_level=error \
        -Darch_libdir=/lib/x86_64-linux-gnu \
        -Dra_type=epid \
        -Dra_client_spid=3A2053D125F7AB3642C3FAC6A22BABFD \
        -Dra_client_linkable=0 \
        client.manifest.template > client.manifest
cc secret_prov_minimal/client.c -O2 -fPIE -Wall -std=c11 -I../../tools/sgx/ra-tls -pie -Wl,--enable-new-dtags -lsgx_util -Wl,-rpath,/usr/lib/x86_64-linux-gnu -o secret_prov_minimal/client
cd secret_prov_minimal && \
gramine-sgx-sign \
        --manifest client.manifest \
        --output client.manifest.sgx
Attributes:
    size:        0x20000000
    thread_num:  4
    isv_prod_id: 0
    isv_svn:     0
    attr.flags:  0x6
    attr.xfrm:   0x3
    misc_select: 0x0
SGX remote attestation:
    EPID (spid = `3A2053D125F7AB3642C3FAC6A22BABFD`, linkable = False)
Memory:
    000000003fd19000-0000000040000000 [REG:R--] (manifest) measured
    000000003fcf9000-000000003fd19000 [REG:RW-] (ssa) measured
    000000003fcf5000-000000003fcf9000 [TCS:---] (tcs) measured
    000000003fcf1000-000000003fcf5000 [REG:RW-] (tls) measured
    000000003fcb1000-000000003fcf1000 [REG:RW-] (stack) measured
    000000003fc71000-000000003fcb1000 [REG:RW-] (stack) measured
    000000003fc31000-000000003fc71000 [REG:RW-] (stack) measured
    000000003fbf1000-000000003fc31000 [REG:RW-] (stack) measured
    000000003fbe1000-000000003fbf1000 [REG:RW-] (sig_stack) measured
    000000003fbd1000-000000003fbe1000 [REG:RW-] (sig_stack) measured
    000000003fbc1000-000000003fbd1000 [REG:RW-] (sig_stack) measured
    000000003fbb1000-000000003fbc1000 [REG:RW-] (sig_stack) measured
    000000003f794000-000000003f7d8000 [REG:R-X] (code) measured
    000000003f7d9000-000000003fbb1000 [REG:RW-] (data) measured
    0000000020000000-000000003f794000 [REG:RWX] (free)
Measurement:
    1396a7770b81663438d7302a951a92272fc80da5939372f52c47ae5a51789dea
gramine-sgx-get-token --output secret_prov_minimal/client.token --sig secret_prov_minimal/client.sig
Attributes:
    mr_enclave:  1396a7770b81663438d7302a951a92272fc80da5939372f52c47ae5a51789dea
    mr_signer:   e725999b742f47419e5a074b32d8c869711d68d20d059dc987e5c87424cb37a9
    isv_prod_id: 0
    isv_svn:     0
    attr.flags:  0000000000000006
    attr.xfrm:   0000000000000003
    mask.flags:  ffffffffffffffff
    mask.xfrm:   fffffffffff9ff1b
    misc_select: 00000000
    misc_mask:   ffffffff
    modulus:     f19f15a643fbadc6714cbe9e8d670a8a...
    exponent:    3
    signature:   cda39419b277164d002bb565f9c4dcb1...
    date:        2023-03-17
cd secret_prov && \
gramine-manifest \
        -Dlog_level=error \
        -Darch_libdir=/lib/x86_64-linux-gnu \
        -Dra_type=epid \
        -Dra_client_spid=3A2053D125F7AB3642C3FAC6A22BABFD \
        -Dra_client_linkable=0 \
        client.manifest.template > client.manifest
cc secret_prov/client.c -O2 -fPIE -Wall -std=c11 -I../../tools/sgx/ra-tls -pie -Wl,--enable-new-dtags -lsgx_util -Wl,-rpath,/usr/lib/x86_64-linux-gnu -lsecret_prov_attest -o secret_prov/client
cd secret_prov && \
gramine-sgx-sign \
        --manifest client.manifest \
        --output client.manifest.sgx
Attributes:
    size:        0x20000000
    thread_num:  4
    isv_prod_id: 0
    isv_svn:     0
    attr.flags:  0x6
    attr.xfrm:   0x3
    misc_select: 0x0
SGX remote attestation:
    EPID (spid = `3A2053D125F7AB3642C3FAC6A22BABFD`, linkable = False)
Memory:
    000000003fd19000-0000000040000000 [REG:R--] (manifest) measured
    000000003fcf9000-000000003fd19000 [REG:RW-] (ssa) measured
    000000003fcf5000-000000003fcf9000 [TCS:---] (tcs) measured
    000000003fcf1000-000000003fcf5000 [REG:RW-] (tls) measured
    000000003fcb1000-000000003fcf1000 [REG:RW-] (stack) measured
    000000003fc71000-000000003fcb1000 [REG:RW-] (stack) measured
    000000003fc31000-000000003fc71000 [REG:RW-] (stack) measured
    000000003fbf1000-000000003fc31000 [REG:RW-] (stack) measured
    000000003fbe1000-000000003fbf1000 [REG:RW-] (sig_stack) measured
    000000003fbd1000-000000003fbe1000 [REG:RW-] (sig_stack) measured
    000000003fbc1000-000000003fbd1000 [REG:RW-] (sig_stack) measured
    000000003fbb1000-000000003fbc1000 [REG:RW-] (sig_stack) measured
    000000003f794000-000000003f7d8000 [REG:R-X] (code) measured
    000000003f7d9000-000000003fbb1000 [REG:RW-] (data) measured
    0000000020000000-000000003f794000 [REG:RWX] (free)
Measurement:
    5443de7f9a589d71e74b591a81400e539245ecfbff51300b26a6ef257b4c516f
gramine-sgx-get-token --output secret_prov/client.token --sig secret_prov/client.sig
Attributes:
    mr_enclave:  5443de7f9a589d71e74b591a81400e539245ecfbff51300b26a6ef257b4c516f
    mr_signer:   e725999b742f47419e5a074b32d8c869711d68d20d059dc987e5c87424cb37a9
    isv_prod_id: 0
    isv_svn:     0
    attr.flags:  0000000000000006
    attr.xfrm:   0000000000000003
    mask.flags:  ffffffffffffffff
    mask.xfrm:   fffffffffff9ff1b
    misc_select: 00000000
    misc_mask:   ffffffff
    modulus:     f19f15a643fbadc6714cbe9e8d670a8a...
    exponent:    3
    signature:   4013b71d88020198e001b520c830917d...
    date:        2023-03-17
cd secret_prov_pf && \
gramine-manifest \
        -Dlog_level=error \
        -Darch_libdir=/lib/x86_64-linux-gnu \
        -Dra_type=epid \
        -Dra_client_spid=3A2053D125F7AB3642C3FAC6A22BABFD \
        -Dra_client_linkable=0 \
        client.manifest.template > client.manifest
cc secret_prov_pf/client.c -O2 -fPIE -Wall -std=c11 -I../../tools/sgx/ra-tls -pie -Wl,--enable-new-dtags -lsgx_util -Wl,-rpath,/usr/lib/x86_64-linux-gnu -o secret_prov_pf/client
cd secret_prov_pf && \
gramine-sgx-sign \
        --manifest client.manifest \
        --output client.manifest.sgx
Attributes:
    size:        0x20000000
    thread_num:  4
    isv_prod_id: 0
    isv_svn:     0
    attr.flags:  0x6
    attr.xfrm:   0x3
    misc_select: 0x0
SGX remote attestation:
    EPID (spid = `3A2053D125F7AB3642C3FAC6A22BABFD`, linkable = False)
Memory:
    000000003fd19000-0000000040000000 [REG:R--] (manifest) measured
    000000003fcf9000-000000003fd19000 [REG:RW-] (ssa) measured
    000000003fcf5000-000000003fcf9000 [TCS:---] (tcs) measured
    000000003fcf1000-000000003fcf5000 [REG:RW-] (tls) measured
    000000003fcb1000-000000003fcf1000 [REG:RW-] (stack) measured
    000000003fc71000-000000003fcb1000 [REG:RW-] (stack) measured
    000000003fc31000-000000003fc71000 [REG:RW-] (stack) measured
    000000003fbf1000-000000003fc31000 [REG:RW-] (stack) measured
    000000003fbe1000-000000003fbf1000 [REG:RW-] (sig_stack) measured
    000000003fbd1000-000000003fbe1000 [REG:RW-] (sig_stack) measured
    000000003fbc1000-000000003fbd1000 [REG:RW-] (sig_stack) measured
    000000003fbb1000-000000003fbc1000 [REG:RW-] (sig_stack) measured
    000000003f794000-000000003f7d8000 [REG:R-X] (code) measured
    000000003f7d9000-000000003fbb1000 [REG:RW-] (data) measured
    0000000020000000-000000003f794000 [REG:RWX] (free)
Measurement:
    c45a925ef76ee01cbc2c3d2f74819978821fb39853101c699b55b567641c6672
gramine-sgx-get-token --output secret_prov_pf/client.token --sig secret_prov_pf/client.sig
Attributes:
    mr_enclave:  c45a925ef76ee01cbc2c3d2f74819978821fb39853101c699b55b567641c6672
    mr_signer:   e725999b742f47419e5a074b32d8c869711d68d20d059dc987e5c87424cb37a9
    isv_prod_id: 0
    isv_svn:     0
    attr.flags:  0000000000000006
    attr.xfrm:   0000000000000003
    mask.flags:  ffffffffffffffff
    mask.xfrm:   fffffffffff9ff1b
    misc_select: 00000000
    misc_mask:   ffffffff
    modulus:     f19f15a643fbadc6714cbe9e8d670a8a...
    exponent:    3
    signature:   ab96a5e9207aeed11d2db01a5acc2ff6...
    date:        2023-03-17
cc secret_prov_minimal/server.c -O2 -fPIE -Wall -std=c11 -I../../tools/sgx/ra-tls -pie -Wl,--enable-new-dtags -lsgx_util -Wl,-rpath,/usr/lib/x86_64-linux-gnu -lsecret_prov_verify_epid -pthread -o secret_prov_minimal/server_epid
cc secret_prov/server.c -O2 -fPIE -Wall -std=c11 -I../../tools/sgx/ra-tls -pie -Wl,--enable-new-dtags -lsgx_util -Wl,-rpath,/usr/lib/x86_64-linux-gnu -lsecret_prov_verify_epid -pthread -o secret_prov/server_epid
cc secret_prov_pf/server.c -O2 -fPIE -Wall -std=c11 -I../../tools/sgx/ra-tls -pie -Wl,--enable-new-dtags -lsgx_util -Wl,-rpath,/usr/lib/x86_64-linux-gnu -lsecret_prov_verify_epid -pthread -o secret_prov_pf/server_epid
```

```
gramine-sgx ./client
Gramine is starting. Parsing TOML manifest file, this may take some time...
-----------------------------------------------------------------------------------------------------------------------
Gramine detected the following insecure configurations:

  - sgx.debug = true                           (this is a debug enclave)
  - loader.insecure__use_cmdline_argv = true   (forwarding command-line args from untrusted host to the app)
  - sgx.allowed_files = [ ... ]                (some files are passed through from untrusted host without verification)

Gramine will continue application execution, but this configuration must not be used in production!
-----------------------------------------------------------------------------------------------------------------------

--- Received secret1 = 'FIRST_SECRET', secret2 = '42' ---
```

```
 RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1 RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 RA_TLS_EPID_API_KEY=646457af6dea4427a2aae2e78a7b6ecf ./server_epid--- Starting the Secret Provisioning server on port 4433 ---
IAS report: signature verified correctly
IAS report: allowing quote status GROUP_OUT_OF_DATE
            [ advisory URL: https://security-center.intel.com ]
            [ advisory IDs: ["INTEL-SA-00381", "INTEL-SA-00389", "INTEL-SA-00465", "INTEL-SA-00477", "INTEL-SA-00528", "INTEL-SA-00617", "INTEL-SA-00657", "INTEL-SA-00767"] ]
Received the following measurements from the client:
  - MRENCLAVE:   5443de7f9a589d71e74b591a81400e539245ecfbff51300b26a6ef257b4c516f
  - MRSIGNER:    e725999b742f47419e5a074b32d8c869711d68d20d059dc987e5c87424cb37a9
  - ISV_PROD_ID: 0
  - ISV_SVN:     0
[ WARNING: In reality, you would want to compare against expected values! ]
--- Sent secret1 ---
--- Sent secret2 = '42' ---
```

## current commands

```
$ make clean && make app epid RA_TYPE=epid RA_CLIENT_SPID=3A2053D125F7AB3642C3FAC6A22BABFD RA_CLIENT_LINKABLE=0 GRAMINEDIR=/home/mglt/gramine
$ RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1 RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 RA_TLS_EPID_API_KEY=646457af6dea4427a2aae2e78a7b6ecf ./server_epid "dac61ce6d1763f1875e5b486126ebe42ed7003f1c8e52938f18af508ee1b430a" "e725999b742f47419e5a074b32d8c869711d68d20d059dc987e5c87424cb37a9" 0 0 "4433" "../ssl/server.crt" "../ssl/server.key" "../ssl/_Ed25519PrivateKey-ed25519-pkcs8.der" 

$ gramine-sgx ./client

```
# Testing RA-TLS Attestation with LURK


```
## Building the server and the client
$ cd pylurk.git/example/cli
$ make -f Makefile_server_prov clean && make -f Makefile_server_prov app epid RA_TYPE=epid RA_CLIENT_SPID=3A2053D125F7AB3642C3FAC6A22BABFD RA_CLIENT_LINKABLE=0 GRAMINEDIR=/home/mglt/gramine

$ cd secret_prov/
$$ ./secret_prov_service -sig_file client.sig 
Starting Secret Provision Service:

(Reading attributes from client.sig)

    - mrenclave: 7c9bdcdc7667ffa25d10476dffdb47187357a0909e60f583e7e647eb3a87e290
    - mrsigner: e725999b742f47419e5a074b32d8c869711d68d20d059dc987e5c87424cb37a9
    - isv_prod_id: 0
    - isv_svn: 0 
    - secret: ../sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der

secret_key [49 bytes]:
30 2E 2 1 0 30 5 6 3 2B 65 70 4 22 4 20 12 F 12 D8 DB 8F ED B0 15 49 EC 5C 63 6D DB 55 D9 7A 66 BE A7 17 6A 2C 96 47 BD A5 12 82 23 9A 0 0 
--- Starting the Secret Provisioning server on port 4433 ---
mglt@nuc:~/gitlab/pylurk.git/example/cli/secret_prov$ 

$ gramine-sgx client
Gramine is starting. Parsing TOML manifest file, this may take some time...
-----------------------------------------------------------------------------------------------------------------------
Gramine detected the following insecure configurations:

  - sgx.debug = true                           (this is a debug enclave)
  - loader.insecure__use_cmdline_argv = true   (forwarding command-line args from untrusted host to the app)
  - sgx.allowed_files = [ ... ]                (some files are passed through from untrusted host without verification)

Gramine will continue application execution, but this configuration must not be used in production!
-----------------------------------------------------------------------------------------------------------------------

IAS report: signature verified correctly
IAS report: allowing quote status GROUP_OUT_OF_DATE
            [ advisory URL: https://security-center.intel.com ]
            [ advisory IDs: ["INTEL-SA-00381", "INTEL-SA-00389", "INTEL-SA-00465", "INTEL-SA-00477", "INTEL-SA-00528", "INTEL-SA-00617", "INTEL-SA-00657", "INTEL-SA-00767"] ]
Received the following measurements from the client:
  - MRENCLAVE:   7c9bdcdc7667ffa25d10476dffdb47187357a0909e60f583e7e647eb3a87e290
  - MRSIGNER:    e725999b742f47419e5a074b32d8c869711d68d20d059dc987e5c87424cb37a9
  - ISV_PROD_ID: 0
  - ISV_SVN:     0
Comparing with provided values:
--- Sent secret1 ---
--- Sent secret2 = '42' ---
secret_received [49]:
30 2E 2 1 0 30 5 6 3 2B 65 70 4 22 4 20 12 F 12 D8 DB 8F ED B0 15 49 EC 5C 63 6D DB 55 D9 7A 66 BE A7 17 6A 2C 96 47 BD A5 12 82 23 9A 0 0 
--- secret1 successfully stored
--- Received secret1 = '0.', secret2 = '42' ---


```

