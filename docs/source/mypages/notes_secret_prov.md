# Testing RA TLS attestation with Gramine

This section detail show to test the programs within the Gramine project. 

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


# Testing RA-TLS Attestation with LURK

This section details how to use the secret provisionning service provided by pylurk. 
These are largely inspired by those provided by the Gramine project. 

It contains the following steps:
1. On first time make sure service proviosioning has been properly compiled to enable attestation. As the client part will be embeded into the cryptographic service, the client MUST be build before the CS enclave is built. As these are just executable software, there is not a need to build them unless you expect to execute `gramine-sgx client` in which case the templates needs to be built with attestation information. 
 
2. Building the enclave EINITTOKEN that is in in our case the `python.sig` file.

3. Starting the secret provisionning service
4. Starting the enclave 

## 1. Building/Compiling Provisioning Client / Server 

```
$ cd ~/gitlab/pylurk.git/example/cli
$ make -f Makefile_server_prov clean && make -f Makefile_server_prov app epid RA_TYPE=epid RA_CLIENT_SPID=3A2053D125F7AB3642C3FAC6A22BABFD RA_CLIENT_LINKABLE=0 GRAMINEDIR=/home/mglt/gramine
rm -f OUTPUT
cd secret_prov;         rm -f client server_* *.token *.sig *.manifest.sgx *.manifest
cd secret_prov && \
gramine-manifest \
        -Dlog_level=error \
        -Darch_libdir=/lib/x86_64-linux-gnu \
        -Dra_type=epid \
        -Dra_client_spid=3A2053D125F7AB3642C3FAC6A22BABFD \
        -Dra_client_linkable=0 \
        client.manifest.template > client.manifest
cc secret_prov/client.c -O2 -fPIE -Wall -std=c11 -I/home/mglt/gramine/tools/sgx/ra-tls -pie -Wl,--enable-new-dtags -lsgx_util -Wl,-rpath,/usr/lib/x86_64-linux-gnu -lsecret_prov_attest -o secret_prov/client
secret_prov/client.c: In function ‘main’:
secret_prov/client.c:42:13: warning: unused variable ‘c’ [-Wunused-variable]
   42 |     uint8_t c;
      |             ^
secret_prov/client.c:33:9: warning: variable ‘ret2’ set but not used [-Wunused-but-set-variable]
   33 |     int ret2;
      |         ^~~~
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
    59cf9766eecf45ffa8b12d85c1b9e872ce8df95ffc121a09f7828ae9438c5193
gramine-sgx-get-token --output secret_prov/client.token --sig secret_prov/client.sig
Attributes:
    mr_enclave:  59cf9766eecf45ffa8b12d85c1b9e872ce8df95ffc121a09f7828ae9438c5193
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
    signature:   1779c023d5f8ca3e1e777cf8d12ddf74...
    date:        2023-03-24
cc secret_prov/server.c -O2 -fPIE -Wall -std=c11 -I/home/mglt/gramine/tools/sgx/ra-tls -pie -Wl,--enable-new-dtags -lsgx_util -Wl,-rpath,/usr/lib/x86_64-linux-gnu -lsecret_prov_verify_epid -pthread -o secret_prov/server_epid
```

## 2. Building or initializing the Cryptographic Service

```
$ cd ~/gitlab/pylurk.git/example/cli
$ make clean && make all SGX=1 RA_TYPE=epid RA_CLIENT_SPID=3A2053D125F7AB3642C3FAC6A22BABFD RA_CLIENT_LINKABLE=0 GRAMINEDIR=/home/mglt/gramine
rm -f *.manifest *.manifest.sgx *.token *.sig OUTPUT* *.PID TEST_STDOUT TEST_STDERR
rm -f -r scripts/__pycache__
gramine-manifest \
        -Dlog_level=error \
        -Darch_libdir=/lib/x86_64-linux-gnu \
        -Dentrypoint=/usr/bin/python3.10 \
        -Dra_type=epid \
        -Dra_client_spid=3A2053D125F7AB3642C3FAC6A22BABFD \
        -Dra_client_linkable=0 \
        python.manifest.template >python.manifest
gramine-sgx-sign \
        --manifest python.manifest \
        --output python.manifest.sgx
Attributes:
    size:        0x20000000
    thread_num:  32
    isv_prod_id: 29539
    isv_svn:     0
    attr.flags:  0x4
    attr.xfrm:   0x3
    misc_select: 0x0
SGX remote attestation:
    EPID (spid = `3A2053D125F7AB3642C3FAC6A22BABFD`, linkable = False)
Memory:
    000000001f9b4000-0000000020000000 [REG:R--] (manifest) measured
    000000001f8b4000-000000001f9b4000 [REG:RW-] (ssa) measured
    000000001f894000-000000001f8b4000 [TCS:---] (tcs) measured
    000000001f874000-000000001f894000 [REG:RW-] (tls) measured
    000000001f834000-000000001f874000 [REG:RW-] (stack) measured
    000000001f7f4000-000000001f834000 [REG:RW-] (stack) measured
    000000001f7b4000-000000001f7f4000 [REG:RW-] (stack) measured
    000000001f774000-000000001f7b4000 [REG:RW-] (stack) measured
    000000001f734000-000000001f774000 [REG:RW-] (stack) measured
    000000001f6f4000-000000001f734000 [REG:RW-] (stack) measured
    000000001f6b4000-000000001f6f4000 [REG:RW-] (stack) measured
    000000001f674000-000000001f6b4000 [REG:RW-] (stack) measured
    000000001f634000-000000001f674000 [REG:RW-] (stack) measured
    000000001f5f4000-000000001f634000 [REG:RW-] (stack) measured
    000000001f5b4000-000000001f5f4000 [REG:RW-] (stack) measured
    000000001f574000-000000001f5b4000 [REG:RW-] (stack) measured
    000000001f534000-000000001f574000 [REG:RW-] (stack) measured
    000000001f4f4000-000000001f534000 [REG:RW-] (stack) measured
    000000001f4b4000-000000001f4f4000 [REG:RW-] (stack) measured
    000000001f474000-000000001f4b4000 [REG:RW-] (stack) measured
    000000001f434000-000000001f474000 [REG:RW-] (stack) measured
    000000001f3f4000-000000001f434000 [REG:RW-] (stack) measured
    000000001f3b4000-000000001f3f4000 [REG:RW-] (stack) measured
    000000001f374000-000000001f3b4000 [REG:RW-] (stack) measured
    000000001f334000-000000001f374000 [REG:RW-] (stack) measured
    000000001f2f4000-000000001f334000 [REG:RW-] (stack) measured
    000000001f2b4000-000000001f2f4000 [REG:RW-] (stack) measured
    000000001f274000-000000001f2b4000 [REG:RW-] (stack) measured
    000000001f234000-000000001f274000 [REG:RW-] (stack) measured
    000000001f1f4000-000000001f234000 [REG:RW-] (stack) measured
    000000001f1b4000-000000001f1f4000 [REG:RW-] (stack) measured
    000000001f174000-000000001f1b4000 [REG:RW-] (stack) measured
    000000001f134000-000000001f174000 [REG:RW-] (stack) measured
    000000001f0f4000-000000001f134000 [REG:RW-] (stack) measured
    000000001f0b4000-000000001f0f4000 [REG:RW-] (stack) measured
    000000001f074000-000000001f0b4000 [REG:RW-] (stack) measured
    000000001f064000-000000001f074000 [REG:RW-] (sig_stack) measured
    000000001f054000-000000001f064000 [REG:RW-] (sig_stack) measured
    000000001f044000-000000001f054000 [REG:RW-] (sig_stack) measured
    000000001f034000-000000001f044000 [REG:RW-] (sig_stack) measured
    000000001f024000-000000001f034000 [REG:RW-] (sig_stack) measured
    000000001f014000-000000001f024000 [REG:RW-] (sig_stack) measured
    000000001f004000-000000001f014000 [REG:RW-] (sig_stack) measured
    000000001eff4000-000000001f004000 [REG:RW-] (sig_stack) measured
    000000001efe4000-000000001eff4000 [REG:RW-] (sig_stack) measured
    000000001efd4000-000000001efe4000 [REG:RW-] (sig_stack) measured
    000000001efc4000-000000001efd4000 [REG:RW-] (sig_stack) measured
    000000001efb4000-000000001efc4000 [REG:RW-] (sig_stack) measured
    000000001efa4000-000000001efb4000 [REG:RW-] (sig_stack) measured
    000000001ef94000-000000001efa4000 [REG:RW-] (sig_stack) measured
    000000001ef84000-000000001ef94000 [REG:RW-] (sig_stack) measured
    000000001ef74000-000000001ef84000 [REG:RW-] (sig_stack) measured
    000000001ef64000-000000001ef74000 [REG:RW-] (sig_stack) measured
    000000001ef54000-000000001ef64000 [REG:RW-] (sig_stack) measured
    000000001ef44000-000000001ef54000 [REG:RW-] (sig_stack) measured
    000000001ef34000-000000001ef44000 [REG:RW-] (sig_stack) measured
    000000001ef24000-000000001ef34000 [REG:RW-] (sig_stack) measured
    000000001ef14000-000000001ef24000 [REG:RW-] (sig_stack) measured
    000000001ef04000-000000001ef14000 [REG:RW-] (sig_stack) measured
    000000001eef4000-000000001ef04000 [REG:RW-] (sig_stack) measured
    000000001eee4000-000000001eef4000 [REG:RW-] (sig_stack) measured
    000000001eed4000-000000001eee4000 [REG:RW-] (sig_stack) measured
    000000001eec4000-000000001eed4000 [REG:RW-] (sig_stack) measured
    000000001eeb4000-000000001eec4000 [REG:RW-] (sig_stack) measured
    000000001eea4000-000000001eeb4000 [REG:RW-] (sig_stack) measured
    000000001ee94000-000000001eea4000 [REG:RW-] (sig_stack) measured
    000000001ee84000-000000001ee94000 [REG:RW-] (sig_stack) measured
    000000001ee74000-000000001ee84000 [REG:RW-] (sig_stack) measured
    000000001ea57000-000000001ea9b000 [REG:R-X] (code) measured
    000000001ea9c000-000000001ee74000 [REG:RW-] (data) measured
    0000000000010000-000000001ea57000 [REG:RWX] (free)
Measurement:
    c5a30148a517716df3cad124f9fe895e8f50d82dfa8dce76779a8d0cb9598ef8
gramine-sgx-get-token --output python.token --sig python.sig
Attributes:
    mr_enclave:  c5a30148a517716df3cad124f9fe895e8f50d82dfa8dce76779a8d0cb9598ef8
    mr_signer:   e725999b742f47419e5a074b32d8c869711d68d20d059dc987e5c87424cb37a9
    isv_prod_id: 29539
    isv_svn:     0
    attr.flags:  0000000000000004
    attr.xfrm:   0000000000000003
    mask.flags:  ffffffffffffffff
    mask.xfrm:   fffffffffff9ff1b
    misc_select: 00000000
    misc_mask:   ffffffff
    modulus:     f19f15a643fbadc6714cbe9e8d670a8a...
    exponent:    3
    signature:   04ed09f1e7be72fc229f5a6b5aee01b3...
    date:        2023-03-24
```

## 3. Starting the secret provisionning service


By default, the parameters are read from the python.sig file

```
$ cd ~/gitlab/pylurk.git/example/cli/secret_prov
$ ./secret_prov_service 
Starting Secret Provision Service:
(Reading attributes from /home/mglt/gitlab/pylurk.git/example/cli/python.sig)
    - mrenclave: c5a30148a517716df3cad124f9fe895e8f50d82dfa8dce76779a8d0cb9598ef8
    - mrsigner: e725999b742f47419e5a074b32d8c869711d68d20d059dc987e5c87424cb37a9
    - isv_prod_id: 29539
    - isv_svn: 0 
    - secret: ../sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der

secret_key [48 bytes]:
30 2E 2 1 0 30 5 6 3 2B 65 70 4 22 4 20 12 F 12 D8 DB 8F ED B0 15 49 EC 5C 63 6D DB 55 D9 7A 66 BE A7 17 6A 2C 96 47 BD A5 12 82 23 9A 
--- Starting the Secret Provisioning server on port 4433 ---

```

## 4. Initializing the Crypto Service with attestation

```
$ cd ~/gitlab/pylurk.git/example/cli
$ $ ./crypto_service --connectivity tcp --port 9401 --cert sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --gramine_sgx --secret_provisioning 
 --- Executing: /home/mglt/gitlab/pylurk.git/example/cli/./crypto_service with Namespace(connectivity="'tcp'", host="'127.0.0.1'", port=9401, sig_scheme="'ed25519'", key=None, cert=PosixPath('sig_key_dir/_Ed25519PublicKey-ed25519-X509.der'), debug=False, test_vector_mode=None, test_vector_file=None, gramine_sgx=True, gramine_direct=False, gramine_build=False, secret_provisioning=True)
key file not provided. New key will be generated in /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir
cmd: ./start_cs.py --connectivity tcp --host 127.0.0.1 --port 9401 --sig_scheme ed25519 --key sig_key_dir --cert ./sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --secret_provisioning
mglt@nuc:~/gitlab/pylurk.git/example/cli$ Gramine is starting. Parsing TOML manifest file, this may take some time...
Detected a huge manifest, preallocating 64MB of internal memory.
-----------------------------------------------------------------------------------------------------------------------
Gramine detected the following insecure configurations:

  - loader.insecure__use_cmdline_argv = true   (forwarding command-line args from untrusted host to the app)
  - sgx.allowed_files = [ ... ]                (some files are passed through from untrusted host without verification)

Gramine will continue application execution, but this configuration must not be used in production!
-----------------------------------------------------------------------------------------------------------------------

Detected a huge manifest, preallocating 64MB of internal memory.
secret_received [48]:
30 2E 2 1 0 30 5 6 3 2B 65 70 4 22 4 20 12 F 12 D8 DB 8F ED B0 15 49 EC 5C 63 6D DB 55 D9 7A 66 BE A7 17 6A 2C 96 47 BD A5 12 82 23 9A 0 
--- secret1 successfully stored
--- Received secret1 = '0.', secret2 = '42' ---
 --- Executing: //./start_cs.py with Namespace(connectivity="'tcp'", host="'127.0.0.1'", port=9401, sig_scheme="'ed25519'", key=PosixPath('sig_key_dir'), cert=PosixPath('sig_key_dir/_Ed25519PublicKey-ed25519-X509.der'), debug=False, test_vector_mode=None, test_vector_file=None, gramine_sgx=False, gramine_direct=False, gramine_build=False, secret_provisioning=True)
Provisionning the secret key (and overwritting existing value if present)
cs_template_conf: {'log': None, 'connectivity': {'type': 'tcp', 'ip': '127.0.0.1', 'port': 9401}, ('tls13', 'v1'): {'sig_scheme': ['ed25519'], 'public_key': [PosixPath('sig_key_dir/_Ed25519PublicKey-ed25519-X509.der')], 'private_key': 'secret_prov/secret.bin', 'debug': {'trace': False}}}
Configuration Template (from end user arguments ):

{'log': None,
 'connectivity': {'type': 'tcp',
                  'ip': '127.0.0.1',
                  'port': 9401},
 ('tls13', 'v1'): {'sig_scheme': ['ed25519'],
                   'public_key': [PosixPath('sig_key_dir/_Ed25519PublicKey-ed25519-X509.der')],
                   'private_key': 'secret_prov/secret.bin',
                   'debug': {'trace': False}}}
Full configuration:

{'profile': 'explicit configuration',
 'description': 'LURK Cryptographic Service configuration '
                'template',
 'connectivity': {'type': 'tcp',
                  'ip': '127.0.0.1',
                  'port': 9401},
 'enabled_extensions': [('lurk', 'v1'), ('tls13', 'v1')],
 ('lurk', 'v1'): {'type_authorized': ['ping', 'capabilities']},
 ('tls13', 'v1'): {'debug': {'trace': False},
                   'role': 'client',
                   'type_authorized': ['c_init_client_finished',
                                       'c_post_hand_auth',
                                       'c_init_client_hello',
                                       'c_server_hello',
                                       'c_client_finished',
                                       'c_register_tickets'],
                   'ephemeral_method_list': ['no_secret',
                                             'cs_generated',
                                             'e_generated'],
                   'authorized_ecdhe_group': ['secp256r1',
                                              'secp384r1',
                                              'secp521r1',
                                              'x25519',
                                              'x448'],
                   'sig_scheme': ['ed25519'],
                   'client_early_secret_authorized': True,
                   'early_exporter_secret_authorized': True,
                   'exporter_secret_authorized': True,
                   'app_secret_authorized': True,
                   'resumption_secret_authorized': True,
                   's_init_early_secret_session_id': True,
                   'last_exchange': {'s_init_cert_verify': False,
                                     's_hand_and_app_secret': False,
                                     'c_init_client_finished': False,
                                     'c_init_post_auth': False,
                                     'c_client_finished': False},
                   'max_tickets': 6,
                   'ticket_life_time': 172800,
                   'ticket_nonce_len': 20,
                   'ticket_generation_method': 'ticket',
                   'ticket_len': 4,
                   'post_handshake_authentication': True,
                   'max_post_handshake_authentication': 1,
                   'public_key': [PosixPath('sig_key_dir/_Ed25519PublicKey-ed25519-X509.der')],
                   'private_key': 'secret_prov/secret.bin',
                   '_private_key': <cryptography.hazmat.backends.openssl.ed25519._Ed25519PrivateKey object at 0x1337f160>,
                   '_public_key': <cryptography.hazmat.backends.openssl.ed25519._Ed25519PublicKey object at 0x1337e5c0>,
                   '_cert_type': 'X509',
                   '_cert_entry_list': [{'cert': b'0\x82\x01.'
                                                 b'0\x81\xe1\xa0'
                                                 b'\x03\x02\x01\x02'
                                                 b'\x02\x14&?'
                                                 b'V\xc5s\xf6'
                                                 b'k6\xd8\x9a'
                                                 b'\x0f\xc7\xdb\xaf'
                                                 b'J\xcf\xf7\xa3'
                                                 b'r\x0f0\x05'
                                                 b'\x06\x03+e'
                                                 b'p0\x1a1'
                                                 b'\x180\x16\x06'
                                                 b'\x03U\x04\x03'
                                                 b'\x0c\x0fcr'
                                                 b'yptography.i'
                                                 b'o0\x1e\x17'
                                                 b'\r23032320151'
                                                 b'4Z\x17\r2304'
                                                 b'23201514'
                                                 b'Z0\x1a1'
                                                 b'\x180\x16\x06'
                                                 b'\x03U\x04\x03'
                                                 b'\x0c\x0fcr'
                                                 b'yptography.i'
                                                 b'o0*0'
                                                 b'\x05\x06\x03+'
                                                 b'ep\x03!'
                                                 b'\x00o~\xb8'
                                                 b'\xf5\xa3(\xa4'
                                                 b'\xb9\xc5V\xfc'
                                                 b'3\x88\x94\x96'
                                                 b'QK\xa3\x14'
                                                 b'\xa6\xcc\xaf\x86'
                                                 b'tX|$'
                                                 b'\x93\xad\\\xa6'
                                                 b'\xd8\xa390'
                                                 b'70\x1a\x06'
                                                 b'\x03U\x1d\x11'
                                                 b'\x04\x130\x11'
                                                 b'\x82\x0fcr'
                                                 b'yptography.i'
                                                 b'o0\x0b\x06'
                                                 b'\x03U\x1d\x0f'
                                                 b'\x04\x04\x03\x02'
                                                 b'\x02\xd40\x0c'
                                                 b'\x06\x03U\x1d'
                                                 b'\x13\x01\x01\xff'
                                                 b'\x04\x020\x00'
                                                 b'0\x05\x06\x03'
                                                 b'+ep\x03'
                                                 b'A\x00I\xd2'
                                                 b'L\x07\\\x93'
                                                 b'\xae\xaa\x98\x03'
                                                 b'j\xd6\xe4%'
                                                 b'etE\xbd'
                                                 b'N\x15\xfb\x14'
                                                 b'\xfd\x8dW\x9b'
                                                 b'\x80\xc5\xf5\x81'
                                                 b'\x95\x9f\xa0\xaa'
                                                 b'u\x04\xf1\xf8'
                                                 b'l\xfa\xfc\x0e'
                                                 b'\xbd\xee:\xf7'
                                                 b'\xfa\xec\xd3d'
                                                 b"\xff\x86'\xa6"
                                                 b'\rH\xdd|'
```

While having a look at the secret provisioning server we can see:

```
IAS report: signature verified correctly
IAS report: allowing quote status GROUP_OUT_OF_DATE
            [ advisory URL: https://security-center.intel.com ]
            [ advisory IDs: ["INTEL-SA-00381", "INTEL-SA-00389", "INTEL-SA-00465", "INTEL-SA-00477", "INTEL-SA-00528", "INTEL-SA-00617", "INTEL-SA-00657", "INTEL-SA-00767"] ]
Received the following measurements from the client:
  - MRENCLAVE:   c5a30148a517716df3cad124f9fe895e8f50d82dfa8dce76779a8d0cb9598ef8
  - MRSIGNER:    e725999b742f47419e5a074b32d8c869711d68d20d059dc987e5c87424cb37a9
  - ISV_PROD_ID: 29539
  - ISV_SVN:     0
Comparing with provided values:
--- Sent secret1 ---

```


