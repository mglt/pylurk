

# pyLURK : python implementation of LURK

The LURK Protocol as well as the LURK Extensions that
enables remote interaction with cryptographic material. 

pylurk implements the LURK Extension 'tls12' which enables
interactions between a LURK Client and a LURK Server in a TLS1.2 

The LURK specifications is available in
[draft-mglt-lurk-lurk](https://datatracker.ietf.org/doc/draft-mglt-lurk-lurk/)
and the TLS 1.2 extension is available in
[draft-mglt-lurk-tls12](https://datatracker.ietf.org/doc/draft-mglt-lurk-tls12/).


The current code is available on
[github](https://github.com/mglt/pylurk/).

# Installation

## Quick Install

pylurk can be installed using pip3

```shell
pip3 install pylurk
```

## Manual installation

### Prerequisites

pylurk has the following dependencies :

* [python3.6 or greater](https://www.python.org/downloads/)
* [construct2.8](https://pypi.python.org/pypi/construct)([doc](https://construct.readthedocs.io/en/latest/)) 
* [cryptodome](https://www.pycryptodome.org/en/latest/)([doc](https://pycryptodome.readthedocs.io/en/latest/src/installation.html)
* [tinyec](https://github.com/alexmgr/tinyec)
* [pyca/cryptography](https://cryptography.io/en/latest/) (optional)
 only used to create certificate

#### installing python3.6

check you Python version

```
python3 --version
```

If the version is lower than 3.6 install the latest Python version. On
Ubuntu this could be achieved as :

```
sudo apt-get install python3
```

#### installing construct

installing contruct 2.8. There is a version 2.9 that seems to have
significant changes from 2.8. Further testing is needed before moving to
the latest version. 
 
```
wget
https://files.pythonhosted.org/packages/e5/c6/3e3aeef38bb0c27364af3d21493d9690c7c3925f298559bca3c48b7c9419/construct-2.8.22.tar.gz
tar -xvzf construct-2.8.12.tar.gz
cd construct-2.8.22
sudo python3 setup.py install
```

or 

```
pip3 install construct==2.8.22 
```


#### installing cryptodrome

```
sudo apt-get install build-essential libgmp3-dev python3-dev
pip3 install pycryptodomex
python3 -m Cryptodome.SelfTest
```

#### installing tinyec

```
pip3 install tinyec
```

### installing pyca/cryptography 

```
pip3 install cryptography
```


### installing pylurk

Installing pylurk:

```
git clone ssh://gitolite@forge.ericsson.net/lurk/pylurk.git pylurk
cd pylurk
python3 test_lurk.py 
python3 test_tls12.py 
```


# Installation Testing  

The lurk and tls12 tests modules have been written to tests and
illustrate the usage of the LURK protocol as well as its TLS 1.2
extension. 

```
python3 -m pylurk.tests.lurk

python3 -m pylurk.tests.tls12
```

# Example 

## Demo scripts: LURK exchange for TLS 1.2 / RSA Master

Start the LURK Server by running the following command 
```shell
python3 -m pylurk.sample.tls12_rsa_master_server_demo
Server started with configuration below:
    - role: server
    - connectivity: {'type': 'udp', 'ip_address': '127.0.0.1', 'port': 6789}
    - extensions:
        - lurk, v1, ping
        - lurk, v1, capabilities
        - tls12, v1, ping
        - tls12, v1, capabilities
        - tls12, v1, rsa_master
             > designation: tls12
             > version: v1
             > type: rsa_master
             > key_id_type: ['sha256_32']
             > freshness_funct: ['null', 'sha256']
             > random_time_window: 5
             > check_server_random: False
             > check_client_random: False
             > cert: ['/home/emigdan/gitlab/pylurk.git/pylurk/core/../data/cert-rsa-enc.der']
             > key: ['/home/emigdan/gitlab/pylurk.git/pylurk/core/../data/key-rsa-enc-pkcs8.der']
        - tls12, v1, rsa_extended_master
        - tls12, v1, ecdhe


UDP Server listening...
```

Run the LURK Client detailing the operations on an TLS Edge Server 

```
python3 -m pylurk.sample.tls12_rsa_master_client_demo

    This demo exposes the interactions between a TLS Server terminating a TLS session and a Key Server. The demo illustrates the case of RSA authentication


== 1. Instantiating LurkUDPClient ==
------------------------------------


    LurkUDPClient started with capabilities:
        -ping
        -capabilities
        -rsa_master
        -rsa_extended_master
        -ecdhe



== 2. Listening for ClientHello from TLS Client... ==
-----------------------------------------------------


    ...ClientHello
    ...Container: 
    ...    client_version = Container: 
    ...        major = TLS12M (total 6)
    ...        minor = TLS12m (total 6)
    ...    random = Container: 
    ...        gmt_unix_time = [\x8e\xe9\x03 (total 4)
    ...        random = ;\xe7\xfb,\x07\xba\x86\x068\xb4\xfc3'\x1d\x
    ...            f7\xd2T\xfcB\x87\xf8\xc8\xbe\x8b\xddV\xec\xb8 (t
    ...            otal 28)
    ...    session_id = \x99B\x80\xe1\xeb\xbf\xed\x886lm\x8d\xe8\x8
    ...        2\xcd(B0\xe6\xd18\xc8c\x9f\x8a/\xbf\xc0\x1b\xd8t\x08
    ...         (total 32)
    ...    cipher_suites = ListContainer: 
    ...        TLS_RSA_WITH_AES_128_GCM_SHA256
    ...        TLS_RSA_WITH_AES_256_GCM_SHA384
    ...    compression_methods = ListContainer: 
    ...        null
    ...    extensions = ListContainer: 

    ...---------->




== 3. Responding with a ServerHello to the TLS Client ==
--------------------------------------------------------


    a) Selecting cipher suite:
        > TLS_RSA_WITH_AES_128_GCM_SHA256

    b) Extracting client_random:
        > Random
        > Container: 
        >     gmt_unix_time = [\x8e\xe9\x03 (total 4)
        >     random = ;\xe7\xfb,\x07\xba\x86\x068\xb4\xfc3'\x1d\xf7\x
        >         d2T\xfcB\x87\xf8\xc8\xbe\x8b\xddV\xec\xb8 (total 28)
        

    c) Generating a random (S):
        > Random
        > Container: 
        >     gmt_unix_time = [\x8e\xe9\x03 (total 4)
        >     random = 2\x0f^\xe3VFp\x80\n^\xcb\xa2\xc0\x8b\x8e,\x01\x
        >         13\xafB\x17\x8a\xb8\x8d\xa4\xe3\x82\xb8 (total 28)

    d) Obfuscating S (server_random):
        > Random
        > Container: 
        >     gmt_unix_time = [\x8e\xe9\x03 (total 4)
        >     random = \x1b\xa2\x193\xd8\xb6\x96{\xbd\x18V\xb2~l1#}\xa
        >         63C\x98\xb9b\x02\xf8o\xf9\x9b (total 28)


    e) Sending the ServerHello
    ...ServerHello
    ...Container: 
    ...    server_version = Container: 
    ...        major = TLS12M (total 6)
    ...        minor = TLS12m (total 6)
    ...    random = Container: 
    ...        gmt_unix_time = [\x8e\xe9\x03 (total 4)
    ...        random = \x1b\xa2\x193\xd8\xb6\x96{\xbd\x18V\xb2~l1#
    ...            }\xa63C\x98\xb9b\x02\xf8o\xf9\x9b (total 28)
    ...    session_id = +q\x91\xa0\xcc\xe3W\xf7Q)\xdd5\x94\xd6\xf0\
    ...        xd7D\xeb\x8aD\x91,?\xdaA\x05ej\x9e\xdd\xb6s (total 3
    ...        2)
    ...    cipher_suite = TLS_RSA_WITH_AES_128_GCM_SHA256 (total 31
    ...        )
    ...    compression_method = null (total 4)
    ...    extensions = ListContainer: 

    ...Certificate
    ...ListContainer: 
    ...    b'0\x82\x03f0\x82\x02N\xa0\x03\x02\x01\x02\x02\x14nU\xc1
    ...        o\xcb\x8d \x99\x14\xf2\x08\xcb\xb6\xc2y\xe4\x86_PH0\
    ...        r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x000\\1\x0b0
    ...        \t\x06\x03U\x04\x06\x13\x02CA1\x0b0\t\x06\x03U\x04\x
    ...        08\x0c\x02QC1\x110\x0f\x06\x03U\x04\x07\x0c\x08Montr
    ...        eal1\x130\x11\x06\x03U\x04\n\x0c\nMy Company1\x180\x
    ...        16\x06\x03U\x04\x03\x0c\x0fwww.example.com0 \x17\r18
    ...        0508223907Z\x18\x0f21180414223907Z0\\1\x0b0\t\x06\x0
    ...        3U\x04\x06\x13\x02CA1\x0b0\t\x06\x03U\x04\x08\x0c\x0
    ...        2QC1\x110\x0f\x06\x03U\x04\x07\x0c\x08Montreal1\x130
    ...        \x11\x06\x03U\x04\n\x0c\nMy Company1\x180\x16\x06\x0
    ...        3U\x04\x03\x0c\x0fwww.example.com0\x82\x01"0\r\x06\t
    ...        *\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f
    ...        \x000\x82\x01\n\x02\x82\x01\x01\x00\xc0\x02\xe0\xd5\
    ...        xe7\x17\xfe\xcf\x04>\xba\x16\xeb\xb289-\xef$\xbc\xf4
    ...        TL\xcdQ(\xc6\x07\x8cwU\xec\x82%\xae\x1d\x01Y\x86\xa7
    ...        \x9b\t\x18\x13\xb3\x15\xcaTw\n\x12\xc4\xb3L3\xbd\xc1
    ...        \xe2\xaa@\x197\xd6l\x07\x8f\xc4\x82\xa7\xb1\xa5\xc07
    ...        \xeb\x1b#\x8b4\x16]\xdf\x87\x94\xdd\xa8\xa7\xb9YO\xd
    ...        a\xc9\x02\x19\x06\x7f\xb4\x81\xce"+b\xec|\xa9\x95\xf
    ...        20#\x97A\x19R<\xfd>\xf3\xad\xd6\xe6\xa4C\x13\r\xb9\x
    ...        c8\x19\x17L\x94\xc7\xd8\xb8\xdd \xf6\xe6\xa3\xdfv\xd
    ...        f\x0bH\xf5XF\xa0\x83\xc7P\x00\xed\xd2L\x83\xc4c\x93\
    ...        x15\x83\x0c2\xec3,\x97U\x8c\x03\xef\xf1\xc0\xa8\xb7\
    ...        x94\xfeVg\\.\xd1X\xc6\xb4\xc1\x97\x94\n\xa8F\xcd\xeb
    ...        @.\xf3\x81\t\x8d\xb6@t\x9e,l\xbf\x01c\xd6\xcf\xef\x0
    ...        1\x91\x9e\xec\xca\xc7\x96\xde\x03\xb6\xe8\xe1Z816!$K
    ...        \x9f\xfa\xe2<\x964\xd3\xce\xf5\x0f*Z\x94\x01\xb39\xb
    ...        5ea\nA\xab>%\x93\xa2 \x17\x02\x03\x01\x00\x01\xa3\x1
    ...        e0\x1c0\x1a\x06\x03U\x1d\x11\x04\x130\x11\x82\x0fwww
    ...        .example.com0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x0
    ...        5\x00\x03\x82\x01\x01\x00AX\xda\x85\xfb\x06\xb0\x1a\
    ...        xf7\x17\x01\x0b\xe8k\xf1i8G\xfb\xea\xe8n}kc\x91\xb5W
    ...        -\xc9\xbc"\x06@gx\xd6\xbe@Gg>\x90+\x03\x83\x9es&q\x8
    ...        f\x98\xf0m`[\xb9\x1e\xe0\r\x8c9\x12\rB^\xe3\xf0\x08z
    ...        \x8a\xf3cl\x96v\x17\xb4\x1d\x98\xd12A7$|Y\x89\x96j?\
    ...        x16\x85\xf8\xfc\xbf\xf4B\x89\x81\x01\xdb\xa3S\xe4\xc
    ...        c7\xeb\x1b!\xdc`\x7f\x13U\x8e\xdeX\xec&\x1b\x00\xb7\
    ...        xad\xccK\x01\x131\xc8Y,\xde\xef\xe6G\x98)\x1c\xe8\x1
    ...        f\xf1\xfe\xc5\xf38tT#?\x9bl\x1bzwd\xdf\x87\x12\n=sBQ
    ...        \x1f]|\x94\x9c!\xb1\x8c\xbd#\x01\xe4\xda\xb9\x17\xe6
    ...        \xa8%\x8f9|\x07\xcb\xbc5\xc9KE\x8c\xf8\x1c\xc6VT\x90
    ...        0\xfdz\xaa\xef\xe8|\xd3z\xbd%-\xf7\xe8\xa3\xd3\xe6\x
    ...        90\xf0\xc1\xc2\xf6`\xaf\x8f\xbf\x93y}-\xc45B3\x0el\x
    ...        84 \x98S.\xf2xh\x1d\x8fU\x95y\xe9\xa4\xc8\xde\x82\xe
    ...        0B '

    ...ServerHelloDone
    ...b''

    ...<----------




== 4. Listening for Client Key Exchange from the TLS Client ==
--------------------------------------------------------------


    ...ClientKeyExchange
    ...b'W\xb3\x0b\xb7"\x8a\xb2\x13\xcc\x97&d*\xba3\x80K\x9f\xc0\x0
    ...    0<_\t\xf4O\xe9\x1ft\xb0\x95\x9f\xd3`\xe6\xa8\x8dY\x15\xe
    ...    7\x8b\x1e\x188\xffhO\x88\x82\x94w/g\x1d\x0c\x89\xb7\xc4g
    ...    \x87\xf9qv\xa9+u\x1c?\x15\xb1n\x1c\xba\x1f\xca\xe5:\xee\
    ...    xb2\x11S\x87\xf3\xa8;\xd3\x06\x08m\xd6\xa1\xd0\xba\xb2\x
    ...    d8\x13L\xb0\xa8\x9e4\xf9h}\x01\x10\xe7\x123%H\xa4\x11\xd
    ...    7\x92\xe2M\xb8\x84C\xcc`\xb9\x89\xb5\xbc\xff\xb0\xf9\x00
    ...    )\xca\xe2?-B*\xbf\xa9\xffh\xc1(G\x1d\xa6\x01\x83\x95\x9b
    ...    \xb5\xdd\x84\x7f\xd9\xc1-\xc9\xe0\xa8\x90p%\xe3\xba\xb5W
    ...    \xc7x\x10\xd2\'D\xdbY@F\x0e\x19*\xbb,ih\xe1\xe7\x84\xb2_
    ...    \x12\xe3".\xa7$\x0b\xd1p\xaa\x00[A\x12n>N\x19u\xdff3\x1c
    ...    ?O) z%\x8d\x8cf\xe9\xbb\xe3\x0b\x81F\xdf\x04U\x13\x87y\x
    ...    e1\xe6\xaci\xa7\xcb\xdf|\'=\x13\xe5\xec.\x7f9\xdf\x90\xb
    ...    e*6lW\xe1'



== 5. Generation of the master secret by the Key Server ==
----------------------------------------------------------


    The master secret is requested to the Key Server (LURK)

    The master secret is generated by the Key Server

          ...Lurk Header
          ...Container: 
          ...    designation = tls12 (total 5)
          ...    version = v1 (total 2)
          ...    type = rsa_master (total 10)
          ...    status = request (total 7)
          ...    id = a(\x89\xb0\x97\x05\x0c\xcd (total 8)
          ...    length = 342
          ...TLS12RSAMasterRequestPayload
          ...Container: 
          ...    key_id = Container: 
          ...        key_id_type = sha256_32 (total 9)
          ...        key_id = \xee\xee\x19\x0e (total 4)
          ...    freshness_funct = sha256 (total 6)
          ...    client_random = Container: 
          ...        gmt_unix_time = [\x8e\xe9\x03 (total 4)
          ...        random = ;\xe7\xfb,\x07\xba\x86\x068\xb4\xfc3'\x1d\x
          ...            f7\xd2T\xfcB\x87\xf8\xc8\xbe\x8b\xddV\xec\xb8 (t
          ...            otal 28)
          ...    server_random = Container: 
          ...        gmt_unix_time = [\x8e\xe9\x03 (total 4)
          ...        random = 2\x0f^\xe3VFp\x80\n^\xcb\xa2\xc0\x8b\x8e,\x
          ...            01\x13\xafB\x17\x8a\xb8\x8d\xa4\xe3\x82\xb8 (tot
          ...            al 28)
          ...    encrypted_premaster = W\xb3\x0b\xb7"\x8a\xb2\x13\xcc\x97
          ...        &d*\xba3\x80K\x9f\xc0\x00<_\t\xf4O\xe9\x1ft\xb0\x95\
          ...        x9f\xd3`\xe6\xa8\x8dY\x15\xe7\x8b\x1e\x188\xffhO\x88
          ...        \x82\x94w/g\x1d\x0c\x89\xb7\xc4g\x87\xf9qv\xa9+... (
          ...        truncated, total 256)

    ...<----------




          ...Lurk Header
          ...Container: 
          ...    designation = tls12 (total 5)
          ...    version = v1 (total 2)
          ...    type = rsa_master (total 10)
          ...    status = success (total 7)
          ...    id = a(\x89\xb0\x97\x05\x0c\xcd (total 8)
          ...    length = 64
          ...TLS12RSAMasterResponsePayload
          ...Container: 
          ...    master = \xbbRPz>\xf5$\xdf\x0e\xe6?\x8d\x8bYj\xf9\x13(\x
          ...        fe\xd4q\xd7\x04\x97\t6\xcd\xf1J\x93-\xf4\xde\xb7\x97
          ...        d\x9bX\xa7\xdb\xdb\xe2J\x1a\xfa\x93R\xcb (total 48)

    ...---------->



== 6. Terminating the TLS Key Exchange with the TLS Client ==
-------------------------------------------------------------


    With the master secret, the TLS Key Exchange can be
              completed
    ...[ChangeCipherSpec]
    ...Finished
    ...-------->
    ...                    [ChangeCipherSpec]
    ...                        Finished
    ...                    <--------
    ...Application Data      <------->     Application Data
```


## Manually generating the LURK exchange for TLS 1.2 RSA Master


Open a python3 shell and start the LURK server by typing
```

>>> from pylurk.core.lurk import LurkUDPServer
>>> LurkUDPServer()
```

Open a python3 shell and start sending LURK queries using a LURK
Client
```
lurk_client = LurkUDPClient( )
query, response = lurk_client.resolve( designation='tls12',\
    version='v1', type='rsa_master', payload={})
##
## query response are dictionaries
##

>>> print(query)
{'designation': 'tls12', 'version': 'v1', 'type': 'rsa_master', 'status': 'request', 'id': 147517109808405528, 'length': 342, 'payload': Container(key_id=Container(key_id_type='sha256_32')(key_id=b'\xee\xee\x19\x0e'))(freshness_funct='null')(client_random=Container(gmt_unix_time=b'[\x8e\xddz')(random=b'\xfd \xf7\x8e\xfc\xd0\x133vS\x81\x14\xe7]z\xbd\xb7\xe9a\xf2\xb4\xe4\x92\xb1,\xfb\x84B'))(server_random=Container(gmt_unix_time=b'[\x8e\xddz')(random=b'\xc3\xe3o\x03>\xcf\xb7\xaa\xdd\xb2\x82\xc9kbg\xf2\xecfsP\x81:\xb4\xda\xe3\xd8\xa0I'))(encrypted_premaster=b'%\xe7{\xf9\x9a\x1d?\x1b\xd7\xfb\xd2\x9e\xc4\'\x9b\xb2\xcd\xe7N^\xd9\xfca?\x0c\x9b\x96\x88\r\xcd\xfa\xe5\x01\xe5\xf5\xa09.\xf1"\x93\xd2\x92\x90"_?\xae\xaa_\\\xe5A\xfb\x97\x84\xc1\xfe\xa8\xda\xfe\xdcu\xec@\xe7\x85\xd0\'\x91\xfa\xa3\xf3jD\xba3\xcbf\x05\x94H_!\x7f\xad\xcd\xfbhG\xf3p\xd1\xa1\xb3\xfe<\xd6\x1e&&8\x98\x86\xbb\x84SB\x98\xa0\xaa\x85@\xb8w\x82\xbf\xfe\x11\x9c\xea\\\xa2[;\'\x998o\xe3}\xd21b\x92@\xbb1qz\xb0\xb5\xebt\x16\x95E\xb2\t\xff~\xd6R\x95\xc7\xeb\xad.\x80%36i\xe8hE\x11\xe4\xe6\xf8\xb4|D-\x06\xa2E\x19\x89>t\x07\xb0jz\xda\xcd\r_G\xe4\x14vJ0\xfb3\x90\xd6$;\x0e\x193\x1d\x13r\xae\xc8\xda\x00\xf8\x0e\x96\x8b&\xf1\xcf\xcf\'\xc6\xe0F\xd7)\x0b|\xf5\r\xd9\xe0\x04\xf5\x93#\xbb?k\xb8.\xdevk\\\xa7\xba\x15\xb4\xc1\xeaiBR~\x84\xc6')}
>>> print(response)
{'designation': 'tls12', 'version': 'v1', 'type': 'rsa_master', 'status': 'success', 'id': b'\x02\x0c\x16\x07\xa0l\x1c\x18', 'length': 64, 'payload': Container(master=b"\xe7\x7f\xaa\xcc\xec8\n\xb1\x9f\xf5@\x05 \xdey\x11\x1b\xd8\xd7\xd2\xcev\x96l\xc3kf\x0b\x17\x10S\xbd\x10\xb2w\xa4\x1f\x87\xa0@'\xc6\xe5u\x15N\x94\x10")}

##
## query, response can nicely be printed using LurkMessage
##

>>> from pylurk.core.lurk import LurkMessage
>>> msg = LurkMessage()
>>> msg.show(query)
Lurk Header
Container: 
    designation = tls12 (total 5)
    version = v1 (total 2)
    type = rsa_master (total 10)
    status = request (total 7)
    id = \x02\x0c\x16\x07\xa0l\x1c\x18 (total 8)
    length = 342
TLS12RSAMasterRequestPayload
Container: 
    key_id = Container: 
        key_id_type = sha256_32 (total 9)
        key_id = \xee\xee\x19\x0e (total 4)
    freshness_funct = null (total 4)
    client_random = Container: 
        gmt_unix_time = [\x8e\xddz (total 4)
        random = \xfd \xf7\x8e\xfc\xd0\x133vS\x81\x14\xe7]z\
            xbd\xb7\xe9a\xf2\xb4\xe4\x92\xb1,\xfb\x84B (tota
            l 28)
    server_random = Container: 
        gmt_unix_time = [\x8e\xddz (total 4)
        random = \xc3\xe3o\x03>\xcf\xb7\xaa\xdd\xb2\x82\xc9k
            bg\xf2\xecfsP\x81:\xb4\xda\xe3\xd8\xa0I (total 2
            8)
    encrypted_premaster = %\xe7{\xf9\x9a\x1d?\x1b\xd7\xfb\xd
        2\x9e\xc4\'\x9b\xb2\xcd\xe7N^\xd9\xfca?\x0c\x9b\x96\
        x88\r\xcd\xfa\xe5\x01\xe5\xf5\xa09.\xf1"\x93\xd2\x92
        \x90"_?\xae\xaa_\\\xe5A\xfb\x97\x84\xc1\xfe\xa8\xda\
        xfe\xdcu\xec... (truncated, total 256)

>>> msg.show(response)
Lurk Header
Container: 
    designation = tls12 (total 5)
    version = v1 (total 2)
    type = rsa_master (total 10)
    status = success (total 7)
    id = \x02\x0c\x16\x07\xa0l\x1c\x18 (total 8)
    length = 64
TLS12RSAMasterResponsePayload
Container: 
    master = \xe7\x7f\xaa\xcc\xec8\n\xb1\x9f\xf5@\x05 \xdey\
        x11\x1b\xd8\xd7\xd2\xcev\x96l\xc3kf\x0b\x17\x10S\xbd
        \x10\xb2w\xa4\x1f\x87\xa0@'\xc6\xe5u\x15N\x94\x10 (t
        otal 48)

```

