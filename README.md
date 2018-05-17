
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

## Quick Start

### Quick Install

pylurk can be installed using pip3

```
pip3 install pylurk
```

### Testing LURK and it TLS 1.2 extension 

The lurk and tls12 tests modules have been written to tests and
illustrate the usage of the LURK protocol as well as its TLS 1.2
extension. 

```
python3 -m pylurk.tests.lurk

python3 -m pylurk.tests.tls12
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
Ubuntu this coudl be achieved as :

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

#### installing pyca/cryptography 

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

## Example


