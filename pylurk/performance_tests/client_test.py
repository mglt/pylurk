from  os.path import join
import threading
import pkg_resources
data_dir = pkg_resources.resource_filename( __name__, '../data/')

from pylurk.core.lurk import LurkServer, ImplementationError, LurkMessage, \
                 HEADER_LEN, LurkClient, LurkServer, LurkUDPClient, ThreadedLurkUDPServer, \
                 LurkUDPServer, LurkTCPClient, LurkTCPServer, ThreadedLurkTCPServer, LurkConf, UDPServerConf, PoolMixIn, LurkHTTPserver, LurkHTTPClient,HTTPRequestHandler,ThreadedLurkHTTPserver
from pylurk.extensions.tls12 import Tls12RsaMasterConf,  Tls12EcdheConf, \
                       Tls12RsaMasterRequestPayload,\
                       Tls12ExtRsaMasterRequestPayload,\
                       Tls12EcdheRequestPayload, LurkExt

from pylurk.utils.utils import message_exchange, resolve_exchange, bytes_error_testing
from time import time

def get_payload_params(mtype, **kwargs):
    '''
    This method will initiate a RequestPayload object based on the mtype and build the payload parameters accordingly given a set of parameters **kwargs
    :param mtype: request type [rsa_master, rsa_master_with_poh, rsa_extended_master, rsa_extended_master_with_poh, ecdhe]
    :param kwargs: parameters needed for building the payload
    :return: payload parameters to be used
    '''

    #get a RequestPayload object based on the mtype
    payload_request = LurkExt('client').get_ext_class()['request', mtype]

    #build payload based on a defined set of paramters
    payload_params = payload_request.build_payload(**kwargs)

    return payload_params

def get_client (protocol, conectivity_conf, secureTLSConnection=False):
    '''
    This method will initiate and return a Lurk client object based on the protocol
    :param protocol: desired transport protocol ['udp', 'tcp', 'http', 'local']
    :param conectivity_conf: dictionnary for the connectivity information, mainly: ip address, port, tls certifications and keys
    :param secureTLSConnection: true or false in case we need a secure connection
    :return: LurKClient object corresponding to the protocol
    '''
    clt_conf = LurkConf()
    clt_conf.set_role('client')

    if (protocol == 'tcp'):
        clt_conf.set_connectivity(type='tcp', ip_address=conectivity_conf['ip'], port=conectivity_conf['port'], keys= conectivity_conf['tls_keys'], certs=conectivity_conf['tls_certs'])
        client = LurkTCPClient( conf = clt_conf.conf, secureTLS_connection=secureTLSConnection )

    elif (protocol == 'http'):
        clt_conf.set_connectivity(type='tcp', ip_address=conectivity_conf['ip'], port=conectivity_conf['port'],
                                  keys=conectivity_conf['tls_keys'], certs=conectivity_conf['tls_certs'])
        client = LurkHTTPClient(conf=clt_conf.conf, secureTLS_connection=secureTLSConnection)

    elif (protocol == 'udp'):
        clt_conf.set_connectivity(type='tcp', ip_address=conectivity_conf['ip'], port=conectivity_conf['port'], keys=conectivity_conf['tls_keys'], certs=conectivity_conf['tls_certs'])
        client = LurkUDPClient(conf=clt_conf.conf)

    else:
        clt_conf.set_connectivity(type='local')
        client = LurkClient(conf=clt_conf.conf)

    return client


#get_payload_params('rsa_master', prf_hash = "sha256", freshness_funct = "sha256")