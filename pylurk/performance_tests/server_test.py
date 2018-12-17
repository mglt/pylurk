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

def get_server(protocol, conectivity_conf, secureTLSConnection=False, multithreading =False, max_threads = 40):
    '''
    This method will initiate and return a Lurk server object based on the transport protocol
    :param protocol: desired transport protocol ['udp', 'tcp', 'http', 'local']
    :param conectivity_conf: dictionnary for the connectivity information, mainly: ip address, port, tls certifications and keys
    :param secureTLSConnection: true or false in case we need a secure connection
    :param multithreading: true or false in case we want to use multithreading
    :param max_threads: maximum number of threads to initiate in case we are using multithreading
    :return: LurkServer object
    '''
    srv_conf = LurkConf()
    srv_conf.set_role('server')

    if (protocol == 'tcp'):
        srv_conf.set_connectivity(type='tcp', ip_address=conectivity_conf['ip'], port=conectivity_conf['port'],
                                  keys=conectivity_conf['tls_keys'], certs=conectivity_conf['tls_certs'])
        if(multithreading):
            server = ThreadedLurkTCPServer(srv_conf.conf, max_workers=max_threads, secureTLS_connection=secureTLSConnection)
        else:
            server = LurkTCPServer(srv_conf.conf, secureTLS_connection=secureTLSConnection)
        t = threading.Thread(target=server.serve_forever)

        t.daemon = True
        t.start()

    elif (protocol == 'http'):
        srv_conf.set_connectivity(type='http', ip_address=conectivity_conf['ip'], port=conectivity_conf['port'],
                                  keys=conectivity_conf['tls_keys'], certs=conectivity_conf['tls_certs'])

        if (multithreading):
            server =ThreadedLurkHTTPserver(srv_conf.conf, max_workers=max_threads,secureTLS_connection=secureTLSConnection )
        else:
            server = LurkHTTPserver(srv_conf.conf, secureTLS_connection=secureTLSConnection)
        t = threading.Thread(target=server.serve_forever)
        t.daemon = True
        t.start()

    elif (protocol == 'udp'):
       srv_conf.set_connectivity(type='udp', ip_address=conectivity_conf['ip'], port=conectivity_conf['port'],
                                  keys=conectivity_conf['tls_keys'], certs=conectivity_conf['tls_certs'])

       if (multithreading):
           server = ThreadedLurkUDPServer(srv_conf.conf, max_workers=max_threads,
                                          secureTLS_connection=secureTLSConnection)
       else:
           server = LurkUDPServer(srv_conf.conf)
       t = threading.Thread(target=server.serve_client)
       t.daemon = True
       t.start()
    else:
        srv_conf.set_connectivity(type='local')
        server = LurkServer(conf=srv_conf.conf)

    return server
