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

def start_server(connectivity_conf, secureTLSConnection=False, multithreading =False, max_threads = 40):
    '''
    This method will initiate and return a Lurk server object based on the transport protocol
    :param conectivity_conf: dictionnary for the connectivity information, mainly:  type, ip address, port, tls certifications and keys
    :param secureTLSConnection: true or false in case we need a secure connection
    :param multithreading: true or false in case we want to use multithreading
    :param max_threads: maximum number of threads to initiate in case we are using multithreading
    :return: LurkServer object
    '''
    srv_conf = LurkConf()
    srv_conf.set_role('server')
    srv_conf.set_connectivity(type=connectivity_conf['type'], ip_address=connectivity_conf['ip_address'], port=connectivity_conf['port'],
                              keys=connectivity_conf['keys'], certs=connectivity_conf['certs'])

    protocol = connectivity_conf['type']

    if (protocol == 'local'):
        srv_conf.set_connectivity(type='local')
        server = LurkServer(conf=srv_conf.conf)
        return server

    if (protocol == 'tcp'):
        if(multithreading):
            server = ThreadedLurkTCPServer(srv_conf.conf, max_workers=max_threads, secureTLS_connection=secureTLSConnection)
        else:
            server = LurkTCPServer(srv_conf.conf, secureTLS_connection=secureTLSConnection)

    elif (protocol == 'http'):
        if (multithreading):
            server =ThreadedLurkHTTPserver(srv_conf.conf, max_workers=max_threads,secureTLS_connection=secureTLSConnection )
        else:
            server = LurkHTTPserver(srv_conf.conf, secureTLS_connection=secureTLSConnection)

    elif (protocol == 'udp'):
       if (multithreading):
           server = ThreadedLurkUDPServer(srv_conf.conf, max_workers=max_threads,
                                          secureTLS_connection=secureTLSConnection)
       else:
           server = LurkUDPServer(srv_conf.conf)

    t = threading.Thread(target=server.serve_forever)
    t.daemon = True
    t.start()

    return server
