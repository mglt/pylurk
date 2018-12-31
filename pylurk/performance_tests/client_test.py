import os.path
from  os.path import join
import threading
import pkg_resources

from pylurk.core.lurk import LurkServer, ImplementationError, LurkMessage, \
                 HEADER_LEN, LurkClient, LurkServer, LurkUDPClient, ThreadedLurkUDPServer, \
                 LurkUDPServer, LurkTCPClient, LurkTCPServer, ThreadedLurkTCPServer, LurkConf, UDPServerConf, PoolMixIn, LurkHTTPserver, LurkHTTPClient,HTTPRequestHandler,ThreadedLurkHTTPserver
from pylurk.extensions.tls12 import Tls12RsaMasterConf,  Tls12EcdheConf, \
                       Tls12RsaMasterRequestPayload,\
                       Tls12ExtRsaMasterRequestPayload,\
                       Tls12EcdheRequestPayload, LurkExt

from pylurk.utils.utils import message_exchange, resolve_exchange, bytes_error_testing
from time import time
import openpyxl



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

def get_client ( connectivity_conf, secureTLSConnection=False):
    '''
    This method will initiate and return a Lurk client object based on the protocol
    :param protocol: desired transport protocol ['udp', 'tcp', 'http', 'local']
    :param conectivity_conf: dictionnary for the connectivity information, mainly: type, ip address, port, tls certifications and keys
    :param secureTLSConnection: true or false in case we need a secure connection
    :return: LurKClient object corresponding to the protocol
    '''
    clt_conf = LurkConf()
    clt_conf.set_role('client')
    clt_conf.set_connectivity(type=connectivity_conf['type'], ip_address=connectivity_conf['ip_address'], port=connectivity_conf['port'],
                              keys=connectivity_conf['keys'], certs=connectivity_conf['certs'])

    protocol = connectivity_conf['type']

    if (protocol == 'tcp'):
       client = LurkTCPClient( conf = clt_conf.conf, secureTLS_connection=secureTLSConnection )

    elif (protocol == 'http'):
        client = LurkHTTPClient(conf=clt_conf.conf, secureTLS_connection=secureTLSConnection)

    elif (protocol == 'udp'):
       client = LurkUDPClient(conf=clt_conf.conf)

    else:
        clt_conf.set_connectivity(type='local')
        client = LurkClient(conf=clt_conf.conf)

    return client


def latency_test (payload_params, connectivity_conf, sheet_name, excel_file = "results.xlsx", secureTLSConnection = False, request_nb = 50, set_nb =20):
    '''

    :param payload_params: dictionary with payload parameters containing the list of tests setups to perform. For example:
          payload_params = {'rsa_master_ref_prf_sha256_pfs_sha256':{
             'type': 'rsa_master',
             'column_name': 'rsa_master_ref_prf_sha256_pfs_sha256', # name of column as it appears in excel file, if it contains 'ref', this means that it will be used as ref values
             'ref': 'rsa_master_ref_prf_sha256_pfs_sha256',  # ref column name when calculating ref values
             'prf_hash': 'sha256',
             'freshness_funct': 'sha256',}

        }
    :param connectivity_conf: dictionary with connectivity info. For example:
               connectivity_conf= {
                'type': "udp",  # "udp", "local",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'keys': {  # TLS keys
                    'client': join(data_dir, 'key_tls12_rsa_client.key'),
                    'server': join(data_dir, 'key_tls12_rsa_server.key'),
                },
                'certs': {  # TLS certifications
                    'client': join(data_dir, 'cert_tls12_rsa_client.crt'),
                    'server': join(data_dir, 'cert_tls12_rsa_server.crt'),
                },
            }
    :param sheet_name: name of the excel sheet where the data should be saved
    :param excel_file:  path of excel file to save the results. The file is created if it does not exist
    :param secureTLSConnection: true if the connection should be secured
    :param request_nb: nb of requests  per set to report their latency
    :param set_nb: nb of sets to test
    :return: row_id in the excel sheet where we can start writing without overwriting any existing values
    '''
    #start by setting up a dictionnary of all parameters of the test to write in excel
    test_params = {
        'connectivity_conf': connectivity_conf,
        'secureTLSConnection':secureTLSConnection,
        'payload_params' : payload_params,
        'set_nb':set_nb,
        'request_nb':request_nb,
        'other_info': {'test_type': 'latency', #specify that we are testing the latency
                       'latency_unit': 'seconds', #specify that the reported latency results are in sec
                       }
    }

    row_id =1
    column_id = 1


    # check if excel file exists and create it otherwise
    if (os.path.isfile(excel_file) == False):
        book = openpyxl.Workbook()
        book.save(excel_file)

    book = openpyxl.load_workbook(excel_file)

    # create the sheet if it does not exist in the mentioned excel_file
    if (sheet_name not in book.sheetnames):
        book.create_sheet(sheet_name)
        book.save(excel_file)

    #get the sheet
    sheet = book[sheet_name]
    sheet.cell(row=row_id, column=column_id).value = 'Test parameters'
    book.save(excel_file)

    #update row and column
    row_id += 1

    #start by writing parameters to excel sheet
    row_id = print_dict(test_params, sheet, row_id, column_id+1)

    sheet.cell(row=row_id, column=column_id).value = 'Set'

    #get the lurk client
    client = get_client(connectivity_conf, secureTLSConnection)

    test_count =1

    for key, params_value in payload_params.items():

        #write the column name reflecting the test we are performing
        sheet.cell(row=row_id, column=column_id+test_count).value = params_value['column_name']

       #generate payload params
        generated_payload_params = get_payload_params(params_value['type'], args = params_value)

        #loop over the set nb
        for j in range (0, set_nb):

            # get total processing time for all requests
            time_start = time()

            for i in range (0, request_nb):
                client.resolve(designation='tls12', \
                               version='v1', \
                               type=params_value['type'], \
                               payload=generated_payload_params)
            # get total processing time for all requests
            time_stop = time()

            # calculate the processing time for requestsNb requests and return it
            total_time = time_stop - time_start

            #write the set id
            sheet.cell(row=row_id+j+1, column=column_id).value = j
            #write the total time to send and recieve request_nb requests
            sheet.cell(row=row_id+j+1, column=column_id+test_count).value = total_time  # to change columns

            #save the file at each set test to keep track of the test
            book.save(excel_file)

            #print some log info
            print("%s %s resolutions in %s sec." % (set, params_value['column_name'], total_time))

        test_count=test_count+1
        book.close()

    # row id  is the row nb depicting the title of tests; thus we retun an empty row where we can start writing to the file after leaving 2 empty rows
    return row_id+set_nb+2
    #read sheet and write ratios
    #create and save graph


def print_dict(dictionary, sheet, row_id, column_id):
    '''
    Method that recursively prints nested dictionaries in an excel sheet.
    IMPORTANT NOTE: this method can not be used by itself as it does not save the sheet. It is a helper function that is called within write_to_excel
    :param dictionary: nested dictionary to print (tuples within the dictionary are supported)
    :param sheet: excel sheet object
    :param row_id: row where to start printing
    :param column_id: column where to start printing
    :return: row id after the last used row (row in which new information can be written)
    '''

    for key, value in dictionary.items():
        if isinstance(value, dict):
            sheet.cell(row=row_id, column=column_id).value = key
            row_id = print_dict(value, sheet, row_id, column_id+1)

        else:
            sheet.cell(row=row_id, column=column_id).value = key
            if isinstance(value, tuple):
                v = "( "
                for t in value:
                    v +=t+", "
                v +=" )"
                sheet.cell(row=row_id, column=column_id + 1).value = v
            else:
                sheet.cell(row=row_id, column=column_id + 1).value = value
            row_id+=1
    return row_id

def write_to_excel ( excel_file, sheet_name, row_id, column_id, **kwargs):
    '''
    This method loads the excel file and and writes the test parameters in the specified sheet
    :param excel_file: excel file path to write into (this file is created if it does not exist)
    :param sheet_name: the sheet name in the specified excel_file to write into. The sheet is created if it does not exist
    :param row_id: row number where to start writing in the excel_file (takes any value >= 1)
    :param column_id: column where to strat writing in the excel file (takes any value >=  1)
    :param kwargs: the list to write in the specified sheet. This can be a nested dictionary. For example:
            'connectivity_conf': connectivity_conf, #connectivity info including type, ip, port, tls keys and tls certificates
            'secureTLSConnection':secureTLSConnection,
            'payload_params' : payload_params, #all payload parameters including specific lurk tests
            'set_nb':set_nb, #nb of tests to run
            'request_nb':request_nb, #nb of requests to test
            'other_info': {'test_type': 'latency', #specifies the test type [latency, CPU']
                           'latency_unit': 'seconds', #specifies that the reported latency results are in sec
                           'multiThreading': True' #specifies if we are using multithreading
                           'thread_nb': 4 #nb of threads used in the test
                           #any other values needed to be printed can be included here

    }
    :return: the row_id at which we can start writing in the specified sheet (leaves 1 empty row)
    '''


    #check if excel file exists and create it otherwise
    if (os.path.isfile(excel_file) == False):
        book = openpyxl.Workbook()
        book.save(excel_file)

    # load the excel file to write into
    book = openpyxl.load_workbook(excel_file)


    #create the sheet if it does not exist in the mentioned excel_file
    if (sheet_name not in book.sheetnames):
        book.create_sheet(sheet_name)
        book.save(excel_file)

    # load the sheet
    sheet = book[sheet_name]

    #print all the kwargs in the sheet
    row_id = print_dict(kwargs, sheet, row_id, column_id)

    #add an empty row
    row_id += 1
    book.save(excel_file)

    #close the book to prevent any errors in re-loading it
    book.close()

    #return the row where we can start writing other information (results)
    return row_id


def authentication_methods ():
    payload_params = {'rsa_master_ref_prf_sha256_pfs_sha256':{
             'type': 'rsa_master',
             'column_name': 'rsa_master_ref_prf_sha256_pfs_sha256', # name of column as it appears in excel file, if it contains 'ref', this means that it will be used as ref values
             'ref': 'rsa_master_ref_prf_sha256_pfs_sha256',  # ref column name when calculating ref values
             'prf_hash': 'sha256',
             'freshness_funct': 'sha256',}

    }
    payload_paramss = {'rsa_master_ref_prf_sha256_pfs_sha256': {
        'type': 'rsa_master',
        'column_name': 'rsa_master_ref_prf_sha256_pfs_sha256', # name of column as it appears in excel file, if it contains 'ref', this means that it will be used as ref values
        'ref': 'rsa_master_ref_prf_sha256_pfs_sha256',  # ref column name when calculating ref values
        'prf_hash': 'sha256',
        'freshness_funct': 'sha256',

    },
        'rsa_master_prf_sha384_pfs_sha512': {
            'type': 'rsa_master',
            'column_name': 'rsa_master_prf_sha384_pfs_sha512',
            'ref': 'rsa_master_ref_prf_sha256_pfs_sha256',
            'prf_hash': 'sha384',
            'freshness_funct': 'sha512'
        },
        'rsa_master_prf_sha512_pfs_sha512': {
            'type': "rsa_master",
            'column_name': 'rsa_master_prf_sha512_pfs_sha512',
            'ref': 'rsa_master_ref_prf_sha256_pfs_sha256',
            'prf_hash': 'sha512',
            'freshness_funct': 'sha512'
        },

        'rsa_extended_master_prf_sha256_pfs_sha256': {
            'type': 'rsa_extended_master',
            'column_name': 'rsa_extended_master_prf_sha256_pfs_sha256',
            'ref': 'rsa_master_ref_prf_sha256_pfs_sha256',
            'prf_hash': 'sha256',
            'freshness_funct': 'sha256'

        },
        'rsa_extended_master_prf_sha384_pfs_sha512': {
            'type': "rsa_extended_master",
            'column_name': 'rsa_extended_master_prf_sha384_pfs_sha512',
            'ref': 'rsa_master_ref_prf_sha256_pfs_sha256',
            'prf_hash': "sha384",
            'freshness_funct': "sha512"
        },
        'rsa_extended_master_prf_sha512_pfs_sha512': {
            'type': "rsa_extended_master",
            'column_name': 'rsa_extended_master_prf_sha512_pfs_sha512',
            'ref': 'rsa_master_ref_prf_sha256_pfs_sha256',
            'prf_hash': 'sha512',
            'freshness_funct': 'sha512'
        },

        'ecdhe_sig_sha256rsa_pfs_sha256': {
            'type': 'ecdhe',
            'column_name': 'ecdhe_sig_sha256rsa_pfs_sha256',
            'ref': 'rsa_master_ref_prf_sha256_pfs_sha256',
            'sig_and_hash': ('sha256', 'rsa'),
            'freshness_funct': 'sha256'
        },
        'ecdhe_sig_sha512rsa_pfs_sha256': {
            'type': 'ecdhe',
            'column_name': 'ecdhe_sig_sha512rsa_pfs_sha256',
            'ref': 'rsa_master_ref_prf_sha256_pfs_sha256',
            'sig_and_hash': ('sha512', 'rsa'),
            'freshness_funct': 'sha256'
        },
        'ecdhe_sig_sha512rsa_pfs_sha512': {
            'type': 'ecdhe',
            'column_name': 'ecdhe_sig_sha512rsa_pfs_sha512',
            'ref': 'rsa_master_ref_prf_sha256_pfs_sha256',
            'sig_and_hash': ('sha512', 'rsa'),
            'freshness_funct': 'sha512'
        },
    }

    data_dir = pkg_resources.resource_filename(__name__, '../data/')
    connectivity_conf= {
        'type': "udp",  # "udp", "local",
        'ip_address': "127.0.0.1",
        'port': 6789,
        'keys': {  # TLS keys
            'client': join(data_dir, 'key_tls12_rsa_client.key'),
            'server': join(data_dir, 'key_tls12_rsa_server.key'),
        },
        'certs': {  # TLS certifications
            'client': join(data_dir, 'cert_tls12_rsa_client.crt'),
            'server': join(data_dir, 'cert_tls12_rsa_server.crt'),
        },
    }

    sheet_name = 'Authentication_methods_latency'
    row_id = latency_test (payload_params, connectivity_conf, sheet_name, excel_file = "results.xlsx", secureTLSConnection = False, request_nb = 2, set_nb =1)






