from  os.path import join
import pkg_resources
from pylurk.performance_tests.performance_utils import latency_test, cpu_overhead_test, get_RTT
from copy import deepcopy

def authentication_methods_test (sheet_name, excel_file, graph_path, thread, request_nb, set_nb):
    '''
    This method performs some latency tests on authentication methods (RSA, RSA_extended and ECDHE) by varying the prf (256 (reference), 384, 512),
    ECDHE: 'sig_and_hash': ('sha256', 'rsa'),'sig_and_hash': ('sha512', 'rsa').
    It saves the results in the specified excel file and plot them in 2 box graphs (one for latency values and another for ratios)
    :param sheet_name: the excel sheet name to store the results
    :param excel_file: path to the excel file that will contain the results. The file is created if it does not exists
    :param graph_path: path to the graphs depicting the results (e.g. results/ (do not start the path with "/")
    :param thread: True or False depicting if we want to
    :param request_nb: requests number to test per set.
    :param set_nb: number of sets to test
    :return:
    '''
    payload_params = {
        'udpLocal':[
            {
            'type': 'rsa_master',
            'column_name': 'rsa_master_ref_prf_sha256_pfs_sha256', # name of column as it appears in excel file, if it contains 'ref', this means that it will be used as ref values
            'ref': 'rsa_master_ref_prf_sha256_pfs_sha256',  # ref column name when calculating ref values
            'prf_hash': 'sha256',
            'freshness_funct': 'sha256',

            },
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_prf_sha384_pfs_sha256',
                'ref': 'rsa_master_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha384',
                'freshness_funct': 'sha256'
            },
            {
                'type': "rsa_master",
                'column_name': 'rsa_master_prf_sha512_pfs_sha256',
                'ref': 'rsa_master_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha512',
                'freshness_funct': 'sha256'
            },
            {
                'type': 'rsa_extended_master',
                'column_name': 'rsa_extended_master_ref_prf_sha256_pfs_sha256',
                'ref': 'rsa_extended_master_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256'

            },
            {
                'type': "rsa_extended_master",
                'column_name': 'rsa_extended_master_prf_sha384_pfs_sha256',
                'ref': 'rsa_extended_master_ref_prf_sha256_pfs_sha256',
                'prf_hash': "sha384",
                'freshness_funct': "sha256"
            },
            {
                'type': "rsa_extended_master",
                'column_name': 'rsa_extended_master_prf_sha512_pfs_sha256',
                'ref': 'rsa_extended_master_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha512',
                'freshness_funct': 'sha256'
            },
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_ref_sig_sha256rsa_pfs_sha256',
                'ref': 'ecdhe_ref_sig_sha256rsa_pfs_sha256',
                'sig_and_hash': ('sha256', 'rsa'),
                'freshness_funct': 'sha256'
            },
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_sig_sha512rsa_pfs_sha256',
                'ref': 'ecdhe_ref_sig_sha256rsa_pfs_sha256',
                'sig_and_hash': ('sha512', 'rsa'),
                'freshness_funct': 'sha256'
            },

        ]
    }

    data_dir = pkg_resources.resource_filename(__name__, '../data/')
    connectivity_conf= {
            'udpLocal':{
                'type': "udp",  # "udp", "local",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            }

    }

    graph_params = {'title': '',
                    'xlabel': 'Authentication Methods',
                    'ylabel': 'Latency (sec)',
                    'box_width': 0.5,  # width of each box in the graph
                    'start_position': 1,  # the position of the first box to draw
                    'show_grid': True,  # show grid in the graph
                    'legend': {
                        'location': 'lower right',
                    # location of the legend. Can take one of the following values:'best','upper right','upper left','lower left','lower right','right','center left','center right','lower center','upper center','center'
                        'font_properties': {
                            # 'fontname':'Calibri',
                            'size': '12',
                            # 'weight': 'bold',
                        }
                    },
                    'font_properties': {  # font properties of title, ylabel and xlabel
                        # 'fontname':'Calibri',
                        'size': '14',
                        'weight': 'bold',
                    },
                    'ticks_font_properties': {
                        # 'fontname':'Calibri',
                        'size': '12',
                        # 'weight': 'bold',
                    },
                    # data to plot grouped into multiple group. if no group is desired, a dictionary for each data to plot should be added
                    'groups': [
                        {'tick_label': 'RSA',  # label on xaxis depicting all the data in data
                         'color': ['white','white'],#['blue', 'green'],
                         # color of the box of each data in data, set 'White if no color is desired
                         'hatch': ['*', 'o'],
                         # pattern of each box in data. Set '' if no hatch is desired. It can take one of the following patterns = ('-', '+', 'x', '\\', '*', 'o', 'O', '.', '/')
                         'data': ['rsa_master_prf_sha384_pfs_sha256', 'rsa_master_prf_sha512_pfs_sha256'],
                         # colummn name of the data to plot as defined in excel sheet
                         'legends': ['prf = sha384', 'prf = sha512']
                         # legend corresponding to each data, set None if no legend to be added to a specified data or provide an empty list
                         },
                        {'tick_label': 'RSA_Extended',
                         'color':['white','white'],# ['blue', 'green'],  # same color and hatch as previous group to have same legend
                         'hatch': ['*', 'o'],
                         'data': ['rsa_extended_master_prf_sha384_pfs_sha256',
                                  'rsa_extended_master_prf_sha512_pfs_sha256'],
                         'legends': [],  # empty list to have one legend per color as specified in previous group
                         },
                        {'tick_label': 'ECDHE',
                         'color': ['white'],#['green'],
                         'hatch': ['o'],
                         'data': ['ecdhe_sig_sha512rsa_pfs_sha256'],
                         'legends': [],
                         },

                    ]}

    latency_test (payload_params, connectivity_conf, graph_params, sheet_name, graph_path, excel_file = excel_file, thread=thread, request_nb_list = [request_nb], set_nb =set_nb)


def mechanism_overhead_pfs_test (sheet_name, excel_file, graph_path, thread, request_nb, set_nb):
    '''
     This method performs some latency tests on authentication methods (RSA, RSA_extended and ECDHE) by varying the pfs (null (reference), 256),
     ECDHE: 'sig_and_hash': ('sha256', 'rsa').
     It saves the results in the specified excel file and plot them in 2 box graphs (one for latency values and another for ratios)
     :param sheet_name: the excel sheet name to store the results
     :param excel_file: path to the excel file that will contain the results. The file is created if it does not exists
     :param graph_path: path to the graphs depicting the results (e.g. results/ (do not start the path with "/")
     :param thread: True or False depicting if we want to
     :param request_nb: requests number to test per set.
     :param set_nb: number of sets to test
     :return:
     '''
    payload_params = {
        'udpLocal': [
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_ref_prf_sha256_pfs_null',
                'ref': 'rsa_master_ref_prf_sha256_pfs_null',
                'prf_hash': 'sha256',
                'freshness_funct': 'null',

            },
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_ref_prf_sha256_pfs_null',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256'
            },
            {
                'type': 'rsa_extended_master',
                'column_name': 'rsa_extended_master_ref_prf_sha256_pfs_null',
                'ref': 'rsa_extended_master_ref_prf_sha256_pfs_null',
                'prf_hash': 'sha256',
                'freshness_funct': 'null'

            },
            {
                'type': "rsa_extended_master",
                'column_name': 'rsa_extended_master_prf_sha256_pfs_sha256',
                'ref': 'rsa_extended_master_ref_prf_sha256_pfs_null',
                'prf_hash': "sha256",
                'freshness_funct': "sha256"
            },
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_ref_sig_sha256rsa_pfs_null',
                'ref': 'ecdhe_ref_sig_sha256rsa_pfs_null',
                'sig_and_hash': ('sha256', 'rsa'),
                'freshness_funct': 'null'
            },
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_sig_sha256rsa_pfs_sha256',
                'ref': 'ecdhe_ref_sig_sha256rsa_pfs_null',
                'sig_and_hash': ('sha256', 'rsa'),
                'freshness_funct': 'sha256'
            },

        ]
    }

    data_dir = pkg_resources.resource_filename(__name__, '../data/')
    connectivity_conf = {
            'udpLocal': {
                'type': "udp",  # "udp", "local",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            }

    }

    graph_params = {'title': '',
                    'xlabel': 'Authentication Methods',
                    'ylabel': 'Latency (sec)',
                    'box_width': 0.5,  # width of each box in the graph
                    'start_position': 1,  # the position of the first box to draw
                    'show_grid': True,  # show grid in the graph
                    'legend': {
                        'location': 'lower right',
                        # location of the legend. Can take one of the following values:'best','upper right','upper left','lower left','lower right','right','center left','center right','lower center','upper center','center'
                        'font_properties': {
                            # 'fontname':'Calibri',
                            'size': '12',
                            # 'weight': 'bold',
                        }
                    },
                    'font_properties': {  # font properties of title, ylabel and xlabel
                        # 'fontname':'Calibri',
                        'size': '14',
                        'weight': 'bold',
                    },
                    'ticks_font_properties': {
                        # 'fontname':'Calibri',
                        'size': '12',
                        # 'weight': 'bold',
                    },
                    # data to plot grouped into multiple group. if no group is desired, a dictionary for each data to plot should be added
                    'groups': [
                        {'tick_label': 'RSA',  # label on xaxis depicting all the data in data
                         'color': ['white'],
                         # color of the box of each data in data, set 'White if no color is desired
                         'hatch': ['*'],
                         # pattern of each box in data. Set '' if no hatch is desired. It can take one of the following patterns = ('-', '+', 'x', '\\', '*', 'o', 'O', '.', '/')
                         'data': ['rsa_master_prf_sha256_pfs_sha256'],
                         # colummn name of the data to plot as defined in excel sheet
                         'legends': ['pfs = sha256']
                         # legend corresponding to each data, set None if no legend to be added to a specified data or provide an empty list
                         },
                        {'tick_label': 'RSA_Extended',
                         'color': ['white'],  # same color and hatch as previous group to have same legend
                         'hatch': ['*'],
                         'data': ['rsa_extended_master_prf_sha256_pfs_sha256'],
                         'legends': [],  # empty list to have one legend per color as specified in previous group
                         },
                        {'tick_label': 'ECDHE',
                         'color': ['white'],
                         'hatch': ['*'],
                         'data': ['ecdhe_sig_sha256rsa_pfs_sha256'],
                         'legends': [],
                         },

                    ]}

    latency_test(payload_params, connectivity_conf, graph_params, sheet_name, graph_path, excel_file=excel_file,
                 thread=thread, request_nb_list=[request_nb], set_nb=set_nb)

def mechanism_overhead_poh_test (sheet_name, excel_file, graph_path, thread, request_nb, set_nb):
    '''
     This method performs some latency tests to check the overhead of the proof of handshake on authentication methods (RSA, RSA_extended)
     It saves the results in the specified excel file and plot them in 2 box graphs (one for latency values and another for ratios)
     :param sheet_name: the excel sheet name to store the results
     :param excel_file: path to the excel file that will contain the results. The file is created if it does not exists
     :param graph_path: path to the graphs depicting the results (e.g. results/ (do not start the path with "/")
     :param thread: True or False depicting if we want to
     :param request_nb: requests number to test per set.
     :param set_nb: number of sets to test
     :return:
     '''
    payload_params = {
        'udpLocal': [
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256'
            },
            {
                'type': 'rsa_master_with_poh',
                'column_name': 'rsa_master_with_poh_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256'
            },

            {
                'type': "rsa_extended_master",
                'column_name': 'rsa_extended_master_prf_sha256_pfs_sha256',
                'ref': 'rsa_extended_master_prf_sha256_pfs_sha256',
                'prf_hash': "sha256",
                'freshness_funct': "sha256"
            },
            {
                'type': "rsa_extended_master_with_poh",
                'column_name': 'rsa_extended_master_with_poh_prf_sha256_pfs_sha256',
                'ref': 'rsa_extended_master_prf_sha256_pfs_sha256',
                'prf_hash': "sha256",
                'freshness_funct': "sha256"
            },

        ]
    }

    data_dir = pkg_resources.resource_filename(__name__, '../data/')
    connectivity_conf = {
            'udpLocal': {
                'type': "udp",  # "udp", "local",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            }

    }

    graph_params = {'title': '',
                    'xlabel': 'Authentication Methods',
                    'ylabel': 'Latency (sec)',
                    'box_width': 0.5,  # width of each box in the graph
                    'start_position': 1,  # the position of the first box to draw
                    'show_grid': True,  # show grid in the graph
                    'legend': {
                        'location': 'lower right',
                        # location of the legend. Can take one of the following values:'best','upper right','upper left','lower left','lower right','right','center left','center right','lower center','upper center','center'
                        'font_properties': {
                            # 'fontname':'Calibri',
                            'size': '12',
                            # 'weight': 'bold',
                        }
                    },
                    'font_properties': {  # font properties of title, ylabel and xlabel
                        # 'fontname':'Calibri',
                        'size': '14',
                        'weight': 'bold',
                    },
                    'ticks_font_properties': {
                        # 'fontname':'Calibri',
                        'size': '12',
                        # 'weight': 'bold',
                    },
                    # data to plot grouped into multiple group. if no group is desired, a dictionary for each data to plot should be added
                    'groups': [
                        {'tick_label': 'RSA',  # label on xaxis depicting all the data in data
                         'color': ['white'], #['blue', 'green'],
                         # color of the box of each data in data, set 'White if no color is desired
                         'hatch': ['*'],
                         # pattern of each box in data. Set '' if no hatch is desired. It can take one of the following patterns = ('-', '+', 'x', '\\', '*', 'o', 'O', '.', '/')
                         'data': ['rsa_master_with_poh_prf_sha256_pfs_sha256'],
                         # colummn name of the data to plot as defined in excel sheet
                         'legends': [ 'With PoH']
                         # legend corresponding to each data, set None if no legend to be added to a specified data or provide an empty list
                         },
                        {'tick_label': 'RSA_Extended',
                         'color': ['white'],#['blue' 'green'],  # same color and hatch as previous group to have same legend
                         'hatch': ['*'],
                         'data': ['rsa_extended_master_with_poh_prf_sha256_pfs_sha256'],
                         'legends': [],  # empty list to have one legend per color as specified in previous group
                         },


                    ]}

    latency_test(payload_params, connectivity_conf, graph_params, sheet_name, graph_path, excel_file=excel_file,
                 thread=thread, request_nb_list=[request_nb], set_nb=set_nb)

def mechanism_overhead_poo_test (sheet_name, excel_file, graph_path, thread, request_nb, set_nb):
    '''
     This method performs some latency tests to check the overhead of the proof of ownership on ECDHE by varying the poo_prf (null (reference), 128, 256),
     It saves the results in the specified excel file and plot them in 2 box graphs (one for latency values and another for ratios)
     :param sheet_name: the excel sheet name to store the results
     :param excel_file: path to the excel file that will contain the results. The file is created if it does not exists
     :param graph_path: path to the graphs depicting the results (e.g. results/ (do not start the path with "/")
     :param thread: True or False depicting if we want to
     :param request_nb: requests number to test per set.
     :param set_nb: number of sets to test
     :return:
     '''
    payload_params = {
        'udpLocal': [
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_ref_poo_null_sig_sha256rsa_pfs_sha256',
                'ref': 'ecdhe_ref_poo_null_sig_sha256rsa_pfs_sha256',
                'sig_and_hash': ('sha256', 'rsa'),
                'freshness_funct': 'sha256',
                'poo_prf': ["null"],
            },
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_poo_sha256_128_sig_sha256rsa_pfs_sha256',
                'ref': 'ecdhe_ref_poo_null_sig_sha256rsa_pfs_sha256',
                'sig_and_hash': ('sha256', 'rsa'),
                'freshness_funct': 'sha256',
                'poo_prf': [ "sha256_128"],
            },
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_poo_sha256_256_sig_sha256rsa_pfs_sha256',
                'ref': 'ecdhe_ref_poo_null_sig_sha256rsa_pfs_sha256',
                'sig_and_hash': ('sha256', 'rsa'),
                'freshness_funct': 'sha256',
                'poo_prf': [ "sha256_256"],
            },
        ]
    }

    data_dir = pkg_resources.resource_filename(__name__, '../data/')
    connectivity_conf = {
            'udpLocal': {
                'type': "udp",  # "udp", "local",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            }
        }


    graph_params = {'title': '',
                    'xlabel': 'PoO',
                    'ylabel': 'Latency (sec)',
                    'box_width': 0.5,  # width of each box in the graph
                    'start_position': 1,  # the position of the first box to draw
                    'show_grid': True,  # show grid in the graph
                    'legend': {
                        'location': 'lower right',
                        # location of the legend. Can take one of the following values:'best','upper right','upper left','lower left','lower right','right','center left','center right','lower center','upper center','center'
                        'font_properties': {
                            # 'fontname':'Calibri',
                            'size': '12',
                            # 'weight': 'bold',
                        }
                    },
                    'font_properties': {  # font properties of title, ylabel and xlabel
                        # 'fontname':'Calibri',
                        'size': '14',
                        'weight': 'bold',
                    },
                    'ticks_font_properties': {
                        # 'fontname':'Calibri',
                        'size': '12',
                        # 'weight': 'bold',
                    },
                    # data to plot grouped into multiple group. if no group is desired, a dictionary for each data to plot should be added
                    'groups': [
                        {'tick_label': 'sha256_128',  # label on xaxis depicting all the data in data
                         'color': ['white'],#['blue'],  # color of the box of each data in data, set 'White if no color is desired
                         'hatch': ['*'],  # pattern of each box in data. Set '' if no hatch is desired. It can take one of the following patterns = ('-', '+', 'x', '\\', '*', 'o', 'O', '.', '/')
                         'data': ['ecdhe_poo_sha256_128_sig_sha256rsa_pfs_sha256'],  # colummn name of the data to plot as defined in excel sheet
                         'legends': ['With PoO'] # legend corresponding to each data, set None if no legend to be added to a specified data or provide an empty list
                         },
                        {'tick_label': 'sha256_256',
                         'color': ['white'],#['blue' ],
                         'hatch': ['*'],
                         'data': ['ecdhe_poo_sha256_256_sig_sha256rsa_pfs_sha256'],
                         'legends': None,
                         },


                    ]}

    latency_test(payload_params, connectivity_conf, graph_params, sheet_name, graph_path, excel_file=excel_file,
                 thread=thread, request_nb_list=[request_nb], set_nb=set_nb)

def transport_protocol_test( sheet_name, excel_file, graph_path, thread, request_nb, set_nb, server_ip,remote_user, server_password):
    '''
    This performs the transport protocol tests between a client and a server
    :param sheet_name: the excel sheet name to store the results
    :param excel_file: path to the excel file that will contain the results. The file is created if it does not exists
    :param graph_path: path to the graphs depicting the results (e.g. results/ (do not start the path with "/")
    :param thread: True or False depicting if we want to
    :param request_nb: requests number to test per set.
    :param set_nb: number of sets to test
    :param server_ip: Ip of the server to which we want to connect remotly
    :param remote_user: username of remote server
    :param server_password: password of remote server
    :return:
    '''


    payload_params = {
        'udpLocal':[
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'rsa_extended_master',
                'column_name': 'rsa_extended_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'ref': 'rsa_extended_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_udpLocal_ref_sig_sha256rsa_pfs_sha256',
                'ref': 'ecdhe_udpLocal_ref_sig_sha256rsa_pfs_sha256',
                'sig_and_hash': ('sha256', 'rsa'),
                'freshness_funct': 'sha256'
            },

        ],
        'udp': [
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_udp_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'rsa_extended_master',
                'column_name': 'rsa_extended_master_udp_prf_sha256_pfs_sha256',
                'ref': 'rsa_extended_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_udp_sig_sha256rsa_pfs_sha256',
                'ref': 'ecdhe_udpLocal_ref_sig_sha256rsa_pfs_sha256',
                'sig_and_hash': ('sha256', 'rsa'),
                'freshness_funct': 'sha256'
            },

        ],
        'tcp': [
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_tcp_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'rsa_extended_master',
                'column_name': 'rsa_extended_master_tcp_prf_sha256_pfs_sha256',
                'ref': 'rsa_extended_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_tcp_sig_sha256rsa_pfs_sha256',
                'ref': 'ecdhe_udpLocal_ref_sig_sha256rsa_pfs_sha256',
                'sig_and_hash': ('sha256', 'rsa'),
                'freshness_funct': 'sha256'
            },

        ],
        'http': [
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_http_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'rsa_extended_master',
                'column_name': 'rsa_extended_master_http_prf_sha256_pfs_sha256',
                'ref': 'rsa_extended_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_http_sig_sha256rsa_pfs_sha256',
                'ref': 'ecdhe_udpLocal_ref_sig_sha256rsa_pfs_sha256',
                'sig_and_hash': ('sha256', 'rsa'),
                'freshness_funct': 'sha256'
            },

        ],

    }

    #define connectivity conf fo client and server
    data_dir = pkg_resources.resource_filename(__name__, '../data/')
    conf = { 'type': "tcp",
                'ip_address': server_ip,
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'remote_user':remote_user,
                'password': server_password,
                'path_to_erilurk':"Desktop/HyameServer/projects/erilurk"
             }

    connectivity_conf = {
        # ensure local connection for udlLocal (do not set remote_user
        'udpLocal': {
            'ip_address': '127.0.0.1',
            'port': 6789,
            'key': join(data_dir, 'key_tls12_rsa_server.key'),
            'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
            'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
            'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt'),
        }
    }
    for type in [  'udp','tcp', 'http']:
        connectivity_conf[type] = deepcopy(conf)
        connectivity_conf[type]['type'] = type


    graph_params = {'title': '',
                    'xlabel': 'Athentication Methods',
                    'ylabel': 'Latency (sec)',
                    'box_width': 0.5,  # width of each box in the graph
                    'start_position': 1,  # the position of the first box to draw
                    'show_grid': True,  # show grid in the graph
                    'legend': {
                        'location': 'lower right',
                        # location of the legend. Can take one of the following values:'best','upper right','upper left','lower left','lower right','right','center left','center right','lower center','upper center','center'
                        'font_properties': {
                            # 'fontname':'Calibri',
                            'size': '12',
                            # 'weight': 'bold',
                        }
                    },
                    'font_properties': {  # font properties of title, ylabel and xlabel
                        # 'fontname':'Calibri',
                        'size': '14',
                        'weight': 'bold',
                    },
                    'ticks_font_properties': {
                        # 'fontname':'Calibri',
                        'size': '12',
                        # 'weight': 'bold',
                    },
                    # data to plot grouped into multiple group. if no group is desired, a dictionary for each data to plot should be added
                    'groups': [
                        {'tick_label': 'RSA',  # label on xaxis depicting all the data in data
                         'color': ['white','white','white'],#['blue', 'green', 'orange'],
                         # color of the box of each data in data, set 'White if no color is desired
                         'hatch': [ '*','/', 'o'], # pattern of each box in data. Set '' if no hatch is desired. It can take one of the following patterns = ('-', '+', 'x', '\\', '*', 'o', 'O', '.', '/')
                         'data': [ 'rsa_master_udp_prf_sha256_pfs_sha256', 'rsa_master_tcp_prf_sha256_pfs_sha256', 'rsa_master_http_prf_sha256_pfs_sha256'],
                         # colummn name of the data to plot as defined in excel sheet
                         'legends': ['UDP', 'TCP', 'HTTP']      # legend corresponding to each data, set None if no legend to be added to a specified data or provide an empty list
                         },
                        {'tick_label': 'RSA_Extended',
                         'color': ['white','white','white'],#['blue', 'green', 'orange'],  # same color and hatch as previous group to have same legend
                         'hatch': ['*','/', 'o'],
                         'data': ['rsa_extended_master_udp_prf_sha256_pfs_sha256','rsa_extended_master_tcp_prf_sha256_pfs_sha256','rsa_extended_master_http_prf_sha256_pfs_sha256'],
                         'legends': [],  # empty list to have one legend per color as specified in previous group
                         },
                        {'tick_label': 'ECDHE',
                         'color': ['white','white','white'],#['blue', 'green', 'orange'],
                         'hatch': ['*','/', 'o'],
                         'data': ['ecdhe_udp_sig_sha256rsa_pfs_sha256', 'ecdhe_tcp_sig_sha256rsa_pfs_sha256', 'ecdhe_http_sig_sha256rsa_pfs_sha256'],
                         'legends': [],
                         },

                    ]}

    latency_test(payload_params, connectivity_conf, graph_params, sheet_name, graph_path, excel_file=excel_file,
                 thread=thread, request_nb_list=[request_nb], set_nb=set_nb, remote_connection=True)


def security_overhead_test( sheet_name, excel_file, graph_path, thread, request_nb, set_nb, server_ip,remote_user, server_password):
    '''
      This performs the security overhead latency tests (tcp, tcp+tls, http, https) between a client and a server
      :param sheet_name: the excel sheet name to store the results
      :param excel_file: path to the excel file that will contain the results. The file is created if it does not exists
      :param graph_path: path to the graphs depicting the results (e.g. results/ (do not start the path with "/")
      :param thread: True or False depicting if we want to
      :param request_nb: requests number to test per set.
      :param set_nb: number of sets to test
      :param server_ip: Ip of the server to which we want to connect remotly
      :param remote_user: username of remote server
      :param server_password: password of remote server
      :return:
      '''

    payload_params = {
        'tcp+tls': [
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_tcptls_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_tcp_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },

        ],
        'tcp': [
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_tcp_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_tcp_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },

        ],

        'http': [
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_http_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_http_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },

        ],
        'https': [
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_https_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_http_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },

        ],

    }

    #define connectivity conf fo client and server
    data_dir = pkg_resources.resource_filename(__name__, '../data/')

    conf = { 'type': "tcp",
                'ip_address': server_ip,
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'remote_user':remote_user,
                'password': server_password,
                'path_to_erilurk':"Desktop/HyameServer/projects/erilurk"
             }

    connectivity_conf = {}
    for type in ['tcp', 'tcp+tls', 'http', 'https']:
        connectivity_conf[type] = deepcopy(conf)
        connectivity_conf[type]['type'] = type

    graph_params = {'title': '',
                    'xlabel': 'Transport Protocol',
                    'ylabel': 'Latency (sec)',
                    'box_width': 0.5,  # width of each box in the graph
                    'start_position': 1,  # the position of the first box to draw
                    'show_grid': True,  # show grid in the graph
                    'legend': {
                        'location': 'lower right',
                        # location of the legend. Can take one of the following values:'best','upper right','upper left','lower left','lower right','right','center left','center right','lower center','upper center','center'
                        'font_properties': {
                            # 'fontname':'Calibri',
                            'size': '12',
                            # 'weight': 'bold',
                        }
                    },
                    'font_properties': {  # font properties of title, ylabel and xlabel
                        # 'fontname':'Calibri',
                        'size': '14',
                        'weight': 'bold',
                    },
                    'ticks_font_properties': {
                        # 'fontname':'Calibri',
                        'size': '12',
                        # 'weight': 'bold',
                    },
                    # data to plot grouped into multiple group. if no group is desired, a dictionary for each data to plot should be added
                    'groups': [
                        {'tick_label': 'TCP+TLS',  # label on xaxis depicting all the data in data
                         'color': ['white'],#['blue'],   # color of the box of each data in data, set 'White if no color is desired
                         'hatch': ['*'],   # pattern of each box in data. Set '' if no hatch is desired. It can take one of the following patterns = ('-', '+', 'x', '\\', '*', 'o', 'O', '.', '/')
                         'data': ['rsa_master_tcptls_prf_sha256_pfs_sha256'],
                         # colummn name of the data to plot as defined in excel sheet
                         'legends': []     # legend corresponding to each data, set None if no legend to be added to a specified data or provide an empty list
                         },
                        {'tick_label': 'HTTPS',
                         'color': ['white'],#['blue'],  # same color and hatch as previous group to have same legend
                         'hatch': ['*'],
                         'data': ['rsa_master_https_prf_sha256_pfs_sha256'],
                         'legends': [],  # empty list to have one legend per color as specified in previous group
                         },

                    ]}

    latency_test(payload_params, connectivity_conf, graph_params, sheet_name, graph_path, excel_file=excel_file,
                 thread=thread, request_nb_list=[request_nb], set_nb=set_nb, remote_connection = True)

def  multithreading_test( sheet_name, excel_file, graph_path, request_nb_list, set_nb, server_ip,remote_user, server_password, thread=True):
    '''
      This method performs a multithreading tests using different transport protocol (udplocal(reference), udp, tcp, http) between a client and a server
      :param sheet_name: the excel sheet name to store the results
      :param excel_file: path to the excel file that will contain the results. The file is created if it does not exists
      :param graph_path: path to the graphs depicting the results (e.g. results/ (do not start the path with "/")
      :param thread: True or False depicting if we want to
      :param request_nb_list: list of requests number to test per set.
      :param set_nb: number of sets to test
      :param server_ip: Ip of the server to which we want to connect remotly
      :param remote_user: username of remote server
      :param server_password: password of remote server
      :return:
      '''

    # define connectivity conf fo client and server
    data_dir = pkg_resources.resource_filename(__name__, '../data/')

    conf = { 'type': "tcp",
                'ip_address': server_ip,
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'remote_user':remote_user,
                'password': server_password,
                'path_to_erilurk':"Desktop/HyameServer/projects/erilurk"
             }

    connectivity_conf = {
        #ensure local connection for udlLocal (do not set remote_user
        'udpLocal':{
                'ip_address': '127.0.0.1',
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt'),
        }
    }
    for type in [ 'udp','tcp', 'http']:
        connectivity_conf[type] = deepcopy(conf)
        connectivity_conf[type]['type'] = type


    graph_params = {'title': '',
                    'xlabel': 'Number of requests',
                    'ylabel': 'Latency (sec)',
                    'box_width': 0.5,  # width of each box in the graph
                    'start_position': 1,  # the position of the first box to draw
                    'show_grid': True,  # show grid in the graph
                    'legend': {
                        'location': 'upper right',
                        # location of the legend. Can take one of the following values:'best','upper right','upper left','lower left','lower right','right','center left','center right','lower center','upper center','center'
                        'font_properties': {
                            # 'fontname':'Calibri',
                            'size': '12',
                            # 'weight': 'bold',
                        }
                    },
                    'font_properties': {  # font properties of title, ylabel and xlabel
                        # 'fontname':'Calibri',
                        'size': '14',
                        'weight': 'bold',
                    },
                    'ticks_font_properties': {
                        # 'fontname':'Calibri',
                        'size': '12',
                        # 'weight': 'bold',
                    },
                    # data to plot grouped into multiple group. if no group is desired, a dictionary for each data to plot should be added
                    'groups': [

                    ]
    }

    payload_params = {
            'udpLocal': [],
            'udp': [],
            'tcp': [],
            'http': [],

        }

    count=0
    for request_nb in request_nb_list:
        # start by setting payload parameters
        udplocal_param = {
                             'type': 'rsa_master',
                             'column_name': 'udpLocal_ref_' + str(request_nb) + '_request',
                             'ref': 'udpLocal_ref_' + str(request_nb_list[0]) + '_request',
                             'prf_hash': 'sha256',
                             'freshness_funct': 'sha256',
                         }
        udp_param = {
                        'type': 'rsa_master',
                        'column_name': 'udp_ref_' + str(request_nb) + '_request',
                        'ref': 'udp_ref_' + str(request_nb_list[0]) + '_request',
                        'prf_hash': 'sha256',
                        'freshness_funct': 'sha256',
                    }
        tcp_param = {
                        'type': 'rsa_master',
                        'column_name': 'tcp_ref_' + str(request_nb) + '_request',
                        'ref': 'tcp_ref_' + str(request_nb_list[0]) + '_request',
                        'prf_hash': 'sha256',
                        'freshness_funct': 'sha256',
                    }
        http_param = {
                         'type': 'rsa_master',
                         'column_name': 'http_ref_' + str(request_nb) + '_request',
                         'ref': 'http_ref_' + str(request_nb_list[0]) + '_request',
                         'prf_hash': 'sha256',
                         'freshness_funct': 'sha256',
                     }

        payload_params['udpLocal'].append(udplocal_param)
        payload_params['udp'].append(udp_param)
        payload_params['tcp'].append(tcp_param)
        payload_params['http'].append(http_param)


        # skip reference (do not plot reference)
        if request_nb == request_nb_list[0]:
            continue
        elif count ==1:#add the legends once
            group = {'tick_label': request_nb,
                     'color': ['white','white','white','white' ],#['blue', 'green', 'orange', 'cyan'],
                     'hatch': ['*','/', 'o',  'x'],
                     'data': ['udpLocal_ref_' + str(request_nb) + '_request', 'udp_ref_' + str(request_nb) + '_request',
                              'tcp_ref_' + str(request_nb) + '_request', 'http_ref_' + str(request_nb) + '_request'],
                     'legends': ['Local', 'UDP', 'TCP', 'HTTP']
                     }
        else:
            group = {'tick_label': request_nb,
                    'color': ['white', 'white', 'white', 'white'],  # ['blue', 'green', 'orange', 'cyan'],
                    'hatch': ['*', '/', 'o', 'x'],
                    'data': ['udpLocal_ref_' + str(request_nb) + '_request', 'udp_ref_' + str(request_nb) + '_request',
                             'tcp_ref_' + str(request_nb) + '_request', 'http_ref_' + str(request_nb) + '_request'],
                    'legends': []
                    }
        # add groups to display in the graph
        graph_params['groups'].append(group)
        count+=1

    latency_test(payload_params, connectivity_conf, graph_params, sheet_name, graph_path, excel_file=excel_file,
                  thread=thread, request_nb_list=request_nb_list, set_nb=set_nb, remote_connection=True)

def  cpu_overhead_protocols_test( file_path, total_requests_persec, requests_per_client, iterations, wait_time, server_ip,remote_user, server_password, cpuNb, thread=False):
    '''
    This method will check the cpu overhead on the client and server side with TOp command for all transport protocols and authentication methods.
    The top results are put in a file based on the pauload_params[column_name] _server or _client based on the client or server test results
    the results should be averaged over total_requests_persec on iterations (as nb of sets). First 2 iterations should be disgarded
    :param file_path: path to place te file with the top results
    :param total_requests_persec:total requests to be sent per sec by all the clients
    :param requests_per_client: number of requests that a client should send per second. This includes the resolve time+waiting time to reach 1 sec
    :param total_time: total time of each test in payload_params. After this time the client and server processes are killed
    :param iterations: number of iterations that the top command should performs
    :param wait_time: time to wait between top command iterations
    :param server_ip: Ip of the server to which we want to connect remotley
    :param remote_user: username of remote server
    :param server_password: password of remote server
    :param cpuNb: nb of cpu to average over for one iteration of the top
    :param thread: true if multi threading should be used
    :return:
    '''

    # define connectivity conf fo client and server
    data_dir = pkg_resources.resource_filename(__name__, '../data/')

    conf = { 'type': "tcp",
                'ip_address': server_ip,
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'remote_user':remote_user,
                'password': server_password,
                'path_to_erilurk':"Desktop/HyameServer/projects/erilurk"
             }

    connectivity_conf = {  #ensure local connection for udlLocal (do not set remote_user
        'udpLocal':{
                'ip_address': '127.0.0.1',
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt'),
        }
    }
    for type in [ 'udplocal','udp_freshnull','udp_fresh256','tcp', 'http', 'https', 'tcp+tls']:
        connectivity_conf[type] = deepcopy(conf)
        if type in ['udp_freshnull','udp_fresh256','udpLocal']:
            connectivity_conf[type]['type'] = 'udp'
        else:
            connectivity_conf[type]['type'] = type


    payload_params = {
        'udpLocal':[
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'rsa_extended_master',
                'column_name': 'rsa_extended_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'ref': 'rsa_extended_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_udpLocal_ref_sig_sha256rsa_pfs_sha256',
                'ref': 'ecdhe_udpLocal_ref_sig_sha256rsa_pfs_sha256',
                'sig_and_hash': ('sha256', 'rsa'),
                'freshness_funct': 'sha256'
            },

        ],
        'udp_fresh256': [
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_udp_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'rsa_extended_master',
                'column_name': 'rsa_extended_master_udp_prf_sha256_pfs_sha256',
                'ref': 'rsa_extended_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_udp_sig_sha256rsa_pfs_sha256',
                'ref': 'ecdhe_udpLocal_ref_sig_sha256rsa_pfs_sha256',
                'sig_and_hash': ('sha256', 'rsa'),
                'freshness_funct': 'sha256'
            },

        ],
        'udp_freshnull': [
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_udp_prf_sha256_pfs_null',
                'ref': 'rsa_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'null',
            },
            {
                'type': 'rsa_extended_master',
                'column_name': 'rsa_extended_master_udp_prf_sha256_pfs_null',
                'ref': 'rsa_extended_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'null',
            },
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_udp_sig_sha256rsa_pfs_null',
                'ref': 'ecdhe_udpLocal_ref_sig_sha256rsa_pfs_sha256',
                'sig_and_hash': ('sha256', 'rsa'),
                'freshness_funct': 'null'
            },

        ],
        'tcp': [
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_tcp_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'rsa_extended_master',
                'column_name': 'rsa_extended_master_tcp_prf_sha256_pfs_sha256',
                'ref': 'rsa_extended_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_tcp_sig_sha256rsa_pfs_sha256',
                'ref': 'ecdhe_udpLocal_ref_sig_sha256rsa_pfs_sha256',
                'sig_and_hash': ('sha256', 'rsa'),
                'freshness_funct': 'sha256'
            },

        ],
        'http': [
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_http_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'rsa_extended_master',
                'column_name': 'rsa_extended_master_http_prf_sha256_pfs_sha256',
                'ref': 'rsa_extended_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_http_sig_sha256rsa_pfs_sha256',
                'ref': 'ecdhe_udpLocal_ref_sig_sha256rsa_pfs_sha256',
                'sig_and_hash': ('sha256', 'rsa'),
                'freshness_funct': 'sha256'
            },

        ],
        'https': [
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_https_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'rsa_extended_master',
                'column_name': 'rsa_extended_master_https_prf_sha256_pfs_sha256',
                'ref': 'rsa_extended_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_https_sig_sha256rsa_pfs_sha256',
                'ref': 'ecdhe_udpLocal_ref_sig_sha256rsa_pfs_sha256',
                'sig_and_hash': ('sha256', 'rsa'),
                'freshness_funct': 'sha256'
            },

        ],
        'tcp+tls': [
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_tcptls_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'rsa_extended_master',
                'column_name': 'rsa_extended_master_tcptls_prf_sha256_pfs_sha256',
                'ref': 'rsa_extended_master_udpLocal_ref_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },
            {
                'type': 'ecdhe',
                'column_name': 'ecdhe_tcptls_sig_sha256rsa_pfs_sha256',
                'ref': 'ecdhe_udpLocal_ref_sig_sha256rsa_pfs_sha256',
                'sig_and_hash': ('sha256', 'rsa'),
                'freshness_funct': 'sha256'
            },

        ],

    }

    graph_params = {'title': '',
                    'xlabel': 'Athentication Methods',
                    'ylabel': 'Cpu Overhead (%)',
                    'box_width': 0.5,  # width of each box in the graph
                    'start_position': 1,  # the position of the first box to draw
                    'show_grid': True,  # show grid in the graph
                    'legend': {
                        'location': 'upper right',
                        # location of the legend. Can take one of the following values:'best','upper right','upper left','lower left','lower right','right','center left','center right','lower center','upper center','center'
                        'font_properties': {
                            # 'fontname':'Calibri',
                            'size': '12',
                            # 'weight': 'bold',
                        }
                    },
                    'font_properties': {  # font properties of title, ylabel and xlabel
                        # 'fontname':'Calibri',
                        'size': '14',
                        'weight': 'bold',
                    },
                    'ticks_font_properties': {
                        # 'fontname':'Calibri',
                        'size': '12',
                        # 'weight': 'bold',
                    },
                    # data to plot grouped into multiple group. if no group is desired, a dictionary for each data to plot should be added
                    'groups': [
                        {'tick_label': 'RSA',  # label on xaxis depicting all the data in data
                         'color': ['white', 'white', 'white','white', 'white', 'white'],  # ['blue', 'green', 'orange'],
                         # color of the box of each data in data, set 'White if no color is desired
                         'hatch': ['*', '/', 'o', '-','x','/'],
                         # pattern of each box in data. Set '' if no hatch is desired. It can take one of the following patterns = ('-', '+', 'x', '\\', '*', 'o', 'O', '.', '/')
                         'data': ['rsa_master_udpLocal_ref_prf_sha256_pfs_sha256','rsa_master_udp_prf_sha256_pfs_sha256','rsa_master_tcp_prf_sha256_pfs_sha256','rsa_master_tcptls_prf_sha256_pfs_sha256',
                                  'rsa_master_http_prf_sha256_pfs_sha256', 'rsa_master_https_prf_sha256_pfs_sha256'],
                         # colummn name of the data to plot as defined in excel sheet
                         'legends': ['UDP_Local','UDP', 'TCP','TCP+TLS', 'HTTP', 'HTTPS']
                         # legend corresponding to each data, set None if no legend to be added to a specified data or provide an empty list
                         },
                        {'tick_label': 'RSA_Extended',
                         'color': ['white', 'white', 'white','white', 'white', 'white'],
                         # ['blue', 'green', 'orange'],  # same color and hatch as previous group to have same legend
                         'hatch': ['*', '/', 'o', '-','x','/'],
                         'data': ['rsa_extended_master_udpLocal_ref_prf_sha256_pfs_sha256','rsa_extended_master_udp_prf_sha256_pfs_sha256','rsa_extended_master_tcp_prf_sha256_pfs_sha256','rsa_extended_master_tcptls_prf_sha256_pfs_sha256',
                                  'rsa_extended_master_http_prf_sha256_pfs_sha256', 'rsa_extended_master_https_prf_sha256_pfs_sha256'],
                         'legends': [],  # empty list to have one legend per color as specified in previous group
                         },
                        {'tick_label': 'ECDHE',
                         'color': ['white', 'white', 'white','white', 'white', 'white'],  # ['blue', 'green', 'orange'],
                         'hatch': ['*', '/', 'o', '-','x','/'],
                         'data': ['ecdhe_udpLocal_ref_sig_sha256rsa_pfs_sha256','ecdhe_udp_sig_sha256rsa_pfs_sha256','ecdhe_tcp_sig_sha256rsa_pfs_sha256','ecdhe_tcptls_sig_sha256rsa_pfs_sha256','ecdhe_http_sig_sha256rsa_pfs_sha256','ecdhe_https_sig_sha256rsa_pfs_sha256'],
                         'legends': [],
                         },

                    ]}


    cpu_overhead_test(payload_params, connectivity_conf, graph_params, file_path, total_requests_persec, requests_per_client,
             iterations, wait_time, cpuNb, thread=thread, remote_connection=True)

if __name__=="__main__":

     thread = False
     request_nb =1
     set_nb = 50
     results_dir =  'results/'
     graph_dir =  results_dir+'graphs/'
     server_ip ='192.168.0.108'#.108

     remote_user='xubuntu_server'
     password = 'xubuntu6789'


     print("--------------------Starting Security Overhead Test----------------------------")
     security_overhead_test('security', results_dir + 'security_overhead.xlsx', graph_dir, thread, request_nb, set_nb, server_ip, remote_user, password)

     print("--------------------Starting Transport Protocol Test----------------------------")
     transport_protocol_test('transport', results_dir+'transport_protocol.xlsx', graph_dir, thread, request_nb, set_nb,server_ip, remote_user, password)



     thread = True
     request_nb_list = [1, 100, 200, 400, 600, 800, 1000]
     print("--------------------Starting Multithreading Test----------------------------")
     multithreading_test('multithread',  results_dir+'multithreading.xlsx', graph_dir, request_nb_list, set_nb, server_ip, remote_user, password,  thread=thread)

     thread =False
     print("--------------------Starting Authentication Methods Test----------------------------")
     authentication_methods_test('authentication', results_dir + 'authentication_methods.xlsx', graph_dir, thread, request_nb, set_nb)
     print("--------------------Starting Mechanism Overhead pfs Test----------------------------")
     mechanism_overhead_pfs_test('pfs', results_dir + 'mechanism_overhead_pfs.xlsx', graph_dir, thread, request_nb, set_nb)
     print("--------------------Starting Mechanism Overhead poh Test----------------------------")
     mechanism_overhead_poh_test('poh', results_dir + 'mechanism_overhead_poh.xlsx', graph_dir, thread, request_nb, set_nb)

     print("--------------------Starting Mechanism Overhead poo Test----------------------------")
     mechanism_overhead_poo_test('poo', results_dir + 'mechanism_overhead_poo.xlsx', graph_dir, thread, request_nb, set_nb)

     total_requests_persec = 100
     requests_per_client = 1
     iterations = 50
     wait_time = 5#wait 5 sec after each iteration
     cpuNb=8
     thread = True
     cpu_overhead_protocols_test(results_dir, total_requests_persec, requests_per_client, iterations, wait_time,
                             server_ip, remote_user, password, cpuNb, thread=thread)
