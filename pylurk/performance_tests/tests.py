from  os.path import join
import pkg_resources
from pylurk.performance_tests.performance_utils import latency_test


def authentication_methods_test (sheet_name, excel_file, graph_path, thread, request_nb, set_nb):
    '''
    This method performs some latency tests on authentication methods (RSA, RSA_extended and ECDHE) by varying the prf (256 (reference), 384, 512),
    ECDHE: 'sig_and_hash': ('sha256', 'rsa'),'sig_and_hash': ('sha512', 'rsa').
    It saves the results in the specified excel file and plot them in 2 box graphs (one for latency values and another for ratios)
    :param sheet_name: the excel sheet name to store the results
    :param excel_file: path to the excel file that will contain the results. The file is created if it does not exists
    :param graph_path: path to the graphs depicting the results (e.g. results/ (do not start the path with "/")
    :param thread: True or False depicting if we want to
    :param request_nb_list: requests number to test per set.
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
        'server_conf':{
            'udpLocal':{
                'type': "udp",  # "udp", "local",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            }
        },
        'client_conf': {
            'udpLocal': {  # run upd for client and server locally
                'type': "udp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_server.crt'),
            },
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
        'server_conf': {
            'udpLocal': {
                'type': "udp",  # "udp", "local",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            }
        },
        'client_conf': {
            'udpLocal': {  # run upd for client and server locally
                'type': "udp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_server.crt'),
            },
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
        'server_conf': {
            'udpLocal': {
                'type': "udp",  # "udp", "local",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            }
        },
        'client_conf': {
            'udpLocal': {  # run upd for client and server locally
                'type': "udp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_server.crt'),
            },
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
                         'legends': ['Without PoH', 'With PoH']
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

def mechanism_overhead_poo_test (sheet_name, excel_file, graph_path, thread, request_nb_list, set_nb):
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
        'server_conf': {
            'udpLocal': {
                'type': "udp",  # "udp", "local",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            }
        },
        'client_conf': {
            'udpLocal': {  # run upd for client and server locally
                'type': "udp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_server.crt'),
            },
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
                         'legends': [] # legend corresponding to each data, set None if no legend to be added to a specified data or provide an empty list
                         },
                        {'tick_label': 'sha256_256',
                         'color': ['white'],#['blue' ],
                         'hatch': ['*'],
                         'data': ['ecdhe_poo_sha256_256_sig_sha256rsa_pfs_sha256'],
                         'legends': [],
                         },


                    ]}

    latency_test(payload_params, connectivity_conf, graph_params, sheet_name, graph_path, excel_file=excel_file,
                 thread=thread, request_nb_list=[request_nb], set_nb=set_nb)

def transport_protocol_test( sheet_name, excel_file, graph_path, thread, request_nb, set_nb):
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
    # @TODO change IP address and port, keys and cert
    connectivity_conf= {
        'server_conf': {
            'udpLocal':{#run upd for client and server locally
                'type': "udp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            },
            'udp':{
                'type': "udp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            },
            'tcp':{
                'type': "tcp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            },
            'http':{
                'type': "http",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            },

        },
        'client_conf':{
            'udpLocal': {#run upd for client and server locally
                'type': "udp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_server.crt'),
            },
            'udp': {
                'type': "udp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_server.crt'),
            },
            'tcp': {
                'type': "tcp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_server.crt'),
            },
            'http': {
                'type': "http",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_server.crt'),

            },

        }

    }

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
                        {'tick_label': 'RSA',  # label on xaxis depicting all the data in data
                         'color': ['white','white','white'],#['blue', 'green', 'orange'],
                         # color of the box of each data in data, set 'White if no color is desired
                         'hatch': [ '*','/', 'o'], # pattern of each box in data. Set '' if no hatch is desired. It can take one of the following patterns = ('-', '+', 'x', '\\', '*', 'o', 'O', '.', '/')
                         'data': ['rsa_master_udp_ref_prf_sha256_pfs_sha256', 'rsa_master_tcp_ref_prf_sha256_pfs_sha256', 'rsa_master_http_ref_prf_sha256_pfs_sha256'],
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
                 thread=thread, request_nb_list=[request_nb], set_nb=set_nb)


def security_overhead_test( sheet_name, excel_file, graph_path, thread, request_nb, set_nb):
    payload_params = {
        'tcp': [
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_tcp_prf_sha256_pfs_sha256',
                'ref': 'rsa_master_tcp_prf_sha256_pfs_sha256',
                'prf_hash': 'sha256',
                'freshness_funct': 'sha256',
            },

        ],
        'tcp+tls': [
            {
                'type': 'rsa_master',
                'column_name': 'rsa_master_tcptls_prf_sha256_pfs_sha256',
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
    # @TODO change IP address and port, keys and cert
    connectivity_conf= {
        'server_conf': {

            'tcp':{
                'type': "tcp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            },
            'tcp+tls': {
                'type': "tcp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            },
            'http':{
                'type': "http",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            },
            'https':{
                'type': "http",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            },

        },
        'client_conf':{

            'tcp': {
                'type': "tcp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_server.crt'),
            },
            'tcp+tls': {
                'type': "tcp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_server.crt'),
            },
            'http': {
                'type': "http",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_server.crt'),

            },
            'https': {
                'type': "http",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_server.crt'),

            },

        }

    }

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
                 thread=thread, request_nb_list=[request_nb], set_nb=set_nb)

def  multithreading_test( sheet_name, excel_file, graph_path, thread, request_nb_list, set_nb):
    # define connectivity conf fo client and server
    data_dir = pkg_resources.resource_filename(__name__, '../data/')
    # @TODO change IP address and port, keys and cert
    connectivity_conf = {
        'server_conf': {
            'udpLocal': {  # run upd for client and server locally
                'type': "udp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            },
            'udp': {
                'type': "udp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            },
            'tcp': {
                'type': "tcp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            },
            'http': {
                'type': "http",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_server.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_client.crt')
            },

        },
        'client_conf': {
            'udpLocal': {  # run upd for client and server locally
                'type': "udp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_server.crt'),
            },
            'udp': {
                'type': "udp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_server.crt'),
            },
            'tcp': {
                'type': "tcp",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_server.crt'),
            },
            'http': {
                'type': "http",
                'ip_address': "127.0.0.1",
                'port': 6789,
                'key': join(data_dir, 'key_tls12_rsa_client.key'),
                'cert': join(data_dir, 'cert_tls12_rsa_client.crt'),
                'key_peer': join(data_dir, 'key_tls12_rsa_server.key'),
                'cert_peer': join(data_dir, 'cert_tls12_rsa_server.crt'),

            },

        }

    }

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

                    ]
    }

    payload_params = {
            'udpLocal': [],
            'udp': [],
            'tcp': [],
            'http': [],

        }
    for request_nb in request_nb_list:
        # start by setting payload parameters
        udplocal_param = {
                             'type': 'rsa_master',
                             'column_name': 'udpLocal_ref_' + request_nb + '_request',
                             'ref': 'udpLocal_ref_' + request_nb_list[0] + '_request',
                             'prf_hash': 'sha256',
                             'freshness_funct': 'sha256',
                         }
        udp_param = {
                        'type': 'rsa_master',
                        'column_name': 'udp_ref' + request_nb + '_request',
                        'ref': 'udp_ref_' + request_nb_list[0] + '_request',
                        'prf_hash': 'sha256',
                        'freshness_funct': 'sha256',
                    }
        tcp_param = {
                        'type': 'rsa_master',
                        'column_name': 'tcp_ref' + request_nb + '_request',
                        'ref': 'tcp_ref_' + request_nb_list[0] + '_request',
                        'prf_hash': 'sha256',
                        'freshness_funct': 'sha256',
                    }
        http_param = {
                         'type': 'rsa_master',
                         'column_name': 'http_ref' + request_nb + '_request',
                         'ref': 'http_ref_' + request_nb_list[0] + '_request',
                         'prf_hash': 'sha256',
                         'freshness_funct': 'sha256',
                     },

        payload_params[ 'udpLocal'].append (udplocal_param)
        payload_params['udp'].append(udp_param)
        payload_params['tcp'].append(tcp_param)
        payload_params['http'].append(http_param)

        # skip reference (do not plot reference
        if request_nb != request_nb_list[0]:
            group = {'tick_label': request_nb,
                     'color': ['white','white','white','white' ],#['blue', 'green', 'orange', 'cyan'],
                     'hatch': ['*','/', 'o',  'x'],
                     'data': ['udpLocal_ref_' + request_nb + '_request', 'udp_ref' + request_nb + '_request',
                              'tcp_ref' + request_nb + '_request', 'http_ref' + request_nb + '_request'],
                     'legends': ['Local', 'UDP', 'TCP', 'HTTP']
                     }
            # add groups to display in the graph
            graph_params['groups'].append(group)



    latency_test(payload_params, connectivity_conf, graph_params, sheet_name, graph_path, excel_file=excel_file,
                    thread=thread, request_nb_list=request_nb_list, set_nb=set_nb)



if __name__=="__main__":

    thread = False
    request_nb =1
    set_nb = 2
    results_dir =  'results/'
    graph_dir =  results_dir+'graphs/'

    print ("--------------------Starting Authentication Methods Test----------------------------")
    authentication_methods_test('authentication', results_dir+'authentication_methods.xlsx', graph_dir, thread, request_nb, set_nb)
    print("--------------------Starting Mechanism Overhead pfs Test----------------------------")
    mechanism_overhead_pfs_test('pfs', results_dir+'mechanism_overhead_pfs.xlsx', graph_dir, thread, request_nb, set_nb)
    print("--------------------Starting Mechanism Overhead poh Test----------------------------")
    mechanism_overhead_poh_test('poh', results_dir+'mechanism_overhead_poh.xlsx', graph_dir, thread, request_nb, set_nb)

    #print("--------------------Starting Mechanism Overhead poo Test----------------------------")
    #mechanism_overhead_poo_test('poo', results_dir+'mechanism_overhead_poo.xlsx', graph_dir, thread, request_nb, set_nb)

    print("--------------------Starting Security Overhead Test----------------------------")
    security_overhead_test('security', results_dir + 'security_overhead.xlsx', graph_dir, thread, request_nb, set_nb)

    #print("--------------------Starting Transport Protocol Test----------------------------")
    transport_protocol_test('transport', results_dir+'transport_protocol.xlsx', graph_dir, thread, request_nb, set_nb)



    thread = True
    request_nb_list = [1, 10, 25, 50, 100, 200]
    print("--------------------Starting Multithreading Test----------------------------")
    multithreading_test('multithread',  results_dir+'multithreading.xlsx', graph_dir, True, request_nb_list, set_nb)
