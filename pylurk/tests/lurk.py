from time import sleep
from pylurk.utils.utils import lurk_serve_payloads, bytes_error_testing,\
                               lurk_client_server_exchange, set_title
from pylurk.core.lurk import LurkServer, LurkMessage\

print(set_title("TESTING LURK PAYLOAD"))
lurk_serve_payloads(silent=False)

print(set_title("TESTING ERROR PAYLOADS"))
server = LurkServer()
query_ref_bytes = LurkMessage().build( designation='lurk', version='v1',\
                   status="request")
lurk_header_error = [\
    ("Invalid Designation", 0, 0,   "invalid_extension" ), \
    ("Invalid Version",     1, 1,   "invalid_extension" ), \
    ("Invalid Type",        2, 2,   "invalid_type" ), \
    ("Invalid Status",      3, 3,   "invalid_status" ), \
    ("Invalid Length",      12, 15, "invalid_format" )\
]

bytes_error_testing( server, query_ref_bytes, lurk_header_error)


## TESTING CLIENT/SERVER LURK "

for connection_type in ['udp', 'tcp', 'tcp+tls', 'http', 'https']:
    for thread_mode in [True, False]:
        lurk_client_server_exchange(connection_type, \
            background=True, \
            thread=thread_mode)
        sleep(1)

