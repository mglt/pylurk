from pylurk.extensions.tls12_struct import *
from pylurk.extensions.tls12 import *

payload = {'key_id': {'key_id_type': 'sha256_32', 'key_id': b"\n\x1b\x87'"}, 'freshness_funct': 'null', 'client_random': {'gmt_unix_time': b'\\/\xe5\x1a', 'random': b'0\x96\xc8\xb3\xadN\xa7*\xbe\xc7N\x0bH)\x04\x13\xaa\xdf4\x91\x0e\x90\xbc\x04\xa5H\xf2\\'}, 'server_random': {'gmt_unix_time': b'\\/\xe5\x1a', 'random': b'\xe6a\xc3\xc3?\x15o\xf7l\xba\x04\xa9\xeb\x03c\x8f\x04a6\xcdq\x8d\x04/~\xb1Z\xe7'}, 'sig_and_hash': {'hash': 'sha256', 'sig': 'ecdsa'}, 'ecdhe_params': {'curve_param': {'curve_type': 'name_curve', 'curve': 'secp256r1'}, 'public': {'form': 'uncompressed', 'x': 36723273566952187803275118896161248799423864592296852996168670094528927185347, 'y': 29968413964867759190405146056347286596222840008010459239617388244337516743184}}, 'poo_params': {'poo_prf': 'sha256_128', 'rG': {'form': 'uncompressed', 'x': 98854112370068053706288889270134256023019533519376315927845593818129096590180, 'y': 46765888137385651983729474077771284630378438133270987305962471774788153849933}, 'tG': {'form': 'uncompressed', 'x': 8144205719720434763021139242778021250459747861381428245077571144706888860749, 'y': 78178473692982855643659893184148649128845329385390063876774369581175587019682}}}

TLS12ECDHERequestPayload.build(payload)

srv = Tls12EcdheResponsePayload()
srv.serve(payload)
