import copy
from pylurk.extensions.tls12_struct import *
from pylurk.extensions.tls12 import *
from pylurk.core.conf import default_conf
from pylurk.core.lurk import LurkMessage


req = Tls12EcdheRequestPayload()
resp = Tls12EcdheResponsePayload()
for freshness_funct in ["null", "sha256"]:
    for ecdhe_curve in ['secp256r1', 'secp384r1', 'secp521r1' ]:
        print("--- %s"%ecdhe_curve)
        ecdhe_private = Tls12EcdheConf().default_ecdhe_private(\
                                    ecdhe_curve=ecdhe_curve)
        for h, sig in [('sha256', 'rsa'), ('sha512', 'rsa'),\
                             ('sha256', 'ecdsa'), ('sha512', 'ecdsa')]:
            sig_and_hash = {'sig':sig, 'hash':h}
            for poo_prf in [ "null", "sha256_128", "sha256_256" ]:
                payload = {'freshness_funct':freshness_funct, \
                           'ecdhe_private':ecdhe_private,\
                           'poo_prf':poo_prf,\
                           'sig_and_hash':sig_and_hash}
                req_payload = req.build_payload(**payload)
                req.show(req_payload)
                res_payload = resp.serve(req_payload)
                resp.show(res_payload)
