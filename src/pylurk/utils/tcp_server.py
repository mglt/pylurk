from pylurk.utils.utils import *

connectivity_conf = {'type': 'udp' }
background=False
thread=False
server = set_lurk('server', connectivity_conf=connectivity_conf, background=background, thread=thread )
if background == True:
    server.join()
