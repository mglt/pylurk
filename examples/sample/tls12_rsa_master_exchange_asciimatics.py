from __future__ import division
from builtins import range
import copy
import math
from asciimatics.effects import Cycle, Print, Stars
from asciimatics.renderers import SpeechBubble, FigletText, Box, StaticRenderer
from asciimatics.scene import Scene
from asciimatics.screen import Screen
from asciimatics.sprites import Arrow, Plot, Sam
from asciimatics.paths import Path
from asciimatics.exceptions import ResizeScreenError
import sys


END_OF_DEMO=1000000
TIC_SPEAK = 100
TIC_MESSAGE = 100
STEP_NBR = 10 #do not put too large numbers.

def _speak(screen, text, pos, start):
    return Print(
        screen,
        SpeechBubble(text, "L", uni=screen.unicode_aware),
        x=pos[0] + 4, y=pos[1] - 4,
        colour=Screen.COLOUR_CYAN,
        clear=True,
        start_frame=start,
        stop_frame=start + TIC_SPEAK)

def s2r( string ):
    """ Return a rendered associated to the string

    Args:
        string : the string to be rendreed

    Returns: 
        rendered: The associated Rendered object 
    """
    return StaticRenderer( images=[r""" %s """%string ] )


def _background_display( screen, start=0, stop=END_OF_DEMO,\
                         labels=[ "Title1", "Title2"], \
                         colors=[ Screen.COLOUR_RED, Screen.COLOUR_GREEN], \
                         y=8, mode="header"):
    """ Displays the back ground
   
    Args:
        screen: the screen the background is displayed to
        domain_nbr: the number of domain. By default set to 3 for 
            Untrusted, Exposed and Trusted. Can be set to 2 for 
            Untrusted Trusted as well. 
        mode: defines how the display occurs. By default it is set 
            to "running", but it can also be set to "intro" to be 
            displayed slower
       start: starting time
    """
    width = int( screen.width / len(labels) )
    width_str = s2r( str.ljust( "", width )  )

    labels_str = []
    for l in labels:
        ll = l[: int( len(l) / 2 ) ]
        rl = l[ int( len(l) / 2 ) :]
        labels_str.append( s2r( str.rjust( ll, int( width / 2 ) ) + \
                        str.ljust( rl, int( width / 2 ) ) ) )
    
    x_label = [ i * width for i in range( len(labels) ) ]

    effects = []
    ## prints left, right middle when possible
    for i in range( len(labels) ):
        if mode in [ "header" "header_plain" ]:
            kwargs = { "x" : x_label[ i ], "colour" : colors[ i ],\
                   "attr" : Screen.A_UNDERLINE, "bg" : 0, \
                   "clear" : True, "start_frame" : start, \
                   "stop_frame" : stop, 'transparent' : True }
            effects.append( Print( screen, labels_str[i], y, **kwargs  ) )   
        if mode in [ "header_plain" ]:
            kwargs = { "x" : x_label[ i ], "colour" : colors[ i ],\
                   "attr" : Screen.A_UNDERLINE, "bg" : Screen.COLOUR_BLACK, \
                   "clear" : True, "start_frame" : start, \
                   "stop_frame" : stop, 'transparent' : True }
            effects.append( Print( screen, labels_str[i], y, **kwargs  ) )   
            kwargs = { "x" : x_label[ i ], "colour" : colors[ i ],\
                       "attr" : Screen.A_NORMAL, "bg" : colors[ i ], \
                       "clear" : True, "start_frame" : start, \
                       "stop_frame" : stop, 'transparent' : False }
            for y_line  in range( screen.height - y ):
               effects.append( Print( screen, width_str,  y + 2 + y_line,\
               **kwargs ) )         
    return effects


def x_path( screen, string ):
    """ returns the dictionary { "path_name" : [] }

    Returns:
        path_dict
    """

    size = []
    s = 0
    for c in string:
        if c == '\n':
            size.append( s )
            s = 0
        else:
            s +=1
    size.append( s )
    string_size = max(size)    

    domain_len = screen.width / 3.0
    margin = 0.1 * domain_len  
#    path_len = domain_len - 2 * margin

    tls_clt = int( margin )
    tls_srv = int( domain_len + margin )
    lurk_clt = int( 2 * domain_len - margin )
    lurk_srv = int( screen.width - margin )

    path_name = [ "tls_clt", "tls_srv", "lurk_clt", "lurk_srv" ]
    # starts from o ends at d in STEP_NBR steps.
    
    frame_step = int( domain_len / STEP_NBR )

    path_x = {}
    path_x[ "tls_clt"] = []
    x = tls_clt
    while x + string_size < tls_srv:
        path_x[ "tls_clt"].append(x)
        x +=  frame_step 
    path_x[ "tls_clt"].append(tls_srv - string_size )

    path_x[ "lurk_clt"] = []
    x = lurk_clt
    while x + string_size < lurk_srv :
        path_x[ "lurk_clt"].append(x)
        x +=  frame_step 
    path_x[ "lurk_clt"].append(lurk_srv - string_size )
   
    path_x[ "tls_srv"] = []
    x = tls_srv - string_size
    while x > tls_clt:
        path_x[ "tls_srv"].append(x)
        x -=  frame_step 
    path_x[ "tls_srv"].append(tls_clt)
   
    path_x[ "lurk_srv"] = []
    x = lurk_srv - string_size
    while x > lurk_clt:
        path_x[ "lurk_srv"].append(x)
        x -=  frame_step 
    path_x[ "lurk_srv"].append(lurk_clt)
    
    return path_x 
   
    

def move_h(screen, string, y, path_name, start):
    """ Move horizontally Text/Image to the other end

    transition always last TIC_MESSAGE

    Args:
        screen: the screen
        string: the string to display
        y: strating y
        path_name: the name of the path
        start: start time
    """
    kwargs = { "colour" : Screen.COLOUR_WHITE, "attr" : Screen.A_BOLD, \
               "bg" : Screen.COLOUR_BLACK, "clear" : True, 'transparent' : True }
    args = [ screen, s2r(string), y ] 
    path = x_path( screen, string )
    step_frame = int( TIC_MESSAGE / STEP_NBR ) 

    effects = []
    for x in path[ path_name ][:-1] :
        effects.append( Print( *args,  **kwargs, x=x,   start_frame=start, \
            stop_frame=start + step_frame ) )
        start += step_frame
    effects.append( Print( *args,  **kwargs, x=path[ path_name ][-1] , \
         start_frame=start, stop_frame=start + END_OF_DEMO ) )
    return effects



def demo(screen):
    scenes = []
    centre = (screen.width // 2, screen.height // 2)
    podium = (8, 5)

    # Scene 1.
    path = Path()
    path.jump_to(-20, centre[1])
    path.move_straight_to(centre[0], centre[1], 10)
    path.wait(30)
    path.move_straight_to(podium[0], podium[1], 10)
    path.wait(100)

    effects = [
        Arrow(screen, path, colour=Screen.COLOUR_GREEN),
        _speak(screen, "Secure TLS Deployment with LURK  \n" +\
                       "-- Example: RSA Authentication --", centre, 30),
    ]
    scenes.append(Scene(effects))

    # Scene 2
    T = 0
    path = Path()
    path.jump_to(podium[0], podium[1])
    effects = [ Arrow(screen, path, colour=Screen.COLOUR_GREEN) ]
    Y = 8
     
    speak = "In practice the line between Untrusted and " +\
          "Trusted Domain does not exist..."
    labels = [ "Untrusted Domain", "Trusted Domain" ]
    colors = [ Screen.COLOUR_RED, Screen.COLOUR_GREEN ]
    effects += [ _speak(screen, speak, podium, T ) ]
    effects += _background_display( screen, start=T, stop=T + TIC_SPEAK, labels=labels,\
                  colors=colors, y=Y, mode="header_plain")
    T += TIC_SPEAK

    speak = "Instead there is a continuum with Untrusted, \n" +\
            "Exposed and Trusted Domain...                "
    labels = [ "Untrusted Domain", "Exposed Domain", "Trusted Domain" ]
    colors = [ Screen.COLOUR_RED, Screen.COLOUR_YELLOW, \
               Screen.COLOUR_GREEN ]
    effects += [ _speak(screen, speak, podium, T) ]
    effects += _background_display( screen, start=T, stop=T + 3 * TIC_SPEAK, labels=labels,\
                  colors=colors, y=Y, mode="header_plain")
    T += TIC_SPEAK

    speak = "For CDN:                                   \n"+\
            "    * Untrusted Domain == Internet,        \n" + \
            "    * Exposed Domain   == delegated CDN,   \n" +\
            "    * Trusted Domain   ==  Your CDN...     "
    effects += [ _speak(screen, speak, podium, T) ]
    T += TIC_SPEAK

    speak = "For vRAN:                                                 \n" +\
            "    * Untrusted Domain == Data Center,                    \n" +\
            "    * Exposed Domain   == vRAN Software,                  \n" +\
            "    * Trusted Domain   == Trusted Execution Environment..."
    effects += [ _speak(screen, speak, podium, T) ]
    T += TIC_SPEAK

    speak = "This can be extended to any case where TLS is used..."
    labels = [ "TLS Client", "TLS Server", "Key Server" ]
    effects += [ _speak(screen, speak, podium, T) ]
    effects += _background_display( screen, start=T, stop=END_OF_DEMO, labels=labels,\
                   colors=colors, y=Y, mode="header_plain")
    T += TIC_SPEAK
    Y += 2

    speak = "A TLS Client terminates the session to the Exposed Environment"
    msg = "ClientHello          \n" +\
          "   server_version    \n" +\
          "   client_random     \n" +\
          "   cipher_suite      \n" +\
          "       TLS_RSA_*, ...\n" +\
          "-------->"
    effects += move_h(screen, msg, Y, 'tls_clt', T)
    effects += [ _speak(screen, speak, podium, T ) ]

    speak = "The TLS Server chose RSA authentication proposed by the \n" +\
            "TLS Client                                              " 
    effects.append( _speak(screen, speak, podium, T + TIC_SPEAK ) )
    T += max(TIC_MESSAGE, 2 * TIC_SPEAK )
    Y += msg.count('\n') + 1  


    speak = "The TLS Server knows RSA Authentication involves    \n" +\
            "interactions with the Key Server and obfuscates the \n" +\
            "server_random to provide perfect forward secrecy.   "
    effects.append( _speak(screen, speak, podium, T ) )
    T += TIC_SPEAK   

    speak = "The TLS Server:                                           \n" +\
            "     - 1) Generates a server_random                       \n" +\
            "     - 2) Obfuscates the server_random                    \n" +\
            "     - 3) Sends the obfuscated value to the TLS Client    \n" +\
            "     - 4) Sends the non obfuscated value to the Key Server"
    effects.append( _speak(screen, speak, podium, T ) )

    txt=        "LURK server_random:            "
    txt_value = "    gmt_unix_time                \n" +\
                "     random                     "
    kwargs = { "colour" : Screen.COLOUR_YELLOW, "attr" : Screen.A_BOLD, \
               "bg" : Screen.COLOUR_BLACK, "clear" : True, 'transparent' : True,\
                'x' : int( 1.1 * int(screen.width / 3 ) ), 'start_frame' : T, \
                'stop_frame' : END_OF_DEMO}
    y = Y - 2 # moving up to two lines the text
    args = [ screen, s2r(txt), y ] 
    effects += [ Print( *args, **kwargs ) ]
    kwargs[ 'colour' ] = Screen.COLOUR_RED
    args = [ screen, s2r(txt_value), y + 1 ] 
    effects += [ Print( *args, **kwargs ) ]
    y += txt.count('\n') + 1 + txt_value.count('\n') 

    txt=       " Obfuscated TLS server_random: "
    txt_value= "    gmt_unix_time               \n" +\
               "     random                     "
    kwargs = { "colour" : Screen.COLOUR_YELLOW, "attr" : Screen.A_BOLD, \
               "bg" : Screen.COLOUR_BLACK, "clear" : True, 'transparent' : True,\
                'x' : int( 1.1 * int(screen.width / 3 ) ), 'start_frame' : T, \
                'stop_frame' : END_OF_DEMO}
    args = [ screen, s2r(txt), y ] 
    effects += [ Print( *args, **kwargs ) ]
    kwargs[ 'colour' ] = Screen.COLOUR_WHITE
    args = [ screen, s2r(txt_value), y + 1 ] 
    effects += [ Print( *args, **kwargs ) ]
    T += TIC_SPEAK   

    speak = "The TLS Server responds with a ServerHello \n" +\
            "That includes the obfuscated server_random "
    msg = "ServerHello               \n" +\
          "    tls_version           \n" +\
          "    server_random (TLS)   \n" +\
          "    Cipher_suite=TLS_RSA  \n" +\
          "Certificate               \n" +\
          "    RSA Public Key        \n" +\
          "ServerHelloDone           \n" +\
          "<--------                  "
    effects += move_h(screen, msg, Y, 'tls_srv', T)
    effects += [ _speak(screen, speak, podium, T ) ]
    T += max( TIC_MESSAGE, TIC_SPEAK )
    Y += msg.count('\n') + 1  
   
    speak = "The TLS Client sends a ClientKeyExchange \n" +\
            "with the encrypted premaster             " 
    msg = "ClientKeyExchange        \n" +\
          "    encrypted_premaster   \n" +\
          "-------->"
    effects += move_h(screen, msg, Y, 'tls_clt', T)
    effects += [ _speak(screen, speak, podium, T ) ]
    T += max( TIC_MESSAGE, TIC_SPEAK )
    Y += msg.count('\n') + 1  

    speak = "Upon receiving the ClientKeyExchange, the \n" +\
            "TLS Server initiates a LURK exchange with \n" +\
            "the Key Server to:                        \n" +\
            "    - 1) Decyrpte the encrypted_premaster \n" +\
            "    - 2) Generate the master_secret       "   
    msg = "RSAMasterRequest   \n" +\
          "    key_id             \n" +\
          "        key_id_type    \n" +\
          "        key_id         \n" +\
          "    freshness_funct    \n" +\
          "    client_random      \n" +\
          "        gmt_unix_time  \n" +\
          "        random =       \n" +\
          "    server_random      \n" +\
          "        gmt_unix_time  \n" +\
          "        random =       \n" +\
          "    encrypted_premaster\n" +\
          "-------->             "
    effects.append( _speak(screen, speak, podium, T ) )
    effects += move_h(screen, msg, Y, 'lurk_clt', T)
    T += max( TIC_MESSAGE, TIC_SPEAK )
    Y += msg.count('\n') + 1  

    speak = "The Key Server :                          \n" +\
            "    - 1) Decrypts the encrypted_premaster \n" +\
            "    - 2) Generates the master secret      "  
    msg = "RSAMasterResponse\n" +\
          "    master       \n" +\
          "<--------       "
    effects.append( _speak(screen, speak, podium, T ) )
    effects += move_h(screen, msg, Y, 'lurk_srv', T)
    T += max( TIC_MESSAGE, TIC_SPEAK )
    Y += msg.count('\n') + 1  


    speak = "With the master_secret, the TLS Server finalizes \n" +\
            "the authenticated TLS Key Exchange.              \n" +\
            "                                                 \n" +\
            "The TLS Server has not accessed the private key !"
    msg = "[ChangeCipherSpec] \n" +\
          "Finishedit         \n" +\
          "-------->          "
    effects += [ _speak(screen, speak, podium, T ) ]
    effects += move_h(screen, msg, Y, 'tls_clt', T )
    T += max( TIC_MESSAGE, TIC_SPEAK )
    Y += msg.count('\n') + 1  

    msg = "[ChangeCipherSpec] \n" +\
          "    Finished       \n" +\
          "<--------          "
    effects += move_h(screen, msg, Y, 'tls_srv', T )
    T += max( TIC_SPEAK, TIC_SPEAK )
    Y += msg.count('\n') + 1  

    txt = "Application Data      <------->     Application Data"
    kwargs = { "colour" : Screen.COLOUR_WHITE, "attr" : Screen.A_BOLD, \
               "bg" : Screen.COLOUR_BLACK, "clear" : True, 'transparent' : True, \
               'x' : int( screen.width  / 3 * ( 0.1 + 1 / 2) - len( txt ) / 2  ), \
               'start_frame' : T, 'stop_frame' : END_OF_DEMO }
    args = [ screen, s2r(txt), Y ] 
    effects.append( Print( *args,  **kwargs ) )
    T += TIC_SPEAK
    Y += txt.count('\n') + 1  



    scenes.append(Scene(effects, duration=20000, clear=True))
    

    #scenes.append(Scene(effects, -1))


    screen.play(scenes, stop_on_resize=True)


if __name__ == "__main__":
    while True:
        try:
            Screen.wrapper(demo)
            sys.exit(0)
        except ResizeScreenError:
            pass

