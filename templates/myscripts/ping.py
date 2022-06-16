import os
import signal

import json

def do_ping(device_ip):
    response = os.system("/bin/ping -w 1 " + device_ip)
    ping_code = ""
    #and then check the response...
    if response == 0:
      ping_code="Successful ping to host!"
    else:
      ping_code="Destination host unreachable!"

    return ping_code


# print(do_ping("192.168.122.16"))
