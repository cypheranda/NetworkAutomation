import os
import signal

import os

def do_ping(device_ip):
    response = os.system("ping -c 1 " + device_ip)
    ping_code = ""
    #and then check the response...
    if response == 0:
      ping_code="Successful ping to host!"
    else:
      ping_code="Destination host unreachable!"

    return ping_code


# print(do_ping("192.168.122.16"))
