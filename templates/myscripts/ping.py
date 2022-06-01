import os
import signal
import time


def do_ping(device_ip):
    ping_code = ""

    output = os.popen(f"ping {device_ip} -w 1").read()

    if "Request timed out" in output:
        ping_code="Request timed out"
    elif "Destination host unreachable" in output:
        ping_code="Destination host unreachable"
    else:
        ping_code="Successful ping to host!"

    return ping_code

