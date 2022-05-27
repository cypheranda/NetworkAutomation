import threading
import os
import tempfile
from netmiko import ConnectHandler
from datetime import datetime
import uuid
import time

from napalm import get_network_driver


def dhcp_server_config(tmp_file, exclude_from_address, exclude_to_address, DHCP_pool, network_ip, network_mask, lease, default_router):
    fout = open(tmp_file, "wt")

    # enable the DHCP server process

    fout.write('service dhcp\n')

    # excluded addresses

    fout.write('ip dhcp excluded-address ' + exclude_from_address + ' ' + exclude_to_address + '\n')

    # conf dhcp pool

    fout.write('ip dhcp pool ' + DHCP_pool + '\n')
    fout.write(' network ' + network_ip + ' ' + network_mask + '\n')
    fout.write(' lease ' + lease + '\n')
    fout.write(' default-router ' + default_router + '\n')
    fout.write(' exit\n')


    fout.close()


def do_dhcp_server_config(devices, os_type, username, password, enable, exclude_from_address, exclude_to_address, DHCP_pool, network_ip, network_mask, lease, default_router):
    # configuration parameters
    # DHCP_SERVER_INTERFACE = 'g0/0'
    # server_ip_address = '10.0.0.1'
    # server_mask = '255.255.255.0'
    # DHCP_pool = 'crypto'
    # network_ip = '10.0.0.0'
    # network_mask = '255.255.255.0'
    # default_router = '10.0.0.1'
    # dns_server = '10.0.0.80'

    if os_type == 'cisco_ios':
        os_type = 'ios'

    try:
        for ip in devices:
            driver = get_network_driver(os_type)

            optional_args = {'secret': enable, 'global_delay_factor': 2}
            ios = driver(ip, username, password, optional_args=optional_args)
            ios.open()

            # create a temporary file to create the config
            tmp_file = str(uuid.uuid4())

            dhcp_server_config(tmp_file, exclude_from_address, exclude_to_address, DHCP_pool, network_ip, network_mask, lease, default_router)
            ios.load_merge_candidate(tmp_file)
            ios.commit_config()

            os.remove(tmp_file)

            print('Closing connection...')
            ios.close()
    except ConnectionRefusedError as err:
        return f"Connection Refused: {err}"
    except TimeoutError as err:
        return f"Connection Refused: {err}"
    except Exception as err:
        return f"Oops! {err}"



    return "Successful config!"


