import threading
import os
import tempfile
from netmiko import ConnectHandler
from datetime import datetime
import uuid
import time

from napalm import get_network_driver

do_enable = 'yes'


def ipsg_enable(tmp_file, do_enable, IPSG_INTERFACE):
    fout = open(tmp_file, "wt")

    # conf ipsg for interface
    cmd = 'ip verify source port-security\n'

    fout.write('interface ' + IPSG_INTERFACE + '\n')
    if do_enable == 'yes':
        fout.write(' ' + cmd)
    elif do_enable == 'no':
        fout.write(' no ' + cmd)
    fout.write(' exit\n')

    fout.close()


def static_binding(tmp_file, do_enable, IP_ADDRESS, MAC_ADDRESS, VLAN, INTERFACE):
    fout = open(tmp_file, "wt")

    # enable the IP Source Guard with a static source IP address and MAC address filtering mapped on VLAN
    cmd = 'ip source binding ' + MAC_ADDRESS + ' vlan ' + VLAN + ' ' + IP_ADDRESS + ' interface ' + INTERFACE + '\n'

    if do_enable == 'yes':
        fout.write(cmd)
    elif do_enable == 'no':
        fout.write('no ' + cmd)
    fout.write('exit\n')

    fout.close()


def do_ipsg(devices, os_type, username, password, enable, config_type, IP_ADDRESS, MAC_ADDRESS, VLAN, INTERFACE):

    return_statement = ""

    for ip in devices:
        # enable or disable IP source guard on interface
        # configuration parameters

        # add or remove static IP source entry
        # example: Switch(config)# ip source binding 0011.0011.0011 vlan 5 10.1.1.11 interface GigabitEthernet1/0/2
        # configuration parameters

        try:
            if os_type == 'cisco_ios':
                driver = get_network_driver('ios')
            else:
                driver = get_network_driver(os_type)

            optional_args = {'secret': enable, 'global_delay_factor': 2}
            ios = driver(ip, username, password, optional_args=optional_args)
            ios.open()

            # create a temporary file to create the config
            tmp_file = str(uuid.uuid4())


            if config_type == 'ipsg_enable':
                ipsg_enable(tmp_file, do_enable, INTERFACE)
            elif config_type == 'static_binding':
                static_binding(tmp_file, do_enable, IP_ADDRESS, MAC_ADDRESS, VLAN, INTERFACE)
            print('Sending commands from file...')

            ios.load_merge_candidate(tmp_file)
            ios.commit_config()

            return_statement += "Succes for " + ip + ".\n"
        except ConnectionRefusedError as err:
            this_error = f"Connection Refused: {err}\n"
            return_statement += this_error
        except TimeoutError as err:
            this_error = f"Connection Refused: {err}\n"
            return_statement += this_error
        except Exception as err:
            this_error = f"Oops: {err}\n"
            return_statement += this_error

        os.remove(tmp_file)

        print('Closing connection...')
        ios.close()

    return return_statement


# do_ipsg('192.168.204.16', 'cisco_ios', 'admin', 'cisco', 'parola', 'static_binding', '111.111.111.111', '00:29:15:80:4E:4A', '102', 'GigabitEthernet0/0')
