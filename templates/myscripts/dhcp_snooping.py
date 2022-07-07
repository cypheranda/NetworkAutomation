import threading
import os
import tempfile
from netmiko import ConnectHandler
from datetime import datetime
import uuid
import time

from napalm import get_network_driver


def dhcp_snooping(tmp_file, all_interfaces, VLANS_RANGE, DHCP_TRUSTED_INTERFACES, UNTRUSTED_LIMIT):
    fout = open(tmp_file, "wt")

    # conf dhcp snooping vlans and trusted interface

    fout.write('ip dhcp snooping\n')
    fout.write('ip dhcp snooping vlan ' + VLANS_RANGE + '\n')

    for DHCP_TRUSTED_INTERFACE in DHCP_TRUSTED_INTERFACES:
        fout.write('interface ' + DHCP_TRUSTED_INTERFACE + '\n')
        fout.write(' ip dhcp snooping trust\n')
        fout.write(' exit\n')

    # conf dhcp untrusted interfaces

    # get the rest of the interfaces
    # print(ios.get_interfaces().keys())
    index = 0
    for interface in all_interfaces.keys():
        if interface != DHCP_TRUSTED_INTERFACE:
            if 'Ethernet' in interface:
                fout.write('interface ' + interface + '\n')
                fout.write(' ip dhcp snooping limit rate ' + UNTRUSTED_LIMIT + '\n')
                fout.write(' exit\n')
                index += 1

    fout.close()


def do_dhcp_snooping(devices, os_type, username, password, enable, VLANS_RANGE, DHCP_TRUSTED_INTERFACES, UNTRUSTED_LIMIT):
    # configuration parameters
    # DHCP_TRUSTED_INTERFACES = 'GigabitEthernet0/0, ...'
    # VLANS_RANGE = '1,4,5'
    # UNTRUSTED_LIMITS = 2 # pt fiecare interfata
    return_statement = ""

    if os_type == 'cisco_ios':
        os_type = 'ios'

    for ip in devices:
        try:
            driver = get_network_driver(os_type)

            optional_args = {'secret': enable, 'global_delay_factor': 2}
            ios = driver(ip, username, password, optional_args=optional_args)
            ios.open()

            # create a temporary file to create the config
            tmp_file = str(uuid.uuid4())

            dhcp_snooping(tmp_file, ios.get_interfaces(), VLANS_RANGE, DHCP_TRUSTED_INTERFACES, UNTRUSTED_LIMIT)
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
            if 'Invalid input' in this_error:
                return_statement += ip + ' is a router! Or you are trying to set dhcp snooping on a L3 switch interface! Feature unavailable'
            else:
                return_statement += this_error + ' for ' + ip + '\n'

        if os.path.exists(tmp_file)==True:
            os.remove(tmp_file)

        print('Closing connection...')
        ios.close()

    return return_statement

