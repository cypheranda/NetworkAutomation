# works on switches
import threading
import os
import tempfile
from netmiko import ConnectHandler
from datetime import datetime
import uuid
import time

from napalm import get_network_driver
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def config(tmp_file, UNTRUSTED_VLANS, TRUSTED_INTERFACES, UNTRUSTED_INTERFACES):
    fout = open(tmp_file, "wt")

    # conf dynamic arp inspection trusted interfaces
    for vlan in UNTRUSTED_VLANS:
        fout.write('ip arp inspection vlan ' + vlan + '\n')

    for interface in TRUSTED_INTERFACES:
        fout.write('interface ' + interface + '\n')
        fout.write(' ip arp inspection trust\n')
        fout.write('exit\n')

    for no_interface in UNTRUSTED_INTERFACES:
        fout.write('interface ' + no_interface + '\n')
        fout.write(' no ip arp inspection trust\n')
        fout.write('exit\n')

    fout.close()

def dai_configuration(ip, os_type, username, password, enable, UNTRUSTED_VLANS, TRUSTED_INTERFACES, UNTRUSTED_INTERFACES):

    # create a temporary file to create the config
    tmp_file = str(uuid.uuid4())

    try:
        driver = get_network_driver(os_type)

        optional_args = {'secret': enable, 'global_delay_factor': 2}
        ios = driver(ip, username, password, optional_args=optional_args)
        ios.open()

        config(tmp_file, UNTRUSTED_VLANS, TRUSTED_INTERFACES, UNTRUSTED_INTERFACES)
        print('Sending commands from file...')

        ios.load_merge_candidate(tmp_file)
        ios.commit_config()
    finally:
        path = tmp_file
        CONFIG_PATH = os.path.join(ROOT_DIR, path)
        os.remove(path)
        ios.close()


def dai(devices, os_type, username, password, enable, UNTRUSTED_VLANS, TRUSTED_INTERFACES, UNTRUSTED_INTERFACES):
    return_statement = ""
    for ip in devices:
            # a router in this case acts as the dhcp server

        if os_type == 'cisco_ios':
            os_type = 'ios'
            # configuration parameters
            # UNTRUSTED_VLANS = ['104']
            # TRUSTED_INTERFACES = ['GigabitEthernet1/0', 'GigabitEthernet2/0']
            # UNTRUSTED_INTERFACES = ['GigabitEthernet0/1', 'GigabitEthernet0/2']


        try:
            dai_configuration(ip, os_type, username, password, enable, UNTRUSTED_VLANS, TRUSTED_INTERFACES, UNTRUSTED_INTERFACES)
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

    return return_statement

# dai(['192.168.204.17'], 'cisco_ios', 'admin', 'cisco', 'parola', ['104'], ['GigabitEthernet1/0', 'GigabitEthernet2/0'], ['GigabitEthernet0/1', 'GigabitEthernet0/2'])

