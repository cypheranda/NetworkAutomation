import threading
import os
import tempfile
from netmiko import ConnectHandler
from datetime import datetime
import uuid
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def switch_stp(tmp_file, vars_array):
    fout = open(tmp_file, "wt")
    for item in vars_array:
        cmd = 'spanning-tree ' + item
        fout.write(cmd)

    fout.close()


def interface_stp(tmp_file, vars_array):
    fout = open(tmp_file, "wt")

    for item in vars_array:
        cmd = item
        if 'interface' in item:
            fout.write(item)
        else:
            cmd = 'spanning-tree ' + cmd

        fout.write(cmd)
    fout.close()


def check_stp_type(tmp_file, stp_file, vars_array):
    if stp_file == 'switch_stp':
        switch_stp(tmp_file, vars_array)
        return 1
    if stp_file == 'interface_stp':
        interface_stp(tmp_file, vars_array)
        return 1
    else:
        return 0

def start_stp(device, configuration, vars_array, tmp_file):
    connection = ConnectHandler(**device)

    print('Entering enable mode...')
    connection.enable()

    # create a temporary file to create the config
    
    if check_stp_type(tmp_file, configuration, vars_array) != 0:
        print('Sending commands from file...')
        connection.send_config_from_file(tmp_file)

    print('Closing connection...')
    connection.disconnect()


def do_stp(devices, os_type, username, password, enable, configuration, vars_array):

    for ip in devices:
        if os_type == 'ios':
            os_type = 'cisco_ios'

        cisco_device = {
            'device_type': os_type,
            'host': ip,
            'username': username,
            'password': password,
            'port': 22,  # optional, default 22
            'secret': enable,  # this is the enable password
            'verbose': True  # optional, default False
        }
        # note that the enable secret and passwords are only sent once, the confirmation is interface-based
        # vars_array = ['mst configuration', 'instance 2 vlan 3', 'name maria', 'revision 5']
        # configuration = 'switch_stp'
        tmp_file = str(uuid.uuid4())
        try:
            start_stp(cisco_device, configuration, vars_array, tmp_file)
        except ConnectionRefusedError as err:
            return f"Connection Refused: {err}"
        except TimeoutError as err:
            return f"Connection Refused: {err}"
        except Exception as err:
            return f"Oops! {err}"

        path = tmp_file
        CONFIG_PATH = os.path.join(ROOT_DIR, path)
        os.remove(path)

    return "Successful config!"

