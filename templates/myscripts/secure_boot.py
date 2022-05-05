# The Cisco IOS Resilient Configuration feature enables a router to secure and maintain a working copy
# of the running image and configuration so that those files can withstand malicious attempts to erase
# the contents of persistent storage (NVRAM and flash).

# works only on Cisco IOSV 15.6 router

import threading
import os
import tempfile
from netmiko import ConnectHandler
from datetime import datetime
import uuid
import time
from napalm import get_network_driver
from templates.myscripts import netmiko_show, netmiko_run_commands_from_file

# Archiving a Router Configuration
# This task describes how to save a primary bootset to a secure archive in persistent storage.

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

def archive_router_config(tmp_file, host_ip, username, password, secret):
    fout = open(tmp_file, "wt")

    image = 'secure boot-image\n'
    config = 'secure boot-config\n'

    output = netmiko_show.get_output('secure boot', host_ip, username, password, secret)
    print(output)

    if 'IOS image and configuration resilience is not active' in output:
        fout.write(image)
        fout.write(config)
    elif 'IOS image resilience is not active' in output:
        fout.write(image)
        fout.write('no ' + config)
        fout.write(config)
    elif 'IOS configuration resilience is not active' in output:
        fout.write(config)
        fout.write('no ' + image)
        fout.write(image)

    fout.close()

# Restoring an Archived Router Configuration
# This task describes how to restore a primary bootset
# from a secure archive after the router has been tampered
# with (by an NVRAM erase or a disk format).

def restore_archived_router_config(tmp_file,  host_ip, username, password, secret):
    fout = open(tmp_file, "wt")

    # get secure bootset output
    secure_bootset = netmiko_show.get_output('secure boot', host_ip, username, password, secret)
    # print(secure_bootset)

    # get boot image

    image_part_start_index = secure_bootset.find('IOS image resilience')
    image_part_stop_index = secure_bootset.find(' type is image')
    image_part = secure_bootset[image_part_start_index:image_part_stop_index]

    image_start_index = image_part.find('Secure archive')
    image = image_part[image_start_index+15:image_part_stop_index]
    # print(image)

    # get archived config

    config_part_start_index = secure_bootset.find('IOS configuration resilience')
    config_part_stop_index = secure_bootset.find(' type is config')
    config_part = secure_bootset[config_part_start_index:config_part_stop_index]

    config_start_index = config_part.find('Secure archive')
    config = config_part[config_start_index+15:config_part_stop_index]
    # print(config)

    fout.write('boot system flash ' + image + '\n')
    fout.write('no\n')
    fout.write('enable\n')
    fout.write(secret + '\n')
    fout.write('conf t\n')
    fout.write('secure boot-config restore ' + config + '\n')
    fout.write('end\n')
    fout.write('copy ' + config + ' running-config\n')


    fout.close()


def do_secureboot(devices, os_type, username, password, enable, config_type):
    for ip in devices:

        # Archiving a Router Configuration

        # restore_archived_router_config
        #config_type = 'restore_archived_router_config'

        # create a temporary file to create the config
        tmp_file = str(uuid.uuid4())

        try:
            if config_type == 'archive_router_config':
                archive_router_config(tmp_file, ip, username, password, enable)
            elif config_type == 'restore_archived_router_config':
                restore_archived_router_config(tmp_file, ip, username, password, enable)
            print('Sending commands from file...')

            # connect to device and run commands from file

            netmiko_run_commands_from_file.run_commands_from_file(tmp_file, ip, username, password, enable)
        except ConnectionRefusedError as err:
            return f"Connection Refused: {err}"
        except TimeoutError as err:
            return f"Connection Refused: {err}"
        except Exception as err:
            return f"Oops! {err}"

        path = tmp_file
        CONFIG_PATH = os.path.join(ROOT_DIR, path)
        os.remove(path)

        return "Successful configuration!"
