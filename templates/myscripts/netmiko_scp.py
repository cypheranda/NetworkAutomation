from netmiko import ConnectHandler
from netmiko import file_transfer
import os
# arguments
from templates.myscripts import netmiko_get_devices_array
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def do_scp_transfer(inventory, inventory_element, devices, os_type, username, password, enable):
    hostnames, ips, files = netmiko_get_devices_array.get_device_backup_file(inventory, inventory_element)
    if len(ips) != len(devices):
        return 0
    elif len(hostnames) != len(devices):
        return 0

    transfer_output = []

    for ip in devices:
        curr_pos = devices.index(ip)
        path = 'backup/' + files[curr_pos]
        CONFIG_PATH = os.path.join(ROOT_DIR, path)  # requires `import os`
        src_file_arg = CONFIG_PATH
        dest_file_arg = hostnames[curr_pos] + '.finalconfig'
        file_system_arg = 'flash:'
        #

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

        connection = ConnectHandler(**cisco_device)
        print(src_file_arg)
        print(dest_file_arg)
        print(file_system_arg)

        transfer_output.append(file_transfer(connection, source_file=src_file_arg, dest_file=dest_file_arg,
                                        file_system=file_system_arg,
                                        direction='put', overwrite_file=True))



        connection.disconnect()

    return transfer_output


def check_scp(inventory, inventory_element, devices, os_type, username, password, enable):
    try:
        do_scp_transfer(inventory, inventory_element, devices, os_type, username, password, enable)
    except ConnectionRefusedError as err:
        return f"Connection Refused: {err}"
    except TimeoutError as err:
        return f"Connection Refused: {err}"
    except Exception as err:
        return f"Oops! {err}"

#
# print(check_scp("inventory", "routers", ['192.168.122.77'], 'ios', 'admin', 'cisco', 'parola'))
