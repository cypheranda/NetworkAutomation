from netmiko import ConnectHandler
from datetime import datetime
import uuid
import time
import os

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def check_archive_enable_scp(devices, os_type, username, password, enable):
    if os_type == 'ios':
        os_type = 'cisco_ios'
    for ip in devices:
        cisco_device = {
            'device_type': os_type,
            'host': ip,
            'username': username,
            'password': password,
            'port': '22',  # optional, default 22
            'secret': enable,  # this is the enable password
            'verbose': True  # optional, default False
        }

        connection = ConnectHandler(**cisco_device)
        prompter = connection.find_prompt()
        if '>' in prompter:
            connection.enable()

        if not connection.check_config_mode():
            connection.config_mode()

        archive_output = connection.send_command('show running-config\n')
        if 'archive' not in archive_output:
            connection.disconnect()
            return "Archive is not configured for " + ip + "\n No backup was loaded!"
        connection.send_command('aaa new-model\n')
        connection.send_command('aaa authentication login default local\n')
        connection.send_command('aaa authorization exec default local none\n')
        connection.send_command('username ' + username + ' privilege 15 password ' + password + '\n')
        connection.send_command('ip scp server enable\n')

        connection.disconnect()


def before_loading(devices, os_type, username, password, enable):
    try:
        check_archive_enable_scp(devices, os_type, username, password, enable)
    except ConnectionRefusedError as err:
        return f"Connection Refused: {err}"
    except TimeoutError as err:
        return f"Connection Refused: {err}"
    except Exception as err:
        return f"Oops! {err}"

    return 1


# output = before_loading(['192.168.122.77'], 'ios', 'admin', 'cisco', 'parola')
# print(output)
