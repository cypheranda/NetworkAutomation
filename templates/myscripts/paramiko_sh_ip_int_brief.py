from netmiko import ConnectHandler
import re
import json
from pprint import pprint
import paramiko
import time
import re


def connect(server_ip, server_port, user, password):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh_client.connect(hostname=server_ip, port=server_port, username=user, password=password,
                       look_for_keys=False, allow_agent=False)
    return ssh_client


def get_shell(ssh_client):
    shell = ssh_client.invoke_shell()
    return shell


def send_command(shell, command, timeout=1):
    shell.send(command + '\n')
    time.sleep(timeout)


def show(shell, n=10000):
    output = shell.recv(n)
    return output.decode()


def close(ssh_client):
    if ssh_client.get_transport().is_active():
        # print('Closing connection...')
        ssh_client.close()


def show_ipintbrief(device_ip, username, password, enable_pass):
    # arguments
    arg1 = device_ip
    arg2 = '22'
    arg3 = username
    arg4 = password
    #

    router1 = {'server_ip': arg1, 'server_port': arg2, 'user': arg3, 'password': arg4}

    client = connect(**router1)
    shell = get_shell(client)

    send_command(shell, 'enable')
    send_command(shell, enable_pass)
    send_command(shell, 'terminal length 0')
    send_command(shell, 'sh ip int brief')

    output = show(shell)
    # print(output)

    close(client)

    # this regex is to match for gigabit, ethernet, fastethernet and loopback.
    intf_pattern = "^[lLgGeEfF]\S+[0-9]/?[0-9]*"
    # create a regex object with the pattern in place.
    regex = re.compile(intf_pattern)
    # initialize this list to collect interface information.
    interfaces = []

    for row in output.splitlines():
        # check for interface names only
        if regex.search(row):
            # start collecting the dictionary
            interfaces.append(
                {'interface': row.split()[0],
                 'ip_address': row.split()[1],
                 'ok': row.split()[2],
                 'method': row.split()[3],
                 'status': row.split()[4],
                 'protocol': row.split()[5]}
            )
    # Convert into string of dictionary.
    # pprint(json.dumps(interfaces))
    int = [interface.get('interface') for interface in interfaces if
           interface.get('status') and interface.get('protocol') == 'up']
    int_ipaddress = [interface.get('ip_address') for interface in interfaces if
                     interface.get('status') and interface.get('protocol') == 'up']

    return int, int_ipaddress
