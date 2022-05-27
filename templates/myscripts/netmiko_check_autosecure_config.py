
# for auto secure
from netmiko import ConnectHandler

def autosecure_domain_name(device):

    net_connect = ConnectHandler(**device)
    net_connect.enable()

    output = net_connect.send_command('show auto secure config')
    net_connect.disconnect()

    if "ip domain-name" in output:
        return 1
    else:
        return 0

def autosecure_local_user(device):

    net_connect = ConnectHandler(**device)
    net_connect.enable()

    output = net_connect.send_command('show auto secure config')
    net_connect.disconnect()

    if "user" in output:
        return 1
    else:
        return 0

def autosecure_firewall(device):

    net_connect = ConnectHandler(**device)
    net_connect.enable()

    output = net_connect.send_command('show auto secure config')
    net_connect.disconnect()

    if "ip inspect" in output:
        return 1
    else:
        return 0

def autosecure_login(device):

    net_connect = ConnectHandler(**device)
    net_connect.enable()

    output = net_connect.send_command('show auto secure config')
    net_connect.disconnect()

    if "enable password" in output:
        if "enable secret" in output:
            return 1
        else:
            return 0
    else:
        return 0
