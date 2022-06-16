from netmiko import ConnectHandler


def get_output(show_type, host_ip, username, password, secret, os_type='ios'):
    if 'ios' in os_type:
        os_type = 'cisco_ios'

    print(os_type)

    cisco_device = {
           'device_type': os_type,
           'host': host_ip,
           'username': username,
           'password': password,
           'port': 22,             # optional, default 22
           'secret': secret,      # this is the enable password
           'verbose': True         # optional, default False
           }
    connection = ConnectHandler(**cisco_device)

    # if show_type == 'secure boot':
    #     cmd = 'secure bootset'

    cmd = show_type
    cmd = 'show ' + cmd + '\n'

    print('Entering enable mode...')
    connection.enable()

    output = connection.send_command(cmd)

    print('Closing netmiko connection...')
    connection.disconnect()

    return output
