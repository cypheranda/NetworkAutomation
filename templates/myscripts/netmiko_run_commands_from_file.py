from netmiko import ConnectHandler

def run_commands_from_file(filein,  host_ip, username, password, secret):
    cisco_device = {
           'device_type': 'cisco_ios',
           'host': host_ip,
           'username': username,
           'password': password,
           'port': 22,             # optional, default 22
           'secret': secret,      # this is the enable password
           'verbose': True         # optional, default False
           }
    connection = ConnectHandler(**cisco_device)

    print('Entering enable mode...')
    connection.enable()

    print('Sending commands from file...')
    connection.send_config_from_file(filein, cmd_verify=False)

    print('Closing connection...')
    connection.disconnect()