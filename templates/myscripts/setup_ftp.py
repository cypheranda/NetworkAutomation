# ne tb username si parola pe care le are Toolbox la conexiune, adica root si gns3
from netmiko import ConnectHandler


def setup_ftp_credentials(ftp_server, host_ip, os_type, username, password, enable, ftp_username, ftp_password):
    if os_type == 'ios':
        os_type = 'cisco_ios'

    # dictionary
    cisco_device = {
        'device_type': os_type,
        'host': host_ip,
        'username': username,
        'password': password,
        'port': 22,  # optional, default 22
        'secret': enable,  # this is the enable password
        'verbose': True  # optional, default False
    }

    connection = ConnectHandler(**cisco_device)

    print('Entering enable mode...')
    connection.enable()

    username_cmd = "ip ftp username " + ftp_username
    password_cmd = "ip ftp password " + ftp_password

    output = connection.send_config_set(username_cmd)
    output = connection.send_config_set(password_cmd)

    print('Closing connection...')
    connection.disconnect()
    return output


def ftp_send_file_to_server(ftp_server, host_ip, os_type, username, password, enable, filename, newname):
    if os_type == 'ios':
        os_type = 'cisco_ios'

    # dictionary
    cisco_device = {
        'device_type': os_type,
        'host': host_ip,
        'username': username,
        'password': password,
        'port': 22,  # optional, default 22
        'secret': enable,  # this is the enable password
        'verbose': True  # optional, default False
    }

    connection = ConnectHandler(**cisco_device)

    print('Entering enable mode...')
    connection.enable()

    command = "copy " + filename + " ftp://" + ftp_server + "/" + newname
    output = connection.send_command_timing(command)
    output = connection.send_command_timing('\n')
    output = connection.send_command_timing('\n')

    print('Closing connection...')
    connection.disconnect()
    return output


def ftp_send_file_from_server(ftp_server, host_ip, os_type, username, password, enable, filename, newname):
    if os_type == 'ios':
        os_type = 'cisco_ios'

    # dictionary
    cisco_device = {
        'device_type': os_type,
        'host': host_ip,
        'username': username,
        'password': password,
        'port': 22,  # optional, default 22
        'secret': enable,  # this is the enable password
        'verbose': True  # optional, default False
    }

    connection = ConnectHandler(**cisco_device)

    print('Entering enable mode...')
    connection.enable()

    command = "copy ftp://" + ftp_server + "/" + filename + " " + newname
    output = connection.send_command_timing(command)
    output = connection.send_command_timing('\n')
    output = connection.send_command_timing('\n')

    print('Closing connection...')
    connection.disconnect()
    return output


def do_ftp(devices, os_type, username, password, enable, config_type, ftp_server, arg1, arg2):
    output = ""
    for ip in devices:
        pos = devices.index(ip)
        try:
            if config_type == 'To':
                output = ftp_send_file_to_server(ftp_server, ip, os_type, username, password, enable, arg1[pos], arg2[pos])
            elif config_type == 'From':
                output = ftp_send_file_from_server(ftp_server, ip, os_type, username, password, enable, arg1[pos], arg2[pos])
            elif config_type == 'Set credentials':
                output = setup_ftp_credentials(ftp_server, ip, os_type, username, password, enable, arg1, arg2) # root, gns3
            # print('Sending commands from file...')

        except ConnectionRefusedError as err:
            return f"Connection Refused: {err}"
        except TimeoutError as err:
            return f"Connection Refused: {err}"
        except Exception as err:
            return f"Oops! {err}"

    if not output:
        return output
    else:
        return "Successful transfer!"

#
# setup_ftp_credentials("192.168.122.150", "192.168.122.17", "root", "gns3")
