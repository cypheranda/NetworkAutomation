from netmiko import ConnectHandler


def tftp_send_file_to_server(tftp_server, host_ip, os_type, username, password, enable, filename, newname):
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

    command = "copy " + filename + " tftp://" + tftp_server + "/" + newname
    output = connection.send_command_timing(command)
    output1 = connection.send_command_timing(tftp_server + '\n')
    output2 = connection.send_command_timing(newname + '\n')

    print('Closing connection...')
    connection.disconnect()

def tftp_get_file_from_server(tftp_server, host_ip, os_type, username, password, enable, filename, newname):
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

    command = "copy tftp://" + tftp_server + "/" + filename + " " + newname
    output = connection.send_command_timing(command)
    output1 = connection.send_command_timing('\n')
    output2 = connection.send_command_timing('\n')

    print('Closing connection...')
    connection.disconnect()


def do_tftp(devices, os_type, username, password, enable, config_type, tftp_server, filenames, newnames):
    return_statement = ""
    for ip in devices:
        try:
            pos = devices.index(ip)

            if config_type == 'To':
                tftp_send_file_to_server(tftp_server, ip, os_type, username, password, enable, filenames[pos], newnames[pos])
            elif config_type == 'From':
                tftp_get_file_from_server(tftp_server, ip, os_type, username, password, enable, filenames[pos], newnames[pos])
            print('Sending commands from file...')

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
