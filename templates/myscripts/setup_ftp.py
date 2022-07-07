# ne tb username si parola pe care le are Toolbox la conexiune, adica root si gns3
from netmiko import ConnectHandler
import time

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
    output = connection.send_command_timing(ftp_server + '\n')
    output1 = connection.send_command_timing(newname + '\n', delay_factor=6)
    time.sleep(3)
    output = connection.read_channel()
    # parse output
    if output:
        output = output.split('\n')[1]
    else:
        output = output1

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
    output1 = connection.send_command_timing(newname + '\n', delay_factor=6)
    if 'already existing with this name' in output1:
        output1 = connection.send_command_timing('\n')

    time.sleep(3)
    output = connection.read_channel()
    # parse output
    if output:
        output = output.split('\n')[1]
    else:
        output = output1

    print('Closing connection...')
    connection.disconnect()
    return output


def do_ftp(devices, os_type, username, password, enable, config_type, ftp_server, arg1, arg2):
    output = ""
    return_statement = ""
    for ip in devices:
        pos = devices.index(ip)
        try:
            if config_type == 'To':
                output = ftp_send_file_to_server(ftp_server, ip, os_type, username, password, enable, arg1[pos], arg2[pos])
            elif config_type == 'From':
                output = ftp_send_file_from_server(ftp_server, ip, os_type, username, password, enable, arg1[pos], arg2[pos])
            elif config_type == 'Set credentials':
                output = setup_ftp_credentials(ftp_server, ip, os_type, username, password, enable, arg1, arg2) # root, gns3
                output = ''
# print('Sending commands from file...')

            if 'Error' in output:
                return_statement += "*** Error for " + ip + ":" + output + "\n"
            else:
                return_statement += "*** Succes for " + ip + " " + output + "\n"

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

#
# setup_ftp_credentials("192.168.122.150", "192.168.122.17", "root", "gns3")
