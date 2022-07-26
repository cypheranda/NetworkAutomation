import threading
import os
import tempfile
import sys
import io
from subprocess import run
import requests
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
from datetime import datetime
import uuid

# from templates.myscripts import netmiko_check_autosecure_config, napalm_check_connectivity
from templates.myscripts import netmiko_check_autosecure_config

old_stdout = sys.stdout
new_stdout = io.StringIO()
sys.stdout = new_stdout
output = ""
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# Interactive full session of AutoSecure
def autosecure_full(type, device, tmp_file, vars_array):
    fout = open(tmp_file, "wt")

    fout.write("auto secure " + type + '\n')

    # Is this router connected to internet? [no]
    fout.write("no" + '\n')

    # Enter the security banner {Put the banner between
    # k and k, where k is any character}
    fout.write("k" + vars_array[0] + "k" + '\n')

    # Enter the new enable secret
    # Choose a secret that's different from password
    # Invalid Password length - must contain 6 to 25 characters. Password configuration failed
    fout.write(vars_array[1] + '\n')

    # Confirm the enable secret
    fout.write(vars_array[1] + '\n')

    # Enter the new enable password
    # Choose a password that's different from secret
    fout.write(vars_array[2] + '\n')

    # Confirm the enable password
    fout.write(vars_array[2] + '\n')


    if netmiko_check_autosecure_config.autosecure_local_user(device) == 0:
        # Configuration of local user database
        # Enter the username
        fout.write(vars_array[3] + '\n')

        # Enter the password:
        # % Invalid Password length - must contain 6 to 25 characters. Password configuration failed
        fout.write(vars_array[4] + '\n')

        # Confirm the password
        fout.write(vars_array[4] + '\n')

    # Blocking Period when Login Attack detected
    fout.write(vars_array[5] + '\n')

    # Maximum Login failures with the device
    fout.write(vars_array[6] + '\n')

    # Maximum time period for crossing the failed login attempts
    fout.write(vars_array[7] + '\n')

    # Configure SSH server?
    fout.write(vars_array[8] + '\n')

    if vars_array[8] == 'yes':
        # Enter the hostname
        fout.write(vars_array[9] + '\n')
        # Enter the domain-name
        fout.write(vars_array[10] + '\n')

    if netmiko_check_autosecure_config.autosecure_firewall(device) == 0:
        # Configure CBAC Firewall feature? [yes/no]
        fout.write(vars_array[11] + '\n')

        if vars_array[11] == "no":
            # Enable tcp intercept feature? [yes/no]
            fout.write(vars_array[12] + '\n')

    # Apply this configuration to running-config? [yes]
    fout.write("yes" + '\n')

    fout.close()


# Non-interactive session of AutoSecure
# empty vars array
def autosecure_nointeract(type, tmp_file):
    fout = open(tmp_file, "wt")

    fout.write("auto secure " + type + '\n')

    fout.close()


# AutoSecure TCP Intercept
# empty vars array
def autosecure_tcpintercept(type, tmp_file):
    fout = open(tmp_file, "wt")

    fout.write("auto secure " + type + '\n')

    # Is this router connected to internet? [no]
    fout.write("no" + '\n')

    # Enable tcp intercept feature? [yes/no]
    fout.write("yes" + '\n')

    # Apply this configuration to running-config? [yes]
    fout.write("yes" + '\n')

    fout.close()


# AutoSecure NTP
# empty vars array
def autosecure_ntp(type, tmp_file):
    fout = open(tmp_file, "wt")

    fout.write("auto secure " + type + '\n')

    # Is this router connected to internet? [no]
    fout.write("no" + '\n')

    # Apply this configuration to running-config? [yes]
    fout.write("yes" + '\n')

    fout.close()


# AutoSecure SSH
# la nivel de interfata grafica tb o verificare asemanatoare pt a nu permite utilizatorului sa seteze domain name
def autosecure_ssh(type, device, tmp_file, vars_array):
    fout = open(tmp_file, "wt")

    fout.write("auto secure " + type + '\n')

    # Is this router connected to internet? [no]
    fout.write("no" + '\n')

    # Configure SSH server? [yes]
    fout.write("yes" + '\n')

    # Enter the domain-name
    if netmiko_check_autosecure_config.autosecure_domain_name(device) == 0:
        fout.write(vars_array[10] + '\n')

    # Apply this configuration to running-config? [yes]
    fout.write("yes" + '\n')

    fout.close()


# AutoSecure Login
def autosecure_login(type, device, tmp_file, vars_array):
    fout = open(tmp_file, "wt")

    fout.write("auto secure " + type + '\n')

    # Is this router connected to internet? [no]
    fout.write("no" + '\n')

    if netmiko_check_autosecure_config.autosecure_login(device) == 0:
        # Enter the new enable secret
        # Choose a secret that's different from password
        # Invalid Password length - must contain 6 to 25 characters. Password configuration failed
        fout.write(vars_array[1] + '\n')

        # Confirm the enable secret
        fout.write(vars_array[1] + '\n')

        # Enter the new enable password
        # Choose a password that's different from secret
        fout.write(vars_array[2] + '\n')

        # Confirm the enable password
        fout.write(vars_array[2] + '\n')


    if netmiko_check_autosecure_config.autosecure_local_user(device) == 0:
        # Configuration of local user database
        # Enter the username
        fout.write(vars_array[3] + '\n')

        # Enter the password:
        # % Invalid Password length - must contain 6 to 25 characters. Password configuration failed
        fout.write(vars_array[4] + '\n')

        # Confirm the password
        fout.write(vars_array[4] + '\n')

    # Blocking Period when Login Attack detected
    fout.write(vars_array[5] + '\n')

    # Maximum Login failures with the device
    fout.write(vars_array[6] + '\n')

    # Maximum time period for crossing the failed login attempts
    fout.write(vars_array[7] + '\n')

    # Apply this configuration to running-config? [yes]
    fout.write("yes" + '\n')

    fout.close()


# AutoSecure Firewall
def autosecure_firewall(type, tmp_file):
    fout = open(tmp_file, "wt")

    fout.write("auto secure " + type + '\n')

    # Is this router connected to internet? [no]
    fout.write("no" + '\n')

    # Configure CBAC Firewall feature? [yes/no]
    fout.write('yes' + '\n')

    # Apply this configuration to running-config? [yes]
    fout.write("yes" + '\n')

    fout.close()


def check_autosecure_type(device, connection, tmp_file, vars_array):
    copy_array = vars_array[1:]
    if vars_array[0] == "management full":
        type = "management full"
        autosecure_full(type, device, tmp_file, copy_array)
        return 1
    elif vars_array[0] == "management no-interact":
        type = "management no-interact"
        autosecure_nointeract(type, tmp_file)
        return 1
    elif vars_array[0] == "management ssh":
        type = "management ssh"
        autosecure_ssh(type, device, tmp_file, copy_array)
        return 1
    elif vars_array[0] == "management ntp":
        type = "management ntp"
        autosecure_ntp(type, tmp_file)
        return 1
    elif vars_array[0] == "management login":
        type = "management login"
        autosecure_login(type, device, tmp_file, copy_array)
        return 1
    elif vars_array[0] == "forwarding full":
        type = "forwarding full"
        autosecure_firewall(type, tmp_file)
        return 1
    elif vars_array[0] == "forwarding no-interact":
        type = "forwarding no-interact"
        autosecure_nointeract(type, tmp_file)
        return 1
    elif vars_array[0] == "forwarding tcp-intercept":
        type = "forwarding tcp-intercept"
        autosecure_tcpintercept(type, tmp_file)
        return 1
    elif vars_array[0] == "forwarding firewall":
        type = "forwarding firewall"
        autosecure_firewall(type, tmp_file)
        return 1
    elif vars_array[0] == "firewall":
        type = "firewall"
        autosecure_firewall(type, tmp_file)
        return 1
    elif vars_array[0] == "full":
        type = "full"
        autosecure_full(type, device, tmp_file, copy_array)
        return 1
    elif vars_array[0] == "login":
        type = "login"
        autosecure_login(type, device, tmp_file, copy_array)
        return 1
    elif vars_array[0] == "no-interact":
        type = "no-interact"
        autosecure_nointeract(type, tmp_file)
        return 1
    elif vars_array[0] == "ntp":
        type = "ntp"
        autosecure_ntp(type, tmp_file)
        return 1
    elif vars_array[0] == "ssh":
        type = "ssh"
        autosecure_ssh(type, device, tmp_file, copy_array)
        return 1
    elif vars_array[0] == "tcp_intercept":
        type = "tcp_intercept"
        autosecure_tcpintercept(type, tmp_file)
        return 1
    else:
        return 0


def send_commands(connection, tmp_file):
    f = open(tmp_file, "r")
    result = ""
    for line in f:
        result = connection.send_command_timing(line, 1, 150, True, True, True, False, None, False, None, False, False)
        if 'Invalid input' in result:
            break

    f.close()
    return result


def autosecure(device, vars_array):
    output = ""
    connection = ConnectHandler(**device)

    print('Entering enable mode...')
    connection.enable()

    # create a temporary file to create the config
    tmp_file = str(uuid.uuid4())
    try:
        if check_autosecure_type(device, connection, tmp_file, vars_array) != 0:
            print('Sending commands from file...')
            output = send_commands(connection, tmp_file)

    finally:
        print('Done!')
        path = tmp_file
        CONFIG_PATH = os.path.join(ROOT_DIR, path)
        os.remove(path)

    print('Closing connection...')
    connection.disconnect()
    return output

def do_autosecure(devices, os_type, username, password, enable, vars_array):
    # mylist = devices.split(', ')
    return_statement = ""

    for ip in devices:
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
        # note that the enable secret and passwords are only sent once, the confirmation is interface-based
        # vars_array = ['1', 'knot setk', 'not set', 'not set 2', 'not set', 'not set 3', '30', '30', '30', 'No', 'not set', 'not set', 'No', 'No']
        try:
            output = autosecure(cisco_device, vars_array)
            if 'Invalid input' in output:
                return_statement += "*** Feature unavailable for " + ip + " as this is a switch.\n"
            else:
                return_statement += "*** Succes for " + ip + ".\n"
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


# vars_array = ['firewall', 'knot setk', 'not set', 'not set 2', 'not set', 'not set 3', '30', '30', '30', 'No', 'not set',
#               'not set', 'No', 'No']
#
# do_autosecure('192.168.204.16', 'ios', 'admin', 'cisco', 'parola', vars_array)
