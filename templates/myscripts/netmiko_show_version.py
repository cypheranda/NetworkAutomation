#!/usr/bin/python
from netmiko import ConnectHandler
import re

# list where informations will be stored

# loop all ip addresses in ip_list
def show_version(device_ip, os_type, username, password):
    device = []
    cisco = {
        'device_type': os_type,
        'ip': device_ip,
        'username': username,  # ssh username
        'password': password,  # ssh password
    }

    net_connect = ConnectHandler(**cisco)

    output = net_connect.send_command('show version')

    # get hostname
    regex_hostname = re.compile(r'(\S+)\suptime')
    hostname = regex_hostname.findall(output)

    # get uptime
    regex_uptime = re.compile(r'\S+\suptime\sis\s(.+)')
    uptime = regex_uptime.findall(output)

    # get version
    regex_version = re.compile(r'Cisco\sIOS\sSoftware.+Version\s([^,]+)')
    version = regex_version.findall(output)

    # get serial
    regex_serial = re.compile(r'Processor\sboard\sID\s(\S+)')
    serial = regex_serial.findall(output)

    # get ios image
    regex_ios = re.compile(r'System\simage\sfile\sis\s"([^ "]+)')
    ios = regex_ios.findall(output)

    # append results
    device.append(hostname[0])
    device.append(uptime[0])
    device.append(version[0])
    device.append(serial[0])
    device.append(ios[0])

    return device
