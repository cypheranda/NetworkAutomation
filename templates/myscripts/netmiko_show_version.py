#!/usr/bin/python
from netmiko import ConnectHandler
import re

# list where informations will be stored

# loop all ip addresses in ip_list
def show_version(device_ip, os_type, username, password):
    device = []
    hostname = ""
    uptime = ""
    version = ""
    serial = ""
    ios = ""

    cisco = {
        'device_type': os_type,
        'ip': device_ip,
        'username': username,  # ssh username
        'password': password,  # ssh password
    }

    try:
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
        hostname = hostname[0]
        uptime = uptime[0]
        version = version[0]
        serial = serial[0]
        ios = ios[0]
    except ConnectionRefusedError as err:
        hostname = "error"
    except TimeoutError as err:
        hostname = "error"
    except Exception as err:
        hostname = "error"

    return hostname, uptime, version, serial, ios
