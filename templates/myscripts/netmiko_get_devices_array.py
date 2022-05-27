import re


def get_device_data(inventory, devices):
    devices_hostname = []
    devices_ip = []
    devices_username = ""
    devices_password = ""
    devices_enable_password = ""
    devices_ostype = ""

    fin = open(inventory, "r")
    line_pos = 0
    found_devices_line = 0
    devices_array = []
    tag_line = '[' + devices + ']'
    for line in fin:
        print(line)
        if found_devices_line == 1:
            if '[' and ']' in line:
                break
            elif len(line) and line!='\n':
                devices_array.append(line)
        if tag_line in line:
            found_devices_line = 1
    line_pos += 1



    for item in devices_array:
        if len(item.split()) >= 2:
            if 'ansible_host' in item.split()[1]:
                devices_hostname.append(item.split()[0])
                devices_ip.append(item.split()[1].split('=')[1])

    # get devices general data
    fin.seek(0)
    for line in fin:
        if "ansible_network_os" in line:
            devices_ostype = line.split('=')[1]
        if "ansible_user" in line:
            devices_username = line.split('=')[1]
        if "ansible_password" in line:
            to_eliminate = line.split('=')[0] + '='
            devices_password = re.sub(to_eliminate, '', line)
        if "ansible_become_password" in line:
            to_eliminate = line.split('=')[0] + '='
            devices_enable_password = re.sub(to_eliminate, '', line)

    fin.close()

    converted_hostname_list = []
    for element in devices_hostname:
        converted_hostname_list.append(element.strip('\n'))

    converted_ip_list = []
    for element in devices_ip:
        converted_ip_list.append(element.strip('\n'))

    devices_ostype = devices_ostype.strip('\n')
    devices_username = devices_username.strip('\n')
    devices_password = devices_password.strip('\n')
    devices_enable_password = devices_enable_password.strip('\n')

    return converted_hostname_list, converted_ip_list, devices_ostype, devices_username, devices_password, devices_enable_password


# devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = get_device_data("inventory", "switches")
# print(devices_hostname[0])
# print(devices_ip[0])
# print(devices_ostype)
# print(devices_username)
# print(devices_password)
# print(devices_enable_password)


def get_device_backup_file(inventory, devices):
    devices_hostname = []
    devices_files = []
    devices_ip = []

    fin = open(inventory, "r")
    line_pos = 0
    found_devices_line = 0
    devices_array = []
    tag_line = '[' + devices + ']'
    for line in fin:
        print(line)
        if found_devices_line == 1:
            if '[' and ']' in line:
                break
            elif len(line) and line != '\n':
                devices_array.append(line)
        if tag_line in line:
            found_devices_line = 1
    line_pos += 1

    for item in devices_array:
        if len(item.split()) >= 3:
            if 'ansible_host' in item.split()[1]:
                if 'src_file' in item.split()[2]:
                    devices_hostname.append(item.split()[0])
                    devices_ip.append(item.split()[1].split('=')[1])
                    devices_files.append(item.split()[2].split('=')[1])

    fin.close()

    converted_hostname_list = []
    for element in devices_hostname:
        converted_hostname_list.append(element.strip('\n'))

    converted_files_list = []
    for element in devices_files:
        converted_files_list.append(element.strip('\n'))

    converted_ip_list = []
    for element in devices_ip:
        converted_ip_list.append(element.strip('\n'))

    return converted_hostname_list, converted_ip_list, converted_files_list


def get_device_src_dest_transfer_files(inventory, devices):
    devices_hostname = []
    devices_src_files = []
    devices_dest_files = []
    devices_ip = []

    fin = open(inventory, "r")
    line_pos = 0
    found_devices_line = 0
    devices_array = []
    tag_line = '[' + devices + ']'
    for line in fin:
        print(line)
        if found_devices_line == 1:
            if '[' and ']' in line:
                break
            elif len(line) and line != '\n':
                devices_array.append(line)
        if tag_line in line:
            found_devices_line = 1
    line_pos += 1

    for item in devices_array:
        if len(item.split()) >= 3:
            if 'ansible_host' in item.split()[1]:
                if 'src_file' in item.split()[2] and 'dest_file' in item.split()[3]:
                    devices_hostname.append(item.split()[0])
                    devices_ip.append(item.split()[1].split('=')[1])
                    devices_src_files.append(item.split()[2].split('=')[1])
                    devices_dest_files.append(item.split()[3].split('=')[1])


    fin.close()

    converted_hostname_list = []
    for element in devices_hostname:
        converted_hostname_list.append(element.strip('\n'))

    converted_src_files_list = []
    for element in devices_src_files:
        converted_src_files_list.append(element.strip('\n'))

    converted_dest_files_list = []
    for element in devices_dest_files:
        converted_dest_files_list.append(element.strip('\n'))

    converted_ip_list = []
    for element in devices_ip:
        converted_ip_list.append(element.strip('\n'))

    return converted_hostname_list, converted_ip_list, converted_src_files_list, converted_dest_files_list


# devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = get_device_data("inventory", "switches")
# print(devices_hostname[0])
# print(devices_ip[0])
# print(devices_ostype)
# print(devices_username)
# print(devices_password)
# print(devices_enable_password)
