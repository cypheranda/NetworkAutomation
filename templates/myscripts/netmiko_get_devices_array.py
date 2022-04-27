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
            elif len(line):
                devices_array.append(line)
        if tag_line in line:
            found_devices_line = 1
    line_pos += 1

    # get devices general data
    fin.seek(0)
    for line in fin:
        if "ansible_network_os" in line:
            devices_ostype = line.split('=')[1]
        if "ansible_user" in line:
            devices_username = line.split('=')[1]
        if "ansible_password" in line:
            devices_password = line.split('=')[1]
        if "ansible_become_password" in line:
            devices_enable_password = line.split('=')[1]

    fin.close()

    for item in devices_array:
        if item.split():
            devices_hostname.append(item.split()[0])
            devices_ip.append(item.split()[1].split('=')[1])

    return devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password


# devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = get_device_data("inventory", "switches")
# print(devices_hostname[0])
# print(devices_ip[0])
# print(devices_ostype)
# print(devices_username)
# print(devices_password)
# print(devices_enable_password)
