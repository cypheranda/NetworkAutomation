import threading
import os
import tempfile
from netmiko import ConnectHandler
from datetime import datetime
import uuid
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

def enable_ospf(tmp_file, ospf_file, vars_array):
    fin = open(ospf_file, "rt")
    fout = open(tmp_file, "wt")
    for line in fin:
        line_copy = line
        if 'process_id' in line:
            line_copy = line.replace('process_id', vars_array[0])
        if 'ip_address' in line:
            line_copy = line.replace('ip_address', vars_array[1])
        if 'wildcard_mask' in line:
            line_copy = line.replace('wildcard_mask', vars_array[2])
        if 'area_id' in line:
            line_copy = line.replace('area_id', vars_array[3])
        fout.write(line_copy)

    fin.close()
    fout.close()

def interface_parameters(tmp_file,ospf_file, vars_array):
    fin = open(ospf_file, "rt")
    fout = open(tmp_file, "wt")
    for line in fin:
        line_copy = line
        if 'interface_number' in line:
            line_copy = line.replace('interface_number', vars_array[0])
        if 'cost_value' in line:
            line_copy = line.replace('cost_value', vars_array[1])
        if 'retransmit_seconds' in line:
            line_copy = line.replace('retransmit_seconds', vars_array[2])
        if 'transmit_seconds' in line:
            line_copy = line.replace('transmit_seconds', vars_array[3])
        if 'number_value' in line:
            line_copy = line.replace('number_value', vars_array[4])
        if 'hello_seconds' in line:
            line_copy = line.replace('hello_seconds', vars_array[5])
        if 'dead_seconds' in line:
            line_copy = line.replace('dead_seconds', vars_array[6])
        if 'auth_key' in line:
            line_copy = line.replace('auth_key', vars_array[7])
        if 'key_id' in line:
            line_copy = line.replace('key_id', vars_array[8])
        if 'md5_key' in line:
            line_copy = line.replace('md5_key', vars_array[9])
        if 'message_digest_or_null' in line:
            line_copy = line.replace('message_digest_or_null', vars_array[10])
        fout.write(line_copy)

    fin.close()
    fout.close()

def point_to_multipoint(tmp_file, ospf_file, vars_array):
    fin = open(ospf_file, "rt")
    fout = open(tmp_file, "wt")
    for line in fin:
        line_copy = line
        if 'number' in line:
            line_copy = line.replace('number', vars_array[1])
        if 'process_id' in line:
            line_copy = line.replace('process_id', vars_array[2])
        if 'ip_address' in line:
            more_lines = line
            array_index = 30
            break
        fout.write(line_copy)

    left_indexes = (len(vars_array) - 3)/2

    for i in left_indexes:
        line_copy = more_lines
        line_copy = line_copy.replace('ip_address', vars_array[array_index])
        line_copy = line_copy.replace('cost_value', vars_array[array_index+1])
        fout.write(line_copy)
        array_index += 1

    fin.close()
    fout.close()

def area_parameters(tmp_file, ospf_file, vars_array):
    fin = open(ospf_file, "rt")
    fout = open(tmp_file, "wt")
    for line in fin:
        line_copy = line
        if 'process_id' in line:
            line_copy = line.replace('process_id', vars_array[0])
        if 'area_id' in line:
            line_copy = line.replace('area_id', vars_array[1])
        if 'cost_value' in line:
            line_copy = line.replace('cost_value', vars_array[2])
        fout.write(line_copy)

    fin.close()
    fout.close()

def nssa_abr_as_a_forced_nssa_translator(tmp_file, ospf_file, vars_array):
    fin = open(ospf_file, "rt")
    fout = open(tmp_file, "wt")
    for line in fin:
        line_copy = line
        if 'process_id' in line:
            line_copy = line.replace('process_id', vars_array[0])
        if 'area_id' in line:
            line_copy = line.replace('area_id', vars_array[1])
        fout.write(line_copy)

    fin.close()
    fout.close()

def rfc_1587(tmp_file, ospf_file, vars_array):
    fin = open(ospf_file, "rt")
    fout = open(tmp_file, "wt")
    for line in fin:
        line_copy = line
        if 'process_id' in line:
            line_copy = line.replace('process_id', vars_array[0])
        fout.write(line_copy)

    fin.close()
    fout.close()

def generating_default_route(tmp_file, ospf_file, vars_array):
    fin = open(ospf_file, "rt")
    fout = open(tmp_file, "wt")
    for line in fin:
        line_copy = line
        if 'process_id' in line:
            line_copy = line.replace('process_id', vars_array[0])
        fout.write(line_copy)

    fin.close()
    fout.close()

def configure_lookup_of_dns_names(tmp_file, ospf_file, vars_array):
    fin = open(ospf_file, "rt")
    fout = open(tmp_file, "wt")
    for line in fin:
        line_copy = line
        fout.write(line_copy)

    fin.close()
    fout.close()

def controlling_default_metrics(tmp_file, ospf_file, vars_array):
    fin = open(ospf_file, "rt")
    fout = open(tmp_file, "wt")
    for line in fin:
        line_copy = line
        if 'process_id' in line:
            line_copy = line.replace('process_id', vars_array[0])
        if 'ref_bw' in line:
            line_copy = line.replace('ref_bw', vars_array[1])
        fout.write(line_copy)

    fin.close()
    fout.close()

def changing_ospf_administrative_distances(tmp_file, ospf_file, vars_array):
    fin = open(ospf_file, "rt")
    fout = open(tmp_file, "wt")
    for line in fin:
        line_copy = line
        if 'process_id' in line:
            line_copy = line.replace('process_id', vars_array[0])
        if 'area_type' in line:
            line_copy = line.replace('area_type', vars_array[1])
        if 'dist_value' in line:
            line_copy = line.replace('dist_value', vars_array[2])
        fout.write(line_copy)

    fin.close()
    fout.close()

def configure_route_calculation_timers(tmp_file, ospf_file, vars_array):
    fin = open(ospf_file, "rt")
    fout = open(tmp_file, "wt")
    for line in fin:
        line_copy = line
        if 'process_id' in line:
            line_copy = line.replace('process_id', vars_array[0])
        if 'spf_start' in line:
            line_copy = line.replace('spf_start', vars_array[1])
        if 'spf_hold' in line:
            line_copy = line.replace('spf_hold', vars_array[2])
        if 'spf_max_wait' in line:
            line_copy = line.replace('spf_max_wait', vars_array[3])
        fout.write(line_copy)

    fin.close()
    fout.close()

def configure_ospf_over_on_demand_circuits(tmp_file, ospf_file, vars_array):
    fin = open(ospf_file, "rt")
    fout = open(tmp_file, "wt")
    for line in fin:
        line_copy = line
        if 'process_id' in line:
            line_copy = line.replace('process_id', vars_array[0])
        if 'number' in line:
            line_copy = line.replace('number', vars_array[1])
        fout.write(line_copy)

    fin.close()
    fout.close()

def changing_the_lsa_group_pacing_interval(tmp_file, ospf_file, vars_array):
    fin = open(ospf_file, "rt")
    fout = open(tmp_file, "wt")
    for line in fin:
        line_copy = line
        if 'process_id' in line:
            line_copy = line.replace('process_id', vars_array[0])
        if 'seconds' in line:
            line_copy = line.replace('seconds', vars_array[1])
        fout.write(line_copy)

    fin.close()
    fout.close()

def blocking_ospf_lsa_flooding(tmp_file, ospf_file, vars_array):
    fin = open(ospf_file, "rt")
    fout = open(tmp_file, "wt")
    for line in fin:
        line_copy = line
        if 'number' in line:
            line_copy = line.replace('number', vars_array[0])
        fout.write(line_copy)

    fin.close()
    fout.close()

def blocking_ospf_lsa_flooding_point_to_multipoint(tmp_file, ospf_file, vars_array):
    fin = open(ospf_file, "rt")
    fout = open(tmp_file, "wt")
    for line in fin:
        line_copy = line
        if 'process_id' in line:
            line_copy = line.replace('process_id', vars_array[0])
        if 'ip_address' in line:
            line_copy = line.replace('ip_address', vars_array[1])
        fout.write(line_copy)

    fin.close()
    fout.close()

def reducing_lsa_flooding(tmp_file, ospf_file, vars_array):
    fin = open(ospf_file, "rt")
    fout = open(tmp_file, "wt")
    for line in fin:
        line_copy = line
        if 'number' in line:
            line_copy = line.replace('number', vars_array[0])
        fout.write(line_copy)

    fin.close()
    fout.close()

def check_ospf_type(tmp_file, ospf_file, vars_array):
    os.path.join(ROOT_DIR, 'ospf_files/enable_ospf')
    if ospf_file == os.path.join(ROOT_DIR, 'ospf_files/enable_ospf'):
        enable_ospf(tmp_file, ospf_file, vars_array)
        return 1
    if ospf_file == os.path.join(ROOT_DIR, 'ospf_files/interface_parameters'):
        interface_parameters(tmp_file, ospf_file, vars_array)
        return 1
    if ospf_file == os.path.join(ROOT_DIR, 'ospf_files/point_to_multipoint_broadcast'):
        point_to_multipoint(tmp_file, ospf_file, vars_array)
        return 1
    if ospf_file == os.path.join(ROOT_DIR, 'ospf_files/point_to_multipoint_nonbroadcast'):
        point_to_multipoint(tmp_file, ospf_file, vars_array)
        return 1
    if ospf_file == os.path.join(ROOT_DIR, 'ospf_files/area_parameters'):
        area_parameters(tmp_file, ospf_file, vars_array)
        return 1
    if ospf_file == os.path.join(ROOT_DIR, 'ospf_files/nssa_abr_as_a_forced_nssa_translator'):
        nssa_abr_as_a_forced_nssa_translator(tmp_file, ospf_file,vars_array)
        return 1
    if ospf_file == os.path.join(ROOT_DIR, 'ospf_files/rfc_1587'):
        rfc_1587(tmp_file, ospf_file, vars_array)
        return 1
    if ospf_file == os.path.join(ROOT_DIR, 'ospf_files/generating_default_route'):
        generating_default_route(tmp_file, ospf_file, vars_array)
        return 1
    if ospf_file == os.path.join(ROOT_DIR, 'ospf_files/configure_lookup_of_dns_names'):
        configure_lookup_of_dns_names(tmp_file, ospf_file, vars_array)
        return 1
    if ospf_file == os.path.join(ROOT_DIR, 'ospf_files/controlling_default_metrics'):
        controlling_default_metrics(tmp_file, ospf_file, vars_array)
        return 1
    if ospf_file == os.path.join(ROOT_DIR, 'ospf_files/changing_ospf_administrative_distances'):
        changing_ospf_administrative_distances(tmp_file, ospf_file, vars_array)
        return 1
    if ospf_file == os.path.join(ROOT_DIR, 'ospf_files/configure_route_calculation_timers'):
        configure_route_calculation_timers(tmp_file, ospf_file, vars_array)
        return 1
    if ospf_file == os.path.join(ROOT_DIR, 'ospf_files/configure_ospf_over_on_demand_circuits'):
        configure_ospf_over_on_demand_circuits(tmp_file, ospf_file, vars_array)
        return 1
    if ospf_file == os.path.join(ROOT_DIR, 'ospf_files/changing_the_lsa_group_pacing_interval'):
        changing_the_lsa_group_pacing_interval(tmp_file, ospf_file, vars_array)
        return 1
    if ospf_file == os.path.join(ROOT_DIR, 'ospf_files/blocking_ospf_lsa_flooding'):
        blocking_ospf_lsa_flooding(tmp_file, ospf_file, vars_array)
        return 1
    if ospf_file == os.path.join(ROOT_DIR, 'ospf_files/reducing_lsa_flooding'):
        reducing_lsa_flooding(tmp_file, ospf_file, vars_array)
        return 1

    return 0

def ospf(device, ospf_file, vars_array, tmp_file):
    connection = ConnectHandler(**device)

    print('Entering enable mode...')
    connection.enable()

    # create a temporary file to create the config
    if check_ospf_type(tmp_file, ospf_file, vars_array) != 0:
        print('Sending commands from file...')
        connection.send_config_from_file(tmp_file)


    print('Closing connection...')
    connection.disconnect()


def do_ospf(devices, os_type, username, password, enable, config_type, vars_array):
    if os_type == 'ios':
        os_type = 'cisco_ios'

    for ip in devices:
        cisco_device = {
            'device_type': os_type,
            'host': ip,
            'username': username,
            'password': password,
            'port': 22,  # optional, default 22
            'secret': enable,  # this is the enable password
            'verbose': True  # optional, default False
        }
        # vars_array = ['1', '0.0.0.0', '0.0.0.0', '0']

        configuration = os.path.join(ROOT_DIR, 'ospf_files/' + config_type)

        tmp_file = str(uuid.uuid4())
        try:
            ospf(cisco_device, configuration, vars_array, tmp_file)
        except ConnectionRefusedError as err:
            return f"Connection Refused: {err}"
        except TimeoutError as err:
            return f"Connection Refused: {err}"
        except Exception as err:
            return f"Oops! {err}"

        path = tmp_file
        CONFIG_PATH = os.path.join(ROOT_DIR, path)
        os.remove(path)

    return "Successful config!"



