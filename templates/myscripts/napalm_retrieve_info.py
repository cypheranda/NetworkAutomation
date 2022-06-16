from napalm import get_network_driver
import json

def get_common_interfaces(devices, os_type, username, password, enable):
    if os_type == 'cisco_ios':
        os_type = 'ios'

    driver = get_network_driver(os_type)
    first = 0
    main_array = []

    for ip in devices:
        optional_args = {'secret': enable}
        ios = driver(ip, username, password, optional_args=optional_args)
        ios.open()

        output = ios.get_interfaces()
        dump = json.dumps(output, sort_keys=True, indent=4)
        loads = json.loads(dump)

        ios.close()
        keys = loads.keys()
        final_array = []
        if first == 0:
            main_array = keys
            first = 1
            if len(devices) == 1:
                return main_array
        elif first == 1:
            for item in main_array:
                isin_both = 0
                for item2 in keys:
                    if item == item2:
                        isin_both = 1
                if isin_both == 1:
                    final_array.append(item)

    # for item in final_array:
    #     print(item)
    return final_array

def check_interface(main_interface, devices, os_type, username, password, enable):
    found = 0
    try:
        interfaces = get_common_interfaces(devices, os_type, username, password, enable)
        for interface in interfaces:
            if main_interface == interface:
                found = 1
    except ConnectionRefusedError as err:
        return f"Connection Refused: {err}"
    except TimeoutError as err:
        return f"Connection Refused: {err}"
    except Exception as err:
        return f"Oops! {err}"

    return found

# get_common_interfaces(['192.168.204.17', '192.168.204.16'], 'ios', 'admin', 'cisco', 'parola')