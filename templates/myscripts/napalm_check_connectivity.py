from napalm import get_network_driver
import json
import sys

def check_connectivity(destination_address, host_address, loopback_address, secret, username, password):
    driver = get_network_driver('ios')

    optional_args = {'secret': secret}
    ios = driver(host_address, username, password, optional_args=optional_args)

    ios.open()

    output = ios.ping(destination=destination_address, count=2, source= loopback_address)
        # count=cate pachete sa trimit, host_address=1.1.1.1=adresa de loopback, pe care vreau sa o folosesc ca cea care trimite pingul
    ping = json.dumps(output, sort_keys=True, indent=4)

    ios.close()

    # check packet loss
    if '\"packet_loss\": 0' in ping:
        return 0
    else:
        return 1

