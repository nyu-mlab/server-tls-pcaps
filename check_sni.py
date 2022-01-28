"""
Example Usage:

root@mlab-dev:~/dev/server-tls-pcaps/output-pcap-new-york-2021-12-21# find . | grep pcap | python3 check_sni.py  | tee /tmp/blah

"""


import sys
import subprocess


def main():

    for line in sys.stdin:
        parse_line(line.strip())


def parse_line(pcap_filename):

    if not pcap_filename.endswith('.pcap'):
        return
    file_sni = pcap_filename.split('-')[-1].replace('.pcap', '').lower().strip()
    pcap_sni = get_sni_from_pcap(pcap_filename)

    if file_sni != pcap_sni:
        print(f'Mismatch: {file_sni} <> {pcap_sni}')


def get_sni_from_pcap(pcap_file):

    p = subprocess.Popen(
        ['tshark', '-r', pcap_file, '-T', 'fields', '-e', 'tls.handshake.extensions_server_name'], 
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.communicate()[0].strip().lower().decode('utf-8')


if __name__ == '__main__':
    main()