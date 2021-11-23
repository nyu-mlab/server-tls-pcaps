import json
import multiprocessing
import os
import random
import socket
import ssl
import subprocess
import sys
import time


PARALELL_COUNT = 20


def main():

    try:
        input_folder = sys.argv[1]
        output_pcap_folder = sys.argv[2]
    except IndexError:
        print('Wrong parameters. See README.')
        return

    mkdir(output_pcap_folder)

    print('Reading input data...')

    # A list of (port, hostname, output_pcap_folder)
    input_set = set()
    for filename in os.listdir(input_folder):
        filename = os.path.join(input_folder, filename)
        with open(filename) as fp:
            # We ignore the IP address below as we want to get the latest IP
            # depending on our geolocation
            for (_, port, hostname) in json.load(fp):
                if hostname:
                    input_set.add((port, hostname, output_pcap_folder))

    print('Scraping...')

    for _ in range(20):
        with multiprocessing.Pool(PARALELL_COUNT) as pool:
            input_list = list(input_set)
            random.shuffle(input_list)
            pool.map(get_pcap_using_dns, input_list)


def get_pcap_using_dns(arg_tuple):
    """Establishes TLS connection. Captures packets"""

    port, hostname, output_pcap_folder = arg_tuple

    # Resolve the hostname
    try:
        new_ip = socket.gethostbyname(hostname)
    except Exception:
        return

    # Each hostname will have its own directory
    pcap_dir = os.path.join(output_pcap_folder, hostname)
    mkdir(pcap_dir)

    # In this directory are pcap files captured at different times
    current_ts = int(time.time())
    pcap_filename = f'{current_ts}-{new_ip}-{port}-{hostname}.pcap'
    pcap_path = os.path.join(pcap_dir, pcap_filename)

    # # Read from cache
    # for existing_pcap_file in os.listdir(output_pcap_folder):
    #     try:
    #         # Match by port and hostname only, as the IP could change in the 2nd scrape
    #         (_, existing_port, existing_hostname) = existing_pcap_file.replace('.pcap', '').split('-')
    #     except:
    #         continue
    #     if existing_port == str(port) and existing_hostname == hostname:
    #         existing_pcap_file = os.path.join(output_pcap_folder, existing_pcap_file)
    #         if os.path.getsize(existing_pcap_file) >= 2000:
    #             # Already scraped and likely contains server cert, so ignore.
    #             print(f'Skipping pcap for {hostname}:{port}')
    #             return
            
    # Force TLS 1.2
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    source_port = random.randint(40000, 65000)

    # Start tcpdump
    proc = subprocess.Popen([
        '/usr/sbin/tcpdump', 
        '-i', 'eth0',        
        '-w', pcap_path,
        f'port {source_port} and host {new_ip}'
    ])

    time.sleep(2)

    # TLS Connection
    try:
        with socket.create_connection((new_ip, 443), timeout=20, source_address=('', source_port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.getpeercert()
    except Exception:
        return
    finally:
        time.sleep(2)
        proc.terminate()


def mkdir(path):

    subprocess.call(['mkdir', '-p', path])


if __name__ == '__main__':
    main()
