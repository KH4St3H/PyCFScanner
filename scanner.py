# Author: Mehrshad
# Usage: python .\scanner.py .\config_file C:\Path\to\nekoray_core.exe
# dependecies: pysocks, requests
# original bash code: https://github.com/MortezaBashsiz/CFScanner

import os
import re
import sys
import argparse
import requests
import subprocess
import datetime
import time

from ipaddress import IPv4Network
from multiprocessing.pool import ThreadPool


subnet_list = set()
v2ray_path = ''
result_name = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M_result.txt')
config_data = {}
threads = 8

cloudflare_ASNs = ['AS209242']
cloudflare_ok_list = [31, 45, 66, 80, 89, 103, 104, 108, 141, 
    147, 154, 159, 168, 170, 185, 188, 191, 
    192, 193, 194, 195, 199, 203, 205, 212]
parser = argparse.ArgumentParser(
    prog = 'CFScanner',
    description = 'Find working cloudflare IP addresses for V2Ray clients',
    # epilog = 'Text at the bottom of help'
)

parser.add_argument('config', help='path to v2ray config file')
parser.add_argument('v2ray_path', help='path to v2ray core executable')
parser.add_argument('-t', '--threads', help='number of desired threads', default=8)

if not os.path.isdir('configs'):
    os.mkdir('configs')
if not os.path.isdir('result'):
    os.mkdir('result')

def fallback(msg):
    print(msg)
    sys.exit(1)

def check_ip(ip):
    ip = str(ip)
    try:
        result = subprocess.check_output('curl -s -w "%{http_code}" --tlsv1.2 -m 2 -servername fronting.sudoer.net -H "Host: fronting.sudoer.net" --resolve fronting.sudoer.net:443:"' + ip + '" https://fronting.sudoer.net', shell=True, timeout=2)
    except Exception:
        print(ip, 'failed')
        return False
    if b'200' not in result:
        print(ip, 'failed')
        return False
    
    with open('config.json.temp', 'r') as config_template:
        config = str(config_template.read())
        port = '3'+str(sum(map(int, ip.split('.'))))
        config = config.replace('IP.IP.IP.IP', ip).replace('PORTPORT', port).replace('IDID', config_data['id'])
        config = config.replace('HOSTHOST', config_data['Host'])
        config = config.replace('CFPORTCFPORT', config_data['Port'])
        config = config.replace('ENDPOINTENDPOINT', config_data['path'])
        config = config.replace('RANDOMHOST', config_data['serverName'])
        with open(f'configs/{ip}.config.json', 'w') as new_config:
            new_config.write(config)
    ps = subprocess.Popen([v2ray_path, 'run', '-c', f'configs/{ip}.config.json'], stdout=subprocess.DEVNULL)
    try:
        t = time.time()
        result = requests.get('https://scan.sudoer.net', proxies={'https': f'socks5://127.0.0.1:'+port}, timeout=2)
        ps.kill()
        print(ip,':',1000*(time.time()-t), 'ms')
        with open(f'result/{result_name}', 'a') as f:
            f.write(f'{1000*(time.time()-t):.2f} {ip}\n')

    except Exception as e:
        ps.kill()
        print(ip, 'failed (timeout)') 
        return False


def get_CIDRs():
    global subnet_list
    with open('cf.local.iplist', 'r') as file:
        subnet_list = {i.strip('\n') for i in file.readlines()}
    for ASN in cloudflare_ASNs:
        try:
            result = requests.get(f'https://asnlookup.com/asn/{ASN}/')
            if result.status_code == 200:
                subnet_list.update(re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})', result.text))
            else:
                print('[*] asnlookup.com returned a code other than 200')
                continue
        except Exception as e:
            print('[*] error retrieving asnlookup.com')
            continue

def find_working_ips():
    for subnet in subnet_list:
        if int(subnet[:subnet.find('.')]) not in cloudflare_ok_list:
            continue
        with ThreadPool(threads) as pool:
            for result in pool.map(check_ip, list(IPv4Network(subnet))):
                print(result)


def parse_config(file_name):
    global config_data

    if not os.path.isfile(file_name):
        fallback('config file does not exist')

    with open(file_name, 'r') as file:
        for line in file.readlines():
            if line and ':' in line:
                config_data[line[:line.find(':')].strip()] = line[line.find(':')+1:].strip()
    if not all(key in config_data for key in ['id', 'Host', 'Port', 'path', 'serverName']):
        fallback('config file format is incorrect')

def main():
    global threads, v2ray_path
    args = parser.parse_args()
    parse_config(args.config)

    v2ray_path = args.v2ray_path
    if not os.path.exists(v2ray_path):
        fallback('v2ray executable does not exists')

    threads = int(args.threads)

    get_CIDRs()
    find_working_ips()

if __name__ == '__main__':
    main()