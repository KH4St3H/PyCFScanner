import os
import sys
import argparse

from pathlib import Path


config_data = {}
threads = 8

parser = argparse.ArgumentParser(
    prog = 'CFScanner',
    description = 'Find working cloudflare IP addresses for V2Ray clients',
    # epilog = 'Text at the bottom of help'
)

parser.add_argument('config', help='path to v2ray config file')
parser.add_argument('v2ray_path', help='path to v2ray core executable')
parser.add_argument('-t', '--threads', help='number of desired threads', default=8)

def fallback(msg):
    print(msg)
    sys.exit(1)

def parse_config(file_name):
    global config_data

    if not os.path.isfile(file_name):
        fallback('config file does not exist')

    with open(file_name, 'r') as file:
        for line in file.readlines():
            if line and ':' in line:
                config_data[line[:line.find(':')].strip()] = line[line.find(':')+1:].strip()
    if not all(key in config_data for key in ['id', 'Host', 'path', 'serverName']):
        fallback('config file format is incorrect')



def main():
    global threads
    args = parser.parse_args()
    parse_config(args.config)

    v2ray_path = Path(args.v2ray_path)
    if not v2ray_path.exists():
        fallback('v2ray executable does not exists')

    threads = args.threads

if __name__ == '__main__':
    main()