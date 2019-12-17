#!/usr/bin/env python3
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from distutils.util import strtobool
import requests
import base64
import binascii
import argparse
import copy
import json
import random
import os
import sys
import logging
import configparser
import socket
import xml.etree.ElementTree as ET

def aes_decrypt(data, key):
    iv = bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(data)

def encrypt(values, key):
    # add two random bytes in front of the body
    data = 'AA' + json.dumps(values)
    data = pad(bytearray(data, 'ascii'), 16, style='pkcs7')
    iv = bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data_enc = cipher.encrypt(data)
    return base64.b64encode(data_enc)

def decrypt(data, key):
    payload = base64.b64decode(data)
    data = aes_decrypt(payload, key)
    # response starts with 2 random bytes, exclude them
    response = unpad(data, 16, style='pkcs7')[2:]
    return response.decode('ascii')

class AirClient(object):

    options = {
        'pwr':   { 'desc': 'Power',
                   'values': {'0': 'off', '1': 'on'} },
        'pm25':  { 'desc': 'PM2.5',
                   'unit': ' µg/m³' },
        'rh':    { 'desc': 'Humidity',
                   'unit': '%' },
        'rhset': { 'desc': 'Target humidity',
                   'unit': '%' },
        'iaql':  { 'desc': 'Indoor allergen index'},
        'temp':  { 'desc': 'Temperature',
                   'unit': ' °C' },
        'func':  { 'desc': 'Function',
                   'values': {'P': 'purification', 'PH': 'purification & humidification'} },
        'mode':  { 'desc': 'Mode',
                   'values': {'P': 'auto', 'A': 'allergen', 'S': 'sleep', 'M': 'manual', 'B': 'bacteria', 'N': 'night'} },
        'om':    { 'desc': 'Fan speed',
                   'values': {'s': 'silent', 't': 'turbo'} },
        'aqil':  { 'desc': 'Air quality index light',
                   'unit': '%' },
        'aqit':  { 'desc': 'Air quality index threshold'},
        'uil':   { 'desc': 'User interface light',
                   'values': {'0': 'off', '1': 'on'} },
        'ddp':   { 'desc': 'Displayed indicator',
                   'values': {'0': 'indoor allergen index', '1': 'PM2.5', '3': 'humidity'} },
        'wl':    { 'desc': 'Water level',
                   'unit': '%' },
        'cl':    { 'desc': 'Child lock' },
        'dt':    { 'desc': 'Timer',
                   'values': {0: 'off'},
                   'unit': ' hour(s)' },
        'dtrs':  { 'desc': 'Timer remaining',
                   'unit': ' minute(s)' },
        'err':   { 'desc': 'Error',
                   'values': {0: 'none', 49408: 'no water', 32768: 'water tank open', 49155: 'pre-filter must be cleaned'} }
    }

    @staticmethod
    def ssdp(timeout=1, repeats=3, debug=False):
        addr = '239.255.255.250'
        port = 1900
        msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            f'HOST: {addr}:{port}',
            'ST: urn:philips-com:device:DiProduct:1',
            'MX: 1', 'MAN: "ssdp:discover"','', '']).encode('ascii')
        urls = {}
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_TTL, 20)
            s.settimeout(timeout)
            for i in range(repeats):
                s.sendto(msg, (addr, port))
                try:
                    while True:
                        data, (ip, _) = s.recvfrom(1024)
                        url = next((x for x in data.decode('ascii').splitlines() if x.startswith('LOCATION: ')), None)
                        urls.update({ip: url[10:]})
                except socket.timeout:
                    pass
                if len(urls): break
        resp = []
        for ip in urls.keys():
            response = requests.get(urls[ip])
            if response.status_code == requests.codes.ok:
                xml = ET.fromstring(response.text)
                resp.append({'ip': ip})
                ns = {'urn': 'urn:schemas-upnp-org:device-1-0'}
                for d in xml.findall('urn:device', ns):
                    for t in ['modelName', 'modelNumber', 'friendlyName']:
                        resp[-1].update({t: d.find('urn:'+t, ns).text})
        logging.debug(resp)
        return resp

    def __init__(self, host):
        self._host = host
        self._session_key = None
        self._load_key()
        if not self._session_key:
            self._get_key()
        resp = self._get('1/device')
        self.name = resp['name']
        self.type = resp['type']
        self.model = resp['modelid']
        self.software = resp['swversion']

    def _get_key(self):

        G = int('A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5', 16)
        P = int('B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371', 16)

        print('Exchanging secret key with the device ...')
        a = random.getrandbits(256)
        A = pow(G, a, P)
        data = json.dumps({'diffie': format(A, 'x')})
        data_enc = data.encode('ascii')
        dh = self._put('0/security', data_enc)
        key = dh['key']
        B = int(dh['hellman'], 16)
        s = pow(B, a, P)
        s_bytes = s.to_bytes(128, byteorder='big')[:16]
        session_key = aes_decrypt(bytes.fromhex(key), s_bytes)
        self._session_key = session_key[:16]
        self._save_key()

    def _save_key(self):
        config = configparser.ConfigParser()
        fpath = os.path.expanduser('~/.pyairctrl')
        config.read(fpath)
        if 'keys' not in config.sections():
            config['keys'] = {}
        hex_key = binascii.hexlify(self._session_key).decode('ascii')
        config['keys'][self._host] = hex_key
        print(f'Saving session_key {hex_key} to {fpath}')
        with open(fpath, 'w') as f:
            config.write(f)

    def _load_key(self):
        fpath = os.path.expanduser('~/.pyairctrl')
        if os.path.isfile(fpath):
            config = configparser.ConfigParser()
            config.read(fpath)
            if 'keys' in config and self._host in config['keys']:
                hex_key = config['keys'][self._host]
                self._session_key = bytes.fromhex(hex_key)

    def set_values(self, values, debug=False):
        status = self._put('1/air', values, encrypted=True)
        self._dump_status(status, debug=debug)

    def set_wifi(self, ssid, pwd):
        values = {}
        if ssid:
            values['ssid'] = ssid
        if pwd:
            values['password'] = pwd
        logging.debug(values)
        wifi = self._put('0/wifi', values, encrypted=True)
        logging.debug(wifi)

    def _get_once(self, endpoint):
        response = requests.get(f'http://{self._host}/di/v1/products/{endpoint}')
        response.raise_for_status()
        resp = decrypt(response.text, self._session_key)
        return json.loads(resp)

    def _get(self, endpoint):
        try:
            return self._get_once(endpoint)
        except Exception as e:
            print(f'Cannot read from device: {type(e).__name__}: {e}')
        print('Will retry after getting a new key ...')
        self._get_key()
        return self._get_once(endpoint)

    def _put(self, endpoint, body, encrypted=False):
        if encrypted:
            body = encrypt(body, self._session_key)
        url = f'http://{self._host}/di/v1/products/{endpoint}'
        response = requests.put(url, body)
        response.raise_for_status()
        if response.status_code == 255 and len(response.text) == 1:
            raise ValueError('An option not supported by device')
        resp = response.text
        if encrypted:
            resp = decrypt(resp, self._session_key)
        return json.loads(resp)

    def _dump_status(self, status, debug=False):
        logging.debug(status)
        for opt, val in status.items():
            opt_def = self.options.get(opt, None)
            if opt_def:
                val_str = opt_def.get('values',{}).get(val, val)
                unit = opt_def.get('unit','') if isinstance(val_str, int) else ''
                print(f'[{opt:5}] {opt_def["desc"]}: {val_str}{unit}')
            else:
                print(f'[{opt:5}] unknown: {val}')

    def get_status(self, debug=False):
        status = self._get('1/air')
        self._dump_status(status, debug=debug)

    def get_wifi(self):
        wifi = self._get('0/wifi')
        print(wifi)

    def get_firmware(self):
        firmware = self._get('0/firmware')
        print(firmware)

    # endpoint '1/userinfo' ?

    def get_filters(self):
        filters = self._get('1/fltsts')
        print(f'Pre-filter and Wick: clean in {filters["fltsts0"]} hours')
        if 'wicksts' in filters:
            print(f'Wick filter: replace in {filters["wicksts"]} hours')
        print(f'Active carbon filter: replace in {filters["fltsts2"]} hours')
        print(f'HEPA filter: replace in {filters["fltsts1"]} hours')

    def pair(self, client_id, client_secret):
        values = {'Pair': ['FI-AIR-AND', client_id, client_secret] }
        resp = self._put('0/pairing', values, encrypted=True)
        print(resp)


def main():
    parser = argparse.ArgumentParser()
    parser.register('type', 'bool', (lambda x: bool(strtobool(x))))
    parser.add_argument('--ipaddr', help='IP address of air purifier', action='append')
    parser.add_argument('-d', '--debug', help='show debug output', action='store_true')
    parser.add_argument('--om', help='set fan speed', choices=['1','2','3','s','t'])
    parser.add_argument('--pwr', help='power on/off', choices=['0','1'])
    parser.add_argument('--mode', help='set mode', choices=['P','A','S','M','B','N'])
    parser.add_argument('--rhset', help='set target humidity', choices=[40, 50, 60, 70], type=int)
    parser.add_argument('--func', help='set function', choices=['P','PH'])
    parser.add_argument('--aqil', help='set light brightness', choices=[0, 25, 50, 75, 100], type=int)
    parser.add_argument('--aqit', help='set air quality index threshold', choices=[0, 1, 4, 7, 10], type=int)
    parser.add_argument('--uil', help='set button lights on/off', choices=['0','1'])
    parser.add_argument('--ddp', help='set indicator pm2.5/IAI/humidity', choices=['0','1','3'])
    parser.add_argument('--dt', help='set timer', choices=range(6), type=int)
    parser.add_argument('--cl', help='set child lock', choices=[True, False], type='bool')
    parser.add_argument('--wifi', help='read wifi options', action='store_true')
    parser.add_argument('--wifi-ssid', help='set wifi ssid')
    parser.add_argument('--wifi-pwd', help='set wifi password')
    parser.add_argument('--firmware', help='read firmware', action='store_true')
    parser.add_argument('--filters', help='read filters status', action='store_true')
    args = parser.parse_args()

    if args.ipaddr:
        devices = [ {'ip': ip} for ip in args.ipaddr ]
    else:
        devices = AirClient.ssdp(debug=args.debug)
        if not devices:
            print('Air purifier not autodetected. Try --ipaddr option to force specific IP address.')
            sys.exit(1)
    
    for device in devices:
        c = AirClient(device['ip'])
        print(f'{c.name}: (model {c.model}, IP {device["ip"]})')
        if args.wifi:
            c.get_wifi()
            sys.exit(0)
        if args.firmware:
            c.get_firmware()
            sys.exit(0)
        if args.wifi_ssid or args.wifi_pwd:
            c.set_wifi(args.wifi_ssid, args.wifi_pwd)
            sys.exit(0)
        if args.filters:
            c.get_filters()
            sys.exit(0)

        r_opts = ['ipaddr', 'debug', 'firmware', 'filters', 'wifi', 'wifi-ssid', 'wifi-pws']
        values = dict(filter(lambda x: x[1] != None and x[0] not in r_opts, vars(args).items()))

        if values:
            c.set_values(values, debug=args.debug)
        else:
            c.get_status(debug=args.debug)


if __name__ == '__main__':
    main()
