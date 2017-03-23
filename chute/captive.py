from __future__ import print_function

import os
import re
import subprocess
import threading
import time

import pyrad
import pyrad.client
import pyrad.dictionary
import pyrad.packet
import requests


ROUTER_ID = os.environ.get("PARADROP_ROUTER_ID", "000000000000000000000000")
SYSTEM_DIR = os.environ.get("PARADROP_SYSTEM_DIR", "/tmp")
BASE_URL = os.environ.get("PARADROP_BASE_URL", None)

RADIUS_SERVER = os.environ.get("CP_RADIUS_SERVER", None)
RADIUS_SECRET = os.environ.get("CP_RADIUS_SECRET", None)
RADIUS_USERNAME = os.environ.get("CP_RADIUS_USERNAME", None)
RADIUS_PASSWORD = os.environ.get("CP_RADIUS_PASSWORD", None)
RADIUS_NAS_ID = os.environ.get("CP_RADIUS_NAS_ID", ROUTER_ID)


LEASES_FILE = os.path.join(SYSTEM_DIR, "dnsmasq-wifi.leases")
LEASES_FILE_FIELDS = ["expiration", "mac", "ip", "name", "devid"]
INTERIM_UPDATE_INTERVAL = 60


def readLeasesFile():
    if not os.path.exists(LEASES_FILE):
        return

    with open(LEASES_FILE, "r") as source:
        for line in source:
            parts = line.split()
            yield dict(zip(LEASES_FILE_FIELDS, parts))


class IntervalTimer(threading.Thread):
    def __init__(self, interval, function, *args, **kwargs):
        super(IntervalTimer, self).__init__()
        self.interval = interval
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.finished = threading.Event()
        self.running = True

    def cancel(self):
        self.finished.set()

    def run(self):
        while True:
            self.finished.wait(self.interval)
            if self.finished.is_set():
                break
            else:
                self.function(*self.args, **self.kwargs)


class ClientTracker(object):
    def __init__(self, radclient):
        self.clients = dict()
        self.radclient = radclient
        self.next_session_id = 0
        self.timer = IntervalTimer(5, self.refresh)

        self.shared_fields = {
            'NAS-Identifier': RADIUS_NAS_ID,
            'NAS-Port-Type': "Wireless-802.11",
            'Called-Station-Id': ROUTER_ID
        }

    def refresh(self):
        new_macs = set()
        old_macs = set(self.clients.keys())

        for client in readLeasesFile():
            mac = client['mac']
            if mac not in self.clients:
                self.onConnect(client)
                self.clients[mac] = client
            new_macs.add(mac)

        for mac in (old_macs - new_macs):
            self.onDisconnect(self.clients[mac])
            del self.clients[mac]

        # Only do interim updates if we can get stats from paradrop daemon.
        if BASE_URL is not None:
            now = time.time()
            for client in self.clients.values():
                if client['next-update'] > now:
                    self.update(client)

    def start(self):
        request = self.radclient.CreateAcctPacket()
        for k, v in self.shared_fields.iteritems():
            request[k] = v
        request['Acct-Status-Type'] = "Accounting-On"

        reply = self.radclient.SendPacket(request)
        print("reply code: {}".format(reply.code))
        if reply.code == pyrad.packet.AccountingResponse:
            print("accepted")
        else:
            print("denied")
        for k in reply.keys():
            print("{}: {}".format(k, reply[k]))

        self.timer.start()

    def stop(self):
        self.timer.cancel()

        for client in self.clients.values():
            self.onDisconnect(client, "NAS-Reboot")

        request = self.radclient.CreateAcctPacket()
        for k, v in self.shared_fields.iteritems():
            request[k] = v
        request['Acct-Status-Type'] = "Accounting-Off"
        request['Acct-Terminate-Cause'] = "NAS-Reboot"

        reply = self.radclient.SendPacket(request)
        print("reply code: {}".format(reply.code))
        if reply.code == pyrad.packet.AccountingResponse:
            print("accepted")
        else:
            print("denied")
        for k in reply.keys():
            print("{}: {}".format(k, reply[k]))

    def update(self, client):
        url = "{}/networks/wifi/stations/{}".format(BASE_URL, client['mac'])
        request = requests.get(url)
        stats = request.json()

        request = self.radclient.CreateAcctPacket()
        for k, v in self.shared_fields.iteritems():
            request[k] = v

        request['Acct-Status-Type'] = "Interim-Update"
        request['Acct-Input-Packets'] = stats['rx_packets']
        request['Acct-Output-Packets'] = stats['tx_packets']
        request['Acct-Input-Octets'] = stats['rx_bytes']
        request['Acct-Output-Octets'] = stats['tx_bytes']

        reply = self.radclient.SendPacket(request)
        print("reply code: {}".format(reply.code))
        if reply.code == pyrad.packet.AccountingResponse:
            print("accepted")
        else:
            print("denied")
        for k in reply.keys():
            print("{}: {}".format(k, reply[k]))

        client['stats'] = stats
        client['next-update'] = time.time() + INTERIM_UPDATE_INTERVAL

    def onConnect(self, client):
        client['start'] = int(time.time())
        client['next-update'] = client['start'] + INTERIM_UPDATE_INTERVAL
        client['session'] = "{:08x}".format(self.next_session_id)
        self.next_session_id += 1

        request = self.radclient.CreateAuthPacket(
            code=pyrad.packet.AccessRequest, User_Name=RADIUS_USERNAME,
            NAS_Identifier=RADIUS_NAS_ID)
        request['User-Password'] = request.PwCrypt(RADIUS_PASSWORD)

        reply = self.radclient.SendPacket(request)
        print("reply code: {}".format(reply.code))
        if reply.code == pyrad.packet.AccessAccept:
            print("accepted")
        else:
            print("denied")
        for k in reply.keys():
            print("{}: {}".format(k, reply[k]))

        mac_upper = client['mac'].upper()
        mac_dashed = mac_upper.replace(':', '-')

        request = self.radclient.CreateAcctPacket(
            User_Name=RADIUS_USERNAME)
        for k, v in self.shared_fields.iteritems():
            request[k] = v

        request['Calling-Station-Id'] = mac_dashed
        request['Acct-Status-Type'] = "Start"
        request['Acct-Session-Id'] = client['session']

        reply = self.radclient.SendPacket(request)
        print("reply code: {}".format(reply.code))
        if reply.code == pyrad.packet.AccountingResponse:
            print("accepted")
        else:
            print("denied")
        for k in reply.keys():
            print("{}: {}".format(k, reply[k]))

    def onDisconnect(self, client, cause="User-Request"):
        client['stop'] = int(time.time())

        mac_upper = client['mac'].upper()
        mac_dashed = mac_upper.replace(':', '-')

        request = self.radclient.CreateAcctPacket(
            User_Name=RADIUS_USERNAME)
        for k, v in self.shared_fields.iteritems():
            request[k] = v
        request['Calling-Station-Id'] = mac_dashed
        request['Acct-Status-Type'] = "Stop"
        request['Acct-Terminate-Cause'] = cause
        request['Acct-Session-Id'] = client['session']
        request['Acct-Session-Time'] = client['stop'] - client['start']

        stats = client.get('stats', None)
        if stats is not None:
            request['Acct-Input-Packets'] = stats['rx_packets']
            request['Acct-Output-Packets'] = stats['tx_packets']
            request['Acct-Input-Octets'] = stats['rx_bytes']
            request['Acct-Output-Octets'] = stats['tx_bytes']

        reply = self.radclient.SendPacket(request)
        print("reply code: {}".format(reply.code))
        if reply.code == pyrad.packet.AccountingResponse:
            print("accepted")
        else:
            print("denied")
        for k in reply.keys():
            print("{}: {}".format(k, reply[k]))


def cleanIptables():
    pattern = re.compile(r"MAC\s+(\S+)\s+.*expires\s+(\d+)")
    now = int(time.time())
    expired = list()

    cmd = ["iptables", "-t", "mangle", "-L", "clients"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    for line in proc.stdout:
        match = pattern.match(line)
        if match is None:
            continue

        mac = match.group(1)
        expires = int(match.group(2))

        if expires >= now:
            expired.append((mac, expires))

    for mac, expires in expired:
        cmd = ["iptables", "-t", "mangle", "-D", "clients", "-m", "mac",
                "--mac-source", mac, "-m", "comment", "--comment",
                "expires {}".format(expires), "-j", "RETURN"]
        subprocess.call(cmd)


if __name__ == "__main__":
    # If RADIUS_SERVER is defined, then set up the client tracker for
    # authentication and accounting.
    if RADIUS_SERVER is not None:
        client = pyrad.client.Client(server=RADIUS_SERVER,
                secret=RADIUS_SECRET,
                dict=pyrad.dictionary.Dictionary("radius-defs"))
        tracker = ClientTracker(client)
        tracker.start()

    try:
        while True:
            time.sleep(60)
            cleanIptables()
    except KeyboardInterrupt:
        pass

    if RADIUS_SERVER is not None:
        tracker.stop()
