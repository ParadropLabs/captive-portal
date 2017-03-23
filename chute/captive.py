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


ROUTER_ID = os.environ.get("PARADROP_ROUTER_ID", "000000000000000000000000")
DATA_DIR = os.environ.get("PARADROP_DATA_DIR", "/tmp")

RADIUS_SERVER = os.environ.get("CP_RADIUS_SERVER", "localhost")
RADIUS_SECRET = os.environ.get("CP_RADIUS_SECRET", "super-secret")
RADIUS_USERNAME = os.environ.get("CP_RADIUS_USERNAME", "lance")
RADIUS_PASSWORD = os.environ.get("CP_RADIUS_PASSWORD", "password")
RADIUS_NAS_ID = os.environ.get("CP_RADIUS_NAS_ID", "localhost")


LEASES_FILE = os.path.join(DATA_DIR, "dnsmasq-wifi.leases")
LEASES_FILE_FIELDS = ["expiration", "mac", "ip", "name", "devid"]


def readLeasesFile():
    if not os.path.exists(LEASES_FILE):
        return

    with open(LEASES_FILE, "r") as source:
        for line in source:
            parts = line.split()
            client = dict(zip(LEASES_FILE_FIELDS, parts))
            yield client


class ClientTracker(object):
    def __init__(self, radclient):
        self.clients = dict()
        self.radclient = radclient
        self.next_session_id = 0

    def refresh(self):
        for client in readLeasesFile():
            mac = client['mac']
            print(mac)
            if mac not in self.clients:
                self.onConnect(client)
                self.clients[mac] = client

    def onConnect(self, client):
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
        request['NAS-Identifier'] = RADIUS_NAS_ID
        request['NAS-Port-Type'] = "Wireless-802.11"
        request['Called-Station-Id'] = ROUTER_ID
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
    client = pyrad.client.Client(server=RADIUS_SERVER, secret=RADIUS_SECRET,
             dict=pyrad.dictionary.Dictionary("radius-defs"))

    tracker = ClientTracker(client)

    timers = []
    timers.append(threading.Timer(5.0, tracker.refresh))
    timers.append(threading.Timer(60.0, cleanIptables))
    for t in timers:
        t.start()

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        for t in timers:
            t.cancel()
