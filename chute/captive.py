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
API_TOKEN = os.environ.get("PARADROP_API_TOKEN", None)

RADIUS_SERVER = os.environ.get("CP_RADIUS_SERVER", "")
RADIUS_SECRET = os.environ.get("CP_RADIUS_SECRET", "")
RADIUS_USERNAME = os.environ.get("CP_RADIUS_USERNAME", "")
RADIUS_PASSWORD = os.environ.get("CP_RADIUS_PASSWORD", "")
RADIUS_NAS_ID = os.environ.get("CP_RADIUS_NAS_ID", ROUTER_ID)

AUTH_URL = os.environ.get("CP_AUTH_URL", "https://cp-api.5nines.com/v1.12")
EXPIRATION = float(os.environ.get("CP_EXPIRATION", 3600))
LOCATION = os.environ.get("CP_LOCATION", 0)

LEASES_FILE = os.path.join(SYSTEM_DIR, "dnsmasq-wifi.leases")
LEASES_FILE_FIELDS = ["expiration", "mac_addr", "ip_addr", "name", "devid"]

CLIENT_UPDATE_INTERVAL = 5
INTERIM_UPDATE_INTERVAL = 60
IPTABLES_CLEAN_INTERVAL = 60

IPTABLES_CHAIN = "clients"
IPTABLES_TARGET = "ACCEPT"


# If BASE_URL is None, we are running on a version of ParaDrop that does
# not support this API, so fall back to using the leases file.
USE_API = (BASE_URL is not None)

# Enabled sending data to RADIUS server if the environment variable is set.
ENABLE_RADIUS = (len(RADIUS_SERVER) > 0)


def timestamp():
    """ Return an integer timestamp. """
    return int(time.time())


def readClients():
    global USE_API

    if USE_API:
        url = "{}/networks/wifi/stations".format(BASE_URL)
        headers = {}
        if API_TOKEN is not None:
            headers['Authorization'] = "Bearer " + API_TOKEN
        request = requests.get(url, headers=headers)
        if request.status_code == 200:
            results = request.json()
            for client in results:
                yield client
            return
        else:
            # We may get a 401 if there is a problem passing the auth check.
            # In that case, fall back to using the leases file.
            print("Received {} from Paradrop daemon, falling back to leases file.".format(request.status_code))
            USE_API = False

    if not os.path.exists(LEASES_FILE):
        return

    with open(LEASES_FILE, "r") as source:
        for line in source:
            parts = line.split()
            yield dict(zip(LEASES_FILE_FIELDS, parts))


def evictDevice(mac):
    """
    Kick a device off the WiFi network.
    """
    url = "{}/networks/wifi/stations/{}".format(BASE_URL, mac)
    headers = {}
    if API_TOKEN is not None:
        headers['Authorization'] = "Bearer " + API_TOKEN
    request = requests.delete(url, headers=headers)


def is_allowed(mac):
    url = "{}/{}/{}".format(AUTH_URL, LOCATION, mac)
    req = requests.get(url)

    # Version 1.12 returns a simple string "1" or "0".
    contents = req.text.strip()
    if contents == "1":
        return True
    elif contents == "0":
        return False
    elif contents == "":
        return False

    # Version 1.2 returns JSON with integer auth values.
    data = req.json()
    if isinstance(data, list) and len(data) > 0:
        if data[0].get("auth", None) == 1:
            return True
        elif data[0].get("auth", None) == 0:
            return False

    # Default: be kind to the users.
    return True


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
    def __init__(self):
        self.clients = dict()
        self.timer = IntervalTimer(CLIENT_UPDATE_INTERVAL, self.refresh)
        self.listeners = {}

    def add_listener(self, event_name, listener):
        if event_name not in self.listeners:
            self.listeners[event_name] = []
        self.listeners[event_name].append(listener)

    def dispatch(self, event_name, *args, **kwargs):
        for listener in self.listeners.get(event_name, []):
            listener(*args, **kwargs)

    def refresh(self):
        """
        Refresh the current list of clients.

        Fetch a new list of connected clients and compare to the the old list
        to determine which clients are new and which have disconnected.  Then
        send the appropriate messages to the RADIUS server.
        """
        new_macs = set()
        old_macs = set(self.clients.keys())

        for client in readClients():
            mac = client['mac_addr']
            if mac in self.clients:
                self.clients[mac].update(client)
            else:
                self.dispatch("add-client", client)
                self.clients[mac] = client
                client['next-update'] = time.time() + INTERIM_UPDATE_INTERVAL
            new_macs.add(mac)

        for mac in (old_macs - new_macs):
            self.dispatch("remove-client", client)
            del self.clients[mac]

        # Only do interim updates if we can get stats from paradrop daemon.
        # Otherwise, all of the byte and packet counts are missing.
        if USE_API:
            now = time.time()
            for client in self.clients.values():
                if now > client['next-update']:
                    self.dispatch("update-client", client)
                    client['next-update'] = now + INTERIM_UPDATE_INTERVAL

    def start(self):
        """
        Start tracking clients.

        Start the IntervalTimer to periodically call the refresh function.
        """
        self.timer.start()

    def stop(self):
        """
        Stop tracking clients.

        Cancel the IntervalTimer that calls the refresh function.
        """
        self.timer.cancel()

        for client in self.clients.values():
            self.dispatch("remove-client", reason="NAS-Reboot")


class RadiusProducer(object):
    def __init__(self, radclient):
        self.radclient = radclient
        self.next_session_id = 0

        self.shared_fields = {
            'Called-Station-Id': ROUTER_ID,
            'NAS-Identifier': RADIUS_NAS_ID,
            'NAS-Port-Type': "Wireless-802.11"
        }

    def start(self):
        """
        Start accounting.

        Send an Accounting-On message to the RADIUS server.
        """
        request = self.radclient.CreateAcctPacket()
        for k, v in self.shared_fields.iteritems():
            request[k] = v
        request['Acct-Status-Type'] = "Accounting-On"
        request['Event-Timestamp'] = timestamp()

        reply = self.radclient.SendPacket(request)
        print("reply code: {}".format(reply.code))
        if reply.code == pyrad.packet.AccountingResponse:
            print("accepted")
        else:
            print("denied")
        for k in reply.keys():
            print("{}: {}".format(k, reply[k]))

    def stop(self):
        """
        Stop accounting.

        Send an Accounting-Off message to the RADIUS server.
        """
        request = self.radclient.CreateAcctPacket()
        for k, v in self.shared_fields.iteritems():
            request[k] = v
        request['Acct-Status-Type'] = "Accounting-Off"
        request['Acct-Terminate-Cause'] = "NAS-Reboot"
        request['Event-Timestamp'] = timestamp()

        reply = self.radclient.SendPacket(request)
        print("reply code: {}".format(reply.code))
        if reply.code == pyrad.packet.AccountingResponse:
            print("accepted")
        else:
            print("denied")
        for k in reply.keys():
            print("{}: {}".format(k, reply[k]))

    def update(self, client):
        """
        Send an accounting update message for a client.
        """
        request = self.radclient.CreateAcctPacket()
        for k, v in self.shared_fields.iteritems():
            request[k] = v

        request['Acct-Input-Octets'] = client['rx_bytes']
        request['Acct-Input-Packets'] = client['rx_packets']
        request['Acct-Output-Octets'] = client['tx_bytes']
        request['Acct-Output-Packets'] = client['tx_packets']
        request['Acct-Session-Id'] = client['session-id']
        request['Acct-Session-Time'] = timestamp() - client['start']
        request['Acct-Status-Type'] = "Interim-Update"
        request['Calling-Station-Id'] = client['station-id']
        request['Event-Timestamp'] = timestamp()
        request['User-Name'] = RADIUS_USERNAME

        reply = self.radclient.SendPacket(request)
        print("reply code: {}".format(reply.code))
        if reply.code == pyrad.packet.AccountingResponse:
            print("accepted")
        else:
            print("denied")
        for k in reply.keys():
            print("{}: {}".format(k, reply[k]))

    def onConnect(self, client):
        print("Connect: {}".format(client['mac_addr']))

        client['start'] = timestamp()
        client['session-id'] = "{:08x}".format(self.next_session_id)
        client['station-id'] = client['mac_addr'].upper().replace(':', '-')
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

        request = self.radclient.CreateAcctPacket()
        for k, v in self.shared_fields.iteritems():
            request[k] = v

        request['Acct-Session-Id'] = client['session-id']
        request['Acct-Status-Type'] = "Start"
        request['Calling-Station-Id'] = client['station-id']
        request['User-Name'] = RADIUS_USERNAME

        reply = self.radclient.SendPacket(request)
        print("reply code: {}".format(reply.code))
        if reply.code == pyrad.packet.AccountingResponse:
            print("accepted")
        else:
            print("denied")
        for k in reply.keys():
            print("{}: {}".format(k, reply[k]))

    def onDisconnect(self, client, cause="User-Request"):
        print("Disconnect: {}".format(client['mac_addr']))

        request = self.radclient.CreateAcctPacket()
        for k, v in self.shared_fields.iteritems():
            request[k] = v
        request['Acct-Session-Id'] = client['session-id']
        request['Acct-Session-Time'] = timestamp() - client['start']
        request['Acct-Status-Type'] = "Stop"
        request['Acct-Terminate-Cause'] = cause
        request['Calling-Station-Id'] = client['station-id']
        request['User-Name'] = RADIUS_USERNAME

        if USE_API:
            request['Acct-Input-Octets'] = client.get('rx_bytes', 0)
            request['Acct-Input-Packets'] = client.get('rx_packets', 0)
            request['Acct-Output-Octets'] = client.get('tx_bytes', 0)
            request['Acct-Output-Packets'] = client.get('tx_packets', 0)

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
    now = timestamp()
    expired = list()
    unexpired_macs = set()

    cmd = ["iptables", "-t", "mangle", "-L", "clients"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    for line in proc.stdout:
        match = pattern.search(line)
        if match is None:
            continue

        mac = match.group(1)
        expires = int(match.group(2))

        if now >= expires:
            print("Rule expiration: {}".format(mac))
            expired.append((mac, expires))
        else:
            unexpired_macs.add(mac)

    for mac, expires in expired:
        cmd = ["iptables", "-t", "mangle", "-D", IPTABLES_CHAIN, "-m", "mac",
                "--mac-source", mac, "-m", "comment", "--comment",
                "expires {}".format(expires), "-j", IPTABLES_TARGET]
        subprocess.call(cmd)

        if USE_API and mac not in unexpired_macs:
            # The last rule for this MAC address has expired, so kick it off
            # the network to force it to go through the process of reconnecting
            # and revisiting the landing page.
            evictDevice(mac)


def grant_access(mac):
    expires = int(time.time() + EXPIRATION)
    comment = "expires {}".format(expires)

    cmd = ["iptables", "--insert", IPTABLES_CHAIN, "--match", "mac",
            "--mac-source", mac, "--match", "comment", "--comment", comment,
            "--jump", IPTABLES_TARGET]
    subprocess.call(cmd)


def check_new_client(client):
    if is_allowed(client['mac_addr']):
        grant_access(client['mac_addr'])


if __name__ == "__main__":
    tracker = ClientTracker()
    tracker.start()
    tracker.add_listener("add-client", check_new_client)

    if ENABLE_RADIUS:
        client = pyrad.client.Client(server=RADIUS_SERVER,
                secret=RADIUS_SECRET,
                dict=pyrad.dictionary.Dictionary("radius-defs"))
        producer = RadiusProducer(client)
        producer.start()

        tracker.add_listener("add-client", producer.onConnect)
        tracker.add_listener("remove-client", producer.onDisconnect)
        tracker.add_listener("update-client", producer.update)

    try:
        while True:
            time.sleep(IPTABLES_CLEAN_INTERVAL)
            cleanIptables()
    except KeyboardInterrupt:
        pass

    tracker.stop()
    if ENABLE_RADIUS:
        producer.stop()
