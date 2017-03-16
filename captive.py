import json
import os

import iptc
import treq
from klein import Klein
from twisted.web import server, resource
from twisted.web.util import redirectTo
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.web.template import Element, renderer, XMLFile
from twisted.python.filepath import FilePath


CP_AUTH_URL = os.environ.get("CP_AUTH_URL", "https://cp-api.5nines.com/v1.12")
CP_LOGIN_URL = os.environ.get("CP_LOGIN_URL", "https://dev-paradrop.5nines.com/cp-login-1")
CP_LANDING_URL = os.environ.get("CP_LANDING_URL", "https://dev-paradrop.5nines.com")
CP_LOCATION = os.environ.get("CP_LOCATION", 11)
CP_EXPIRATION = os.environ.get("CP_EXPIRATION", 3600)
CP_ALLOW_DOMAIN = os.environ.get("CP_ALLOW_DOMAIN", "5nines.com cp-api.5nines.com")
PARADROP_SYSTEM_DIR = os.environ.get("PARADROP_SYSTEM_DIR", "/tmp")


ADMIN_PORT = 8001
CAPTIVE_PORT = 8000


LEASES_FILE = os.path.join(PARADROP_SYSTEM_DIR, "dnsmasq-wifi.leases")
LEASES_FILE_FIELDS = ["expiration", "mac", "ip", "name", "devid"]


def get_clients():
    if not os.path.exists(LEASES_FILE):
        return []

    clients = []
    with open(LEASES_FILE, "r") as source:
        for line in source:
            parts = line.split()
            client = dict(zip(LEASES_FILE_FIELDS, parts))
            clients.append(client)

    return clients


def lookup_mac_address(ip_addr):
    if not os.path.exists(LEASES_FILE):
        return "00:15:6d:85:bc:be"

    with open(LEASES_FILE, "r") as source:
        for line in source:
            # format: expriation mac ip name devid
            parts = line.split()
            if parts[2] == ip_addr:
                return parts[1]

    return None


#def is_authenticated(mac_addr):
#    url = "{}/{}/{}".format(CP_AUTH_URL, mac_addr, CP_LOCATION)
#    req = requests.get(url)
#    if req.status_code != 200:
#        return False
#    return (req.text.strip() == "1")


def check_authenticated(mac_addr):
    url = "{}/{}/{}".format(CP_AUTH_URL, mac_addr, CP_LOCATION)
    return treq.get(url)


def handle_auth_status(status):
    if status.strip() == "1":
        return "OK"
    else:
        return "NO"


def initialize_iptables():
    #
    # Filter table
    #
    filter_table = iptc.Table(iptc.Table.FILTER)
    filter_forward = iptc.Chain(filter_table, "FORWARD")

    # Allow incoming responses from the Internet.
    rule = iptc.Rule()
    rule.in_interface = "eth0"
    rule.out_interface = "wlan0"
    state = rule.create_match("state")
    state.state = "ESTABLISHED,RELATED"
    rule.target = iptc.Target(rule, "ACCEPT")
    filter_forward.append_rule(rule)

    # Allow outgoing DNS requests.
    rule = iptc.Rule()
    rule.in_interface = "wlan0"
    rule.out_interface = "eth0"
    rule.protocol = "udp"
    udp = rule.create_match("udp")
    udp.dport = "53"
    rule.target = iptc.Target(rule, "ACCEPT")
    filter_forward.append_rule(rule)

    # Do not forward marked packets.
    rule = iptc.Rule()
    mark = rule.create_match("mark")
    mark.mark = "99"
    rule.target = iptc.Target(rule, "DROP")
    filter_forward.append_rule(rule)

    #
    # NAT table
    #
    nat_table = iptc.Table(iptc.Table.NAT)
    nat_prerouting = iptc.Chain(nat_table, "PREROUTING")
    nat_postrouting = iptc.Chain(nat_table, "POSTROUTING")

    # Redirect marked HTTP traffic to local webserver.
    rule = iptc.Rule()
    rule.protocol = "tcp"
    tcp = rule.create_match("tcp")
    tcp.dport = "80"
    mark = rule.create_match("mark")
    mark.mark = "99"
    rule.target = iptc.Target(rule, "REDIRECT")
    rule.target.to_port = str(CAPTIVE_PORT)
    nat_prerouting.append_rule(rule)

    # Masquerade outgoing traffic.
    rule = iptc.Rule()
    rule.out_interface = "eth0"
    rule.target = iptc.Target(rule, "MASQUERADE")
    nat_postrouting.append_rule(rule)

    #
    # Mangle table
    #
    mangle_table = iptc.Table(iptc.Table.MANGLE)
    mangle_prerouting = iptc.Chain(mangle_table, "PREROUTING")

    # Allow pre-configured domains, e.g. for the login page.
    for domain in CP_ALLOW_DOMAIN.split():
        rule = iptc.Rule()
        rule.dst = domain
        rule.target = iptc.Target(rule, "ACCEPT")
        mangle_prerouting.append_rule(rule)

    # Mark everything else that comes in.
    rule = iptc.Rule()
    rule.target = iptc.Target(rule, "MARK")
    rule.target.set_mark = "99"
    mangle_prerouting.append_rule(rule)


def allow_client(mac_addr):
#    etime = int(time.time()) + expiration

    mangle_table = iptc.Table(iptc.Table.MANGLE)
    mangle_prerouting = iptc.Chain(mangle_table, "PREROUTING")

    rule = iptc.Rule()
    mac = rule.create_match("mac")
    mac.mac_source = mac_addr
    rule.target = iptc.Target(rule, "ACCEPT")
    mangle_prerouting.insert_rule(rule)


class StatusPage(Element):
    loader = XMLFile(FilePath("status.xml"))

    @renderer
    def clients(self, request, tag):
        for client in get_clients():
            yield tag.clone().fillSlots(**client)


class AdminServer(object):
    app = Klein()

    @app.route("/")
    def get_status(self, request):
        request.setHeader('Content-Type', 'text/html')
        return StatusPage()

    @app.route("/api/request")
    def get_server(self, request):
        request.setHeader('Content-Type', 'application/json')
        return json.dumps(dir(request))

    @app.route("/api/clients")
    def get_clients(self, request):
        request.setHeader('Content-Type', 'application/json')
        clients = get_clients()
        return json.dumps(clients)

    @app.route("/api/events")
    def get_events(self, request):
        request.setHeader('Content-Type', 'application/json')
        return json.dumps(CaptiveServer.events)


class CaptiveServer(object):
    app = Klein()

    events = []

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    @inlineCallbacks
    def default(self, request, path):
        print(dir(request))

        host = request.getHost()
        ip_addr = request.getClientIP()
        mac_addr = lookup_mac_address(ip_addr)
#        is_auth = is_authenticated(mac_addr)

        print(id(self))

        req = yield check_authenticated(mac_addr)
        content = yield treq.content(req)
        result = yield handle_auth_status(content)

        if result == "OK":
            allow_client(mac_addr)

        url = "{}/?mac={}".format(CP_LOGIN_URL, mac_addr)
        o = yield redirectTo(url, request)
        print(o)

        event = {
            'action': 'redirect',
            'client_ip': ip_addr,
            'client_mac': mac_addr,
            'host': str(host),
            'redirect_url': url,
            'path': request.path,
            'uri': request.uri,
            'method': request.method
        }
        CaptiveServer.events.append(event)

        returnValue(o)


if __name__ == "__main__":
    initialize_iptables()

    admin = AdminServer()
    adminSite = server.Site(admin.app.resource())
    reactor.listenTCP(ADMIN_PORT, adminSite)

    captive = CaptiveServer()
    captiveSite = server.Site(captive.app.resource())
    reactor.listenTCP(CAPTIVE_PORT, captiveSite)

    reactor.run()
