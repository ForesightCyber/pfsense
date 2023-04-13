#!/usr/bin/python3

import sys
import os
import logging
import faker
import lxml.etree as ET
import argparse
import ipaddress

SCRIPTDIR = os.path.dirname(os.path.realpath(__file__))


def setDebug():
    logging.basicConfig(level=logging.DEBUG)


def helpMsg(p):
    print(p.format_help())
    print(p.format_values())
    sys.exit()


class Remove():

    def __init__(self, txt, sections):
        self._xml = ET.fromstring(txt)
        self._sections = sections

    def process(self):
        for s in self._sections:
            for x in self._xml.findall(s):
                x.getparent().remove(x)

    def tostring(self):
        return ET.tostring(self._xml, encoding='unicode', method='xml')


class Anonymize():

    pairs = {}

    def __init__(self, txt, sections, tpe):
        self._xml = ET.fromstring(txt)
        self._sections = sections
        self._faker = faker.Faker()
        self._tpe = tpe

    def process(self):
        for s in self._sections:
            for x in self._xml.findall(s):
                if self._tpe == None:
                    x.text = ""
                else:
                    if x.text in self.pairs.keys():
                        x.text = self.pairs[x.text]
                    else:
                        if self._tpe == "paragraph":
                            self.pairs[x.text] = self._faker.paragraph()
                        elif self._tpe == "ip":
                            try:
                                if x.text.find("/") > 0:
                                    ip = ipaddress.ip_network(x.text)
                                else:
                                    ip = ipaddress.ip_address(x.text)
                                if isinstance(ip, ipaddress.IPv6Address):
                                    self.pairs[x.text] = self._faker.ipv6()
                                elif isinstance(ip, ipaddress.IPv4Address):
                                    self.pairs[x.text] = self._faker.ipv4()
                                elif isinstance(ip, ipaddress.IPv4Network):
                                    self.pairs[x.text] = self._faker.ipv4(network=True)
                                elif isinstance(ip, ipaddress.IPv6Network):
                                    self.pairs[x.text] = self._faker.ipv6(network=True)
                                else:
                                    logging.getLogger().error(
                                        "%s is not valid IP address. Leaving as is" % (x.text))
                                    continue
                            except Exception as e:
                                logging.getLogger().error("%s is not valid IP address (%s). Leaving as is" % (x.text, e))
                                continue
                        elif self._tpe == "name":
                            if x.text.find(".") > 0:
                                self.pairs[x.text] = self._faker.hostname()
                            else:
                                self.pairs[x.text] = self._faker.hostname(levels=0)
                        else:
                            raise Exception("Bad type %s" % self._tpe)
                        x.text = self.pairs[x.text]

    def tostring(self):
        return ET.tostring(self._xml, encoding='unicode', method='xml')


p = argparse.ArgumentParser()
p.add_argument('-d', dest='d', action='store_const', const='d', metavar='Bool', default=None)
p.add_argument('--xml-in', dest='xmlin', metavar='XML input', required=False, default=None)
p.add_argument('--xml-out', dest='xmlout', metavar='XML output', required=False, default=None)
p.add_argument('--hide-nodes', dest='hsections', metavar='Which sections to hide (Xpath)',
               default=[
                   ".//bcrypt-hash",
                   ".//authorizedkeys",
                   ".//cert/crt",
                   ".//cert/prv",
                   ".//gold_encryption_password",
                   ".//encryption_password",
                   ".//gold_password",
                   ".//snmpd/rocommunity",
                   ".//pre-shared-key",
                   ".//aliases/*/url",
                   ".//custom_options/tls",
                   ".//bcrypt-hash",
                   ".//sha512-hash",
                   ".//custom_options/tls",
                   ".//cert/crt",
                   ".//cert/prv",
                   ".//ovpnserver/*/certca",
                   ".//openvpn-client/auth_pass",
                   ".//ca/crt",
                   ".//ca/prv",
                   ".//quaggaospfdraw/*/ospfdrunning",
                   ".//quaggaospfdraw/*/ospf6drunning",
                   ".//quaggaospfdraw/*/bgpdrunning",
                   ".//quaggaospfdraw/*/zebrarunning",
                   ".//quaggaospfd/*/password",
                   ".//item/ssloffloadcert",
                   ".//squidnac/*/allowed_subnets",
                   ".//squidnac/*/blacklist",
                   ".//squid/*/custom_options_squid3",
                   ".//nut/*/upsd_users",
                   ".//pfblockerng/*/maxmind_key",
                   ".//sid_mgmt_lists/*/content",
                   ".//suppress/*/suppresspassthru",
                   ".//rule/file_store_logdir",
                   ".//zabbixagentlts/*/userparams",
                   ".//zabbixproxylts/*/tlspskfile",
                   ".//zabbixproxylts/*/advancedparams",
                   ".//defaultsettings/advancedoptions",
                   ".//item/advancedoptions",
                   ".//step9/authcertname",
                   ".//step6/authcertca",
                   ".//unbound/custom_options",
                   ".//openvpn-client/tls",
                   ".//openvpn-server/tls",
                   ".//openvpn-server/shared_key",
                   ".//syslogngadvanced/*/objectparameters",
                   ".//item/useproxypass",
                   ".//item/publickey", ".//item/privatekey",
                   ".//password"
               ], action="append"
               )

p.add_argument('--anonymize-ip-nodes', dest='isections', metavar='Which sections to anonymize by IP (Xpath)',
               default=[
                   ".//ipaddr", ".//route/network", ".//failover_peerip", ".//gateway", ".//range/from", ".//range/to", ".//remoteid/address",
                   ".//allowedips/row/address", ".//endpoint"
               ], action="append"
               )

p.add_argument('--anonymize-name-nodes', dest='nsections', metavar='Which sections to anonymize by Name (Xpath)',
               default=[
                   ".//username", ".//name", ".//hostname", ".//openvpn-csc/common_name",
                   ".//pfblockernglistsv4/config/*/url", ".//alias/address"
                                                         ".//rule/*/username",
               ], action="append"
               )

p.add_argument('--anonymize-descr-nodes', dest='dsections', metavar='Which sections to anonymize by Descripton (Xpath)',
               default=[
                   ".//descr", ".//description", ".//separator/text", ".//aliases/*/detail"
               ], action="append"
               )


p.add_argument('--remove-nodes', dest='rsections', metavar='Which sections to completely remove (Xpath)',
               default=[], action="append"
               )
cfg = p.parse_args()

if cfg.d:
    setDebug()

if cfg.xmlin:
    inf = open(cfg.xmlin, "r")
else:
    inf = sys.stdin

if cfg.xmlout:
    outf = open(cfg.xmlout, "w")
else:
    outf = sys.stdout

infstring = "".join(inf.readlines())

# Remove sections
anon = Remove(infstring, cfg.rsections)
anon.process()
next = anon.tostring()

# Anonymize desccriptions
anon = Anonymize(next, cfg.dsections, "paragraph")
anon.process()
next = anon.tostring()

# Anonymize names
anon = Anonymize(next, cfg.nsections, "name")
anon.process()
next = anon.tostring()

# Anonymize IPs
anon = Anonymize(next, cfg.isections, "ip")
anon.process()
next = anon.tostring()

# Hide sections
anon = Anonymize(next, cfg.hsections, None)
anon.process()
next = anon.tostring()

last = next
print(last, file=outf)

pass
