#!/usr/bin/env python

import argparse

# Suppress Scapy's chattiness
import logging
logging.getLogger("scapy.runtime").setLevel(logging.WARNING)

import scapy.all as sc
sc.conf.verb = 0

expected_ips = []

def dns_callback(p):
    if expected_ips and p[sc.IP].dst not in expected_ips:
        logging.getLogger("scapy.runtime").warning(
            "BAD DNS DESTINATION {}".format(p[sc.IP].dst))
    elif not expected_ips:
        print("{: <16} {: <16} {: <18}".format(p[sc.IP].src, p[sc.IP].dst,
            p[sc.DNSQR].qname))

def sniff_dns(**kwargs):
    sniff_args = {
        "prn": dns_callback,
        "timeout": kwargs.get("timeout"),
        "lfilter": lambda p: p.haslayer(sc.DNS),
        "store": kwargs.get("store")
    }
    if kwargs.get("interface"):
        sniff_args["iface"] = kwargs["interface"]

    if not expected_ips:
        print("{: <16} {: <16} {: <18}".format("SRC", "DST", "URL"))
    sc.sniff(**sniff_args)

def parse_args():
    p = argparse.ArgumentParser(description=
        '''
        Test for leaking DNS queries (i.e. if a VPN is being used). 
        
        If no expected DNS IP is specified then all DNS traffic is printed. If
        one is specified then this script alerts on leaking queries. 
        
        The rationale being that all DNS traffic sniffed should only have 
        either our local IP or the IP of our trusted DNS resolver(s).
        ''', formatter_class=argparse.RawTextHelpFormatter)

    p.add_argument('-i', '--interface', action='store')
    p.add_argument('-e', '--expected-dns-ips', action='store', nargs='+')
    p.add_argument('-t', '--timeout', type=int, action='store')
    p.add_argument('-s', '--store', action='store_true')

    args = p.parse_args()
    return args

def main():
    args = parse_args()

    global expected_ips
    expected_ips = args.expected_dns_ips

    sniff_dns(**vars(args))
    
if __name__ == "__main__":
    main()

