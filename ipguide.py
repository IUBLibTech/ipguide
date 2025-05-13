#!/bin/env python3
from ipaddress import IPv4Network, ip_network
import csv
import logging
from pathlib import Path
import time
import pickle
import time
import subprocess
from typing import Any

def main():
    start = time.time()
    x = IPGuide("network.csv")
    print(f"Loaded database in {time.time() - start:0.3f} seconds.")
    for ip in ('129.79.1.1', '140.182.77.16', '199.167.64.1', '223.255.236.1',
               '12.0.0.1', '192.168.0.3', '::1', '2001:18e8::1:2:3'):
        start = time.time()
        y = x.find_network(ip)
        print(f"{time.time() - start:0.6f}:  {ip} -> {y}")

    print(x.find_asn(87))


class NetTree:    
    """Search Tree for CIDR nodes"""

    def __init__(self):
        "Initialize the tree as empty"
        self.tree = [None, None, None]


    def dump(self, node=None, path="", depth=0) -> str:
        """Return a textual representation of the tree """
        if node is None:
            node = self.tree
        res = ""
        if node[2]:
            res += f"{path}: {node[2]}\n"
        for i in (0, 1):
            if node[i] is None:
                continue
            res += self.dump(node[i], path + str(i), depth + 1)
        return res


    def insert(self, network: str, data: Any):
        """Insert the data at the appropriate part of the tree"""
        net = ip_network(network)
        if isinstance(net, IPv4Network):
            # embed the IPv4 into an IPv6
            net = ip_network(f"::ffff:{net.network_address}/{net.prefixlen + 96}")
        
        here = self.tree
        prefix = f"{int(net.network_address):0128b}"[:net.prefixlen]
        for b in prefix:
            b = int(b)
            if here[b] is None:                
                here[b] = [None, None, None]            
            here = here[b]            
        here[2] = data



    def search(self, network):
        """Walk the tree based on the network prefix and return the most specific
           data found."""
        net = ip_network(network)
        if isinstance(net, IPv4Network):
            # embed the IPv4 into an IPv6
            net = ip_network(f"::ffff:{net.network_address}/{net.prefixlen + 96}")
        here = self.tree
        prefix = f"{int(net.network_address):0128b}"[:net.prefixlen]        
        net = None
        for b in prefix:
            if here[2]:
                net = here[2]
            b = int(b)
            if here[b] is None:                                
                break            
            here = here[b]
        return net


class IPGuide:
    """This is the main IPGuide Database"""
    def __init__(self, filename, download: bool=True, use_pickle: bool=True, max_age_days: float=7):
        """Initialize the ip.guide database.  Optionally download the data if needed, pickle it for
        faster future starts, and refresh it if it's too old"""
        self.filename = Path(filename)
        self.pickle = Path(filename).with_suffix(".pickle") if use_pickle else None
        self.database = None  

        if not self.filename.exists():
            # the database doesn't exist, so we probably need to download it.
            if not download:
                raise FileNotFoundError(f"IP Guide data file {filename} can't be found and download was disabled")            
            logging.debug(f"Retrieving {self.filename} from ip.guide since it's missing")
            self.download_database()    
        else:
            # we have a database, let's check to see if it needs refreshed...
            if time.time() - self.filename.stat().st_mtime > (max_age_days * (24 * 3600)):
                # it's pretty old, let's try to get a new copy
                try:
                    logging.debug(f"Retrieving {self.filename} from ip.guide since it's out of date")
                    self.download_database()
                except Exception as e:
                    logging.warning(f"Cannot refresh the database because {e}. Using previous database")

        # at this point we should have a raw CSV file that is up to date. 
        self.load_database()
        
        
    def download_database(self):
        """Download the database file if possible"""
        try:
            tmpfile = self.filename.with_suffix(".new")        
            logging.debug(f"Refreshing bulk IP Guide data into temp file: {tmpfile}")                
            subprocess.run(['curl', '-o', str(tmpfile), 'https://ip.guide/bulk/networks.csv'],
                            check=True)
            tmpfile.rename(self.filename)
        except Exception as e:
            logging.exception("Can't refresh ip.guide data: {e}")


    def load_database(self):
        """Load the database data.  Use the pickled version if it's available"""
        if not self.filename.exists():
            raise FileNotFoundError(f"Cannot find the IPGuide source csv: {self.filename}")

        if self.pickle is None or not self.pickle.exists() or self.pickle.stat().st_mtime < self.filename.stat().st_mtime:
            logging.debug(f"Loading the ip.guide data from {self.filename}")
            self.database = {'network': NetTree(),
                             'asn': {},
                             'country': {}}

            with open(self.filename, newline='') as cfile:
                reader = csv.reader(cfile)
                for row in reader:
                    if row[0] == 'network':
                        # this is the header, but we'll use this opportunity
                        # to include records for the private networks.                        
                        private = ['10.0.0.0/8', '127.0.0.0/8',
                                    '172.16.0.0/12', '192.168.0.0/16',
                                    '::1/128', 'fc00::/7', 'fe80::/10']
                        for pnet in private:
                            self.database['network'].insert(pnet, (pnet, 0, '*'))
                        self.database['asn'][0] = {
                            'name': 'Locally routed network',
                            'country': '*',
                            'networks': private
                        }
                        self.database['country']['*'] = [0]
                        continue

                    asn = int(row[1])
                    self.database['network'].insert(row[0], (row[0], asn, row[3]))
                    if asn not in self.database['asn']:
                        self.database['asn'][asn] = {
                            'name': row[2],
                            'country': row[3],
                            'networks': []
                        }
                    self.database['asn'][asn]['networks'].append(row[0])
                    if row[3] not in self.database['country']:
                        self.database['country'][row[3]] = []
                    self.database['country'][row[3]].append(asn)

            if self.pickle is not None:
                with open(self.pickle, "wb") as f:
                    pickle.dump(self.database, f)

        else:
            logging.debug("Loading pickled ip.guide data")
            with open(self.pickle, "rb") as f:
                self.database = pickle.load(f)


    def find_network(self, network):
        return self.database['network'].search(network)
    

    def networks_for_asn(self, asn):
        if asn not in self.database['asn']:
            return []
        else:
            return self.database['asn'][asn].get('networks', [])

    def find_asn(self, asn):
        return self.database['asn'].get(asn, None)
    

    def find_country(self, country):
        return self.database['country'].get(country, [])


    def get_networks(self, spec):
        """Get networks based on an IP or an ASN:id value, or a list of the aforementioned"""
        try:
            if not isinstance(spec, list):
                spec = [spec]
            res = []
            for s in spec:
                if s.startswith('ASN:'):                    
                    asn = int(s.split(':')[1])
                    res.extend(self.networks_for_asn(asn))
                else:
                    res.append(s)
            return res
        except Exception as e:
            logging.exception(f"Could not get networks for {spec}: {e}")
            return spec



if __name__ == "__main__":
    main()