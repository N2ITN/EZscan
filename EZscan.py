import os
import nmap
from collections import OrderedDict as ordered

nm = nmap.PortScanner()
nm.scan('192.168.0.0/24', arguments='-O')


class network_obj:
    inst = ordered()

    def __init__(self, h):
        self.ip = h
        self.json = nm[h]
        self.ports = None
        self.vendor = None
        self.OS = None

        if len(nm[h]['tcp']) > 0:
            self.ports = str(list(x for x in nm[h]['tcp'].keys()))

        if len(nm[h]['vendor'].values()) > 0:
            self.vendor = list(nm[h]['vendor'].values())[0]

        if len(nm[h]['osmatch']) > 0:
            self.OS = nm[h]['osmatch'][0]['name']

        network_obj.inst[h] = self

    def print_self(self):

        print(", ".join(
            [x for x in [self.ip, self.ports, self.OS, self.vendor] if x]))

    @staticmethod
    def print_all():
        for i in network_obj.inst.values():
            i.print_self()


def main():
    for h in nm.all_hosts():
        temp = network_obj(h)

    network_obj.print_all()


if __name__ == '__main__':
    main()