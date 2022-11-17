import nmap
import re

# Basic User Interface
print(r"""  _____           _      _____                                 
 |  __ \         | |    / ____|                                
 | |__) |__  _ __| |_  | (___   ___ __ _ _ __  _ __   ___ _ __ 
 |  ___/ _ \| '__| __|  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |  | (_) | |  | |_   ____) | (_| (_| | | | | | | |  __/ |   
 |_|   \___/|_|   \__| |_____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                               
                                                               """)
print(r"""   __ _                                   
  / _| |                                  
 | |_| |_     _ __  _ __ ___   __ _ _ __  
 |  _| __|   | '_ \| '_ ` _ \ / _` | '_ \ 
 | | | |_ _  | | | | | | | | | (_| | |_) |
 |_|  \__(_) |_| |_|_| |_| |_|\__,_| .__/ 
                                   | |    
                                   |_|    """)
print(
    "*****************************************************************************************************************")
print("\n Copyright of Jesse Ramirez, 2022")
print("\n https://www.rmrz.io")
print(
    "\n*****************************************************************************************************************")


class PortScanner:
    # Initialize default ip address and port variables
    def __init__(self):
        self.port_min = 0
        self.port_max = 65535
        self.port_range = str(self.port_min) + '-' + str(self.port_max)
        self.ip_address = '0.0.0.0'

    # Instance for initializing with ip address, min, and max port
    def __init__(self, ip_address, port_min, port_max):
        self.ip_address = ip_address
        self.port_min = port_min
        self.port_max = port_max
        self.port_range = str(self.port_min) + '-' + str(self.port_max)

    # Instance for initializing with ip address and port range
    def __init__(self, ip_address, port_range):
        self.ip_address = ip_address
        self.port_range = port_range

    def print_user_input(self):
        print(f"The IP address entered was {self.ip_address} over range {self.port_range}.")

    def get_ip(self):
        # Regular expression pattern to recognize IPv4 addresses
        ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        while True:
            ans = input("\nPlease enter the IP address you want to scan: ")
            if ip_add_pattern.search(ans):
                print(f"{ans} is a valid IP address.")
                self.ip_address = ans
                break

    def get_ports(self):
        # Regular expression pattern to extract number of ports you want to scan
        port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
        while True:
            print("Please enter the range of ports you want to scan in the format <int>-<int>: ")
            self.port_range = input("Enter port range: ")
            port_range_valid = port_range_pattern.search(self.port_range.replace(" ", ""))
            if port_range_valid:
                self.port_min = int(port_range_valid.group(1))
                self.port_max = int(port_range_valid.group(2))
                # return port_range
                break

    def tcp_port_status(self):
        nm = nmap.PortScanner()
        nm.scan(self.ip_address, str(self.port_range))

        # run a loop to print all the found result about the ports
        for host in nm.all_hosts():
            print('Host : %s (%s)' % (host, nm[host].hostname()))
            print('State : %s' % nm[host].state())
            for proto in nm[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)

                # lport = nm[host][proto].keys()
                lport = sorted(nm[host][proto].keys())
                for port in lport:
                    print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

    def show_port_status(self):
        open_ports = []
        open_ports2 = {"Port": [], "Port Status": []}
        nm = nmap.PortScanner()
        nm.scan(self.ip_address, str(self.port_range))

        for port in range(self.port_min, self.port_max + 1):
            try:
                # For in nmap for port 80 and ip 1.1.1.1, you'd run $ nmap -oX p 80 -sV 1.1.1.1
                results = nm.scan(self.ip_address, str(port))
                # Uncomment the following line to look at dictionary
                # print(results)
                port_status = (results['scan'][self.ip_address]['tcp'][port]['state'])
                print(f"Port {port} is {port_status}.")
                open_ports.append(port)
                open_ports2["Port"].append(port)
                open_ports2["Port Status"].append(port_status)

            except:
                print(f"Cannot scan port {port}.")
        print(open_ports2)

    def stealth_scan(self):
        nm = nmap.PortScanner()
        nm.scan(self.ip_address, str(self.port_range), '-v -sS')
        # print(nm.scaninfo())

        print(f"IP Status: {nm[self.ip_address].state()}")
        print(f"Protocols: {nm[self.ip_address].all_protocols()}")
        print(f"Open Ports: {nm[self.ip_address]['tcp'].keys()}")

    def upd_scan(self):
        nm = nmap.PortScanner()
        nm.scan(self.ip_address, str(self.port_range), '-v -sU')
        # print(nm.scaninfo())

        print(f"IP Status: {nm[self.ip_address].state()}")
        print(f"Protocols: {nm[self.ip_address].all_protocols()}")
        print(f"Open Ports: {nm[self.ip_address]['udp'].keys()}")

    def comprehensive_scan(self):
        nm = nmap.PortScanner()
        nm.scan(self.ip_address, str(self.port_range), '-v -sS -sV -sC -A -O')
        # print(nm.scaninfo())

        print(f"IP Status: {nm[self.ip_address].state()}")
        print(f"Protocols: {nm[self.ip_address].all_protocols()}")
        print(f"Open Ports: {nm[self.ip_address]['tcp'].keys()}")

    def os_detection(self):
        nm = nmap.PortScanner()
        print(nm.scan(self.ip_address, arguments="-O")['scan'][self.ip_address]['osmatch'][1])

    def ip_range(self):
        min_range = input("Enter min range of IP scan (ex. x.x.x.1 min): ")
        max_range = input("Enter max range of IP scan (ex. x.x.x.254 max): ")

        ip = str(self.ip_address)
        size = len(ip)
        ip = ip[:size - 1]
        print(f"Modified IP from {self.ip_address} to {ip}")
        subnet_range = ip + min_range + '-' + max_range
        subnet_range = str(subnet_range)
        print(f"Subnet range is {subnet_range}")

        nm = nmap.PortScanner()
        scan_range = nm.scan(hosts=subnet_range)

        print("\nPRINT KEYS ***************************************")
        for key in scan_range.keys():
            print(key)

        print("\nPRINT ITEMS ***************************************")
        for item in scan_range.items():
            print(type(item))

        print("\nFOR LOOP ***************************************")
        count = 0
        for i in scan_range:
            for j in scan_range[i]:
                if count > 2:
                    print(j, " :: ", scan_range[i][j])
                count += 1
                print("Loop ", count)

        print("\nNICE PRINT***************************************")
        nm.all_hosts()
        for host in nm.all_hosts():
            print("\nHost: %s(%s)" % (host, nm[host].hostname()))
            print("State: %s" % (nm[host].state()))
            print("Open TCP Ports: %s" % (nm[host].all_tcp()))
            print("Open UDP Ports: %s" % (nm[host].all_udp()))
            #print("%s" % (nm[host].all_ip()))

    def multiple_ip_scans(self):
        subnet = self.ip_address + '/24'
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments='-n -sP -PE -PA21,23,80,3389')
        hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        for host, status in hosts_list:
            print(f"IP Address: {host} Status: {status}")
            # print('{0}:{1}'.format(host, status))

class Menu():
    def __init__(self):
        pass


def menu(object):
    # While loop flag, True = Loop, False break loop
    flag = True
    count = 0

    while flag == True:
        if count > 0:
            print(f""""\n  ___     _              _ _                 
 | _ \___| |___  __ _ __| (_)_ _  __ _       
 |   / -_) / _ \/ _` / _` | | ' \/ _` |_ _ _ 
 |_|_\___|_\___/\__,_\__,_|_|_||_\__, (_|_|_)
                                 |___/       """)
        print(f"""                                                   
                                                   
  ______ ______ ______ ______ ______ ______ ______ 
 |______|______|______|______|______|______|______|
 |  \/  |     (_)       |  \/  |                   
 | \  / | __ _ _ _ __   | \  / | ___ _ __  _   _   
 | |\/| |/ _` | | '_ \  | |\/| |/ _ \ '_ \| | | |  
 | |  | | (_| | | | | | | |  | |  __/ | | | |_| |  
 |_|  |_|\__,_|_|_| |_| |_|  |_|\___|_| |_|\__,_|  
  ______ ______ ______ ______ ______ ______ ______ 
 |______|______|______|______|______|______|______|
                                                   
                                                   
                                                   
                                                   """)

        print("a - Define target IP address\nb - Define Ports\nc - Print User Inputs\n0 - Exit")
        if object.ip_address != '' and object.port_range != '':
            print("\n1 - Define IP range over subnet\n2 - View devices connected to IP \n3 - TCP Port Status\n3 - "
                  "Open Ports\n4 - Stealth Scan\n5 - UDP Scan\n6 - OS Detection\n")

        ans = input("Pick an option: ")

        # On the first loop, this is the only options available until it gets some user input
        if ans == 'a':
            object.getIP()
        elif ans == 'b':
            object.getPorts()
        elif ans == 'c':
            object.printUserInput()
        elif ans == '0':
            flag = False

        # Main menu when object is not null
        if object.ip_address != '' and object.port_range != '':
            if ans == '1':
                object.ip_range()
            elif ans == '2':
                object.multiple_ip_scans()
            elif ans == '3':
                object.showPortStatus()
            elif ans == '4':
                object.stealthScan()
            elif ans == '5':
                object.upd_scan()
            elif ans == '6':
                object.os_dection()
            elif ans == '7':
                object.multiple_ip_scans()
            else:
                pass

        # Uncomment for debugging and checking PortScanner class values
        # if object is None:
        #    print(f"ProjectScanner object is empty. Object has values as {object.ip_address} over port range {object.port_range}.")
        # elif object is not None:
        #    print(f"ProjectScanner object has values. IP address {object.ip_address} over port range {object.port_range}.")

        count += 1


def simple_menu(object):
    # While loop flag, True = Loop, False break loop
    flag = True
    count = 0

    while flag == True:
        if count > 0:
            print(f""""\n  ___     _              _ _                 
    | _ \___| |___  __ _ __| (_)_ _  __ _       
    |   / -_) / _ \/ _` / _` | | ' \/ _` |_ _ _ 
    |_|_\___|_\___/\__,_\__,_|_|_||_\__, (_|_|_)
                                    |___/       """)
        print(f"""                                                   

     ______ ______ ______ ______ ______ ______ ______ 
    |______|______|______|______|______|______|______|
    |  \/  |     (_)       |  \/  |                   
    | \  / | __ _ _ _ __   | \  / | ___ _ __  _   _   
    | |\/| |/ _` | | '_ \  | |\/| |/ _ \ '_ \| | | |  
    | |  | | (_| | | | | | | |  | |  __/ | | | |_| |  
    |_|  |_|\__,_|_|_| |_| |_|  |_|\___|_| |_|\__,_|  
     ______ ______ ______ ______ ______ ______ ______ 
    |______|______|______|______|______|______|______|



                                                      """)

        print("a - Define IP address\nb - Define IP Range\n0 - Exit")
        ans = input("Pick an option: ")

        # On the first loop, this is the only options available until it gets some user input
        if ans == 'a':
            object.getIP()
        elif ans == 'b':
            object.ip_range()
        elif ans == 'c':
            object.printUserInput()
        elif ans == '0':
            flag = False


def main():
    # Initiate portScanner object
    s = PortScanner()
    # Loop main menu
    menu(s)
    #simple_menu(s)


if __name__ == '__main__':
    main()
