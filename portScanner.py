import socket
import re

# Basic User Interface
print("\n**********************************************************************")
print(r"""  ___          _       _     ___         _     ___                            
 / __| ___  __| |_____| |_  | _ \___ _ _| |_  / __| __ __ _ _ _  _ _  ___ _ _ 
 \__ \/ _ \/ _| / / -_)  _| |  _/ _ \ '_|  _| \__ \/ _/ _` | ' \| ' \/ -_) '_|
 |___/\___/\__|_\_\___|\__| |_| \___/_|  \__| |___/\__\__,_|_||_|_||_\___|_|  
                                                                              """)
print("***********************************************************************")
print("\n* Copyright of Jesse Ramirez, 2022")
print("\n* https://www.rmrz.io/projects")
print("\n* The purpose of this script is to be a simple socket port scanner without using nmap.")
print("\n***********************************************************************")


class SocketPortScanner:
    def __init__(self):
        # Initialize default ip address and ports
        self.ip_address = '0.0.0.0'
        self.port_min = 0
        self.port_max = 65535
        self.port_range = str(self.port_min) + '-' + str(self.port_max)

    def __int__(self, ip_address, port_range):
        self.ip_address = ip_address
        self.port_range = port_range

    # For debugging purposes: call this function to display the current IP address and port range
    def display_input(self):
        print(f"Current Status: Input IP address is {self.ip_address} over the port range {self.port_range}.\n")

    # Function to get IP address from user
    def get_ip_addr(self):
        # Regular expression pattern to recognize IPv4 addresses
        ip_add_pattern = re.compile("^(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$)")
        # More elegant version
        # ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        while True:
            self.ip_address = input("\nPlease enter the IP address you want to scan: ")
            # Checks to see format matches regular expression format
            if ip_add_pattern.search(self.ip_address):
                print(f"{self.ip_address} is a valid IP address.")
                break

    # Function to get port range from user
    def get_port_range(self):
        # Regular expression pattern to extract number of ports you want to scan
        port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
        while True:
            print("Please enter the range of ports you want to scan in the format <int>-<int> (ex: 400-450): ")
            self.port_range = input("Enter port range: ")
            # Checks to see format matches regular expression format
            port_range_valid = port_range_pattern.search(self.port_range.replace(" ", ""))
            # Assign port min and max range as int variables
            if port_range_valid:
                self.port_min = int(port_range_valid.group(1))
                self.port_max = int(port_range_valid.group(2))
                break
        print(f"Port Range is now {self.port_min}-{self.port_max}.")

    # Function to check port over a pre-defined range
    def check_port(self):
        # Initiate empty list
        open_ports = []
        # Loop through the defined port range
        for port in range(self.port_min, self.port_max + 1):
            try:
                # AF_INET is the address family ipv4, SOCK_STREAM is the TCP protocol
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    # Set the timeout speed for socket connections
                    s.settimeout(0.5)
                    # Connect to defined ip address and current port in the port range
                    s.connect((self.ip_address, port))
                    # If there's an open port, append to the open_ports list
                    open_ports.append(port)
            except:
                pass
        print(f"For IP address {self.ip_address}, these ports are open:")
        # Loop through open_ports list and print them out
        for port in open_ports:
            print("Port: %s" % port)


class Menu:
    # Set marker to True to start the loop, False to exit
    # Set counter to 0 and update it within the loop to do count related loop things
    def __init__(self):
        self.counter = 0

    # Basic user interface
    def print_menu(self, s):
        print("\n---------")
        if self.counter == 0:
            print(r"""" /$$      /$$           /$$                 /$$      /$$                              
| $$$    /$$$          |__/                | $$$    /$$$                              
| $$$$  /$$$$  /$$$$$$  /$$ /$$$$$$$       | $$$$  /$$$$  /$$$$$$  /$$$$$$$  /$$   /$$
| $$ $$/$$ $$ |____  $$| $$| $$__  $$      | $$ $$/$$ $$ /$$__  $$| $$__  $$| $$  | $$
| $$  $$$| $$  /$$$$$$$| $$| $$  \ $$      | $$  $$$| $$| $$$$$$$$| $$  \ $$| $$  | $$
| $$\  $ | $$ /$$__  $$| $$| $$  | $$      | $$\  $ | $$| $$_____/| $$  | $$| $$  | $$
| $$ \/  | $$|  $$$$$$$| $$| $$  | $$      | $$ \/  | $$|  $$$$$$$| $$  | $$|  $$$$$$/
|__/     |__/ \_______/|__/|__/  |__/      |__/     |__/ \_______/|__/  |__/ \______/ 
""")
        elif self.counter > 0:
            print(r""""
            R E L O A D I N G . . .
                 
         /$$      /$$           /$$                 /$$      /$$                              
        | $$$    /$$$          |__/                | $$$    /$$$                              
        | $$$$  /$$$$  /$$$$$$  /$$ /$$$$$$$       | $$$$  /$$$$  /$$$$$$  /$$$$$$$  /$$   /$$
        | $$ $$/$$ $$ |____  $$| $$| $$__  $$      | $$ $$/$$ $$ /$$__  $$| $$__  $$| $$  | $$
        | $$  $$$| $$  /$$$$$$$| $$| $$  \ $$      | $$  $$$| $$| $$$$$$$$| $$  \ $$| $$  | $$
        | $$\  $ | $$ /$$__  $$| $$| $$  | $$      | $$\  $ | $$| $$_____/| $$  | $$| $$  | $$
        | $$ \/  | $$|  $$$$$$$| $$| $$  | $$      | $$ \/  | $$|  $$$$$$$| $$  | $$|  $$$$$$/
        |__/     |__/ \_______/|__/|__/  |__/      |__/     |__/ \_______/|__/  |__/ \______/ 
        """)

        print("---------")
        s.display_input()
        print("a - Enter IP Address\nb - Enter Port Range <int>-<int> (ex: 400-450)\n"
              "c - Scan port range\n0 - Exit")

    # Checks to make sure user input is a valid option
    def check_answer(self, ans):
        # Regular expression for choices and whether user inputs are valid or not
        ans_pattern = re.compile("^[a-c0]+")

        while True:
            if ans_pattern.search(ans):
                print(f"\n{ans} is a valid option and was selected.")
                break
            else:
                print(f"\n{ans} is not a valid option. Please select a valid option: ")
                break

    # Smaller menu meant for debugging or testing features without having to alter the main_menu() function
    def quick_menu(self, s):
        while True:
            self.print_menu(s)
            ans = input("Choose Option: ")
            self.check_answer(ans)

            # Enter testing functions below
            if ans == 'a':
                pass
            elif ans == 'b':
                pass
            elif ans == '0':
                print("Now exiting. Goodbye~")
                print(f"Amount of times this menu looped: {self.counter}.")
                break

            self.counter += 1

    def main_menu(self, s):
        # While loop to keep the program up until it's exited
        while True:
            self.print_menu(s)
            # Take user input
            ans = input("Choose Option: ")
            # Check input against regular expression to verify it's a valid input
            self.check_answer(ans)

            # Call socket functions here based on user selection
            if ans == 'a':
                s.get_ip_addr()
            elif ans == 'b':
                s.get_port_range()
            elif ans == 'c':
                s.check_port()
            # Break the main menu loop
            elif ans == '0':
                print("Now exiting. Goodbye~")
                print(f"Amount of times this menu looped: {self.counter}.")
                break

            self.counter += 1


def main():
    # Create a socket object
    s = SocketPortScanner()
    # Create a Menu object
    m = Menu()
    # Pass the socket object into the Menu class
    m.main_menu(s)


if __name__ == '__main__':
    main()
