import socket
import nmap
from tld import get_fld

scanner = nmap.PortScanner()


# grabbing url and getting it's IP Addr
def get_website_ip():
    website_url = input("Please enter a URL: ")
    # accepts a regular https format with get_fld function
    ip_addr = socket.gethostbyname(get_fld(website_url))
    try:
        print("IP is : ", ip_addr)
    except:
        print("please try again and enter a correct website")

    # code below prints out the website's IP Address
    print("The IP of ", website_url, "is ", ip_addr)
    print("Scanning IP...")
    print("Nmap version: ", scanner.nmap_version())
    #code below scans ports and does different types of scans i.e  TCP SYN/Connect()/ACK/Window/Maimon scans
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())


# END
print(get_website_ip())
