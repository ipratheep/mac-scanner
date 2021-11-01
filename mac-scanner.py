import scapy.all as scapy
import optparse
parser = optparse.OptionParser()


def set_options():
    parser.add_option("-r", "--range", dest="ip_address", help="Enter the ip address or Range")
    options, arguments = parser.parse_args()
    if not options.ip_address:
        parser.error("******* -h PODU BRO FOR HELP *******")
    else:
        return options.ip_address


def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    set_destination = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    final = set_destination/arp_req
    answered = scapy.srp(final, timeout=5, verbose=False)[0]
    result = []
    for answer in answered:
        ans_dic = {"ip": answer[1].psrc, "mac": answer[1].hwsrc}
        result.append(ans_dic)
    return result


def print_result(result):
    print(" IP-ADDRESS\t\t\tMAC-ADDRESS\n*************************************************")
    for result_dic in result:
        print(result_dic["ip"] + "\t\t\t" + result_dic["mac"])


result_list = scan(set_options())
print_result(result_list)
