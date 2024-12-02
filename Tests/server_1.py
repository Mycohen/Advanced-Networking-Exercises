

from scapy.all import sniff
packets = sniff(count=10)
packets.summary()
count=1
for packet in packets:
    print("Packet number:"+ str(count))
    print(packet.show())
    count+=1