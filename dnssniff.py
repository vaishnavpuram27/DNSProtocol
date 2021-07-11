from scapy.all import *

def findDNS(p):
  if p.haslayer(DNS):
    print(p.summary())
    # print(p.display())

    print("Type:"+str(p.type))
    print("Version:"+str(p.version))
    print("Protocol:"+str(p.proto))
    src_ip = p.getlayer(IP).src
    dest_ip = p.getlayer(IP).dst
    print("Source IP:"+str(src_ip))
    print("Destination IP:"+str(dest_ip))
    id = p.getlayer(IP).id
    print("id:"+str(id))
    print("Source Port:" + str(p.sport))
    print("Destination Port:" + str(p.dport))
    print("___________________________DNS____________________________________")
    Transc_id = p.getlayer(DNS).id
    print("Transaction id:"+str(Transc_id))
    print("Flag_QR:"+str(p.qr))
    print("Flag_OPcode:"+str(p.opcode))
    print("Flag_AA:"+str(p.aa))
    print("Flag_TC:"+str(p.tc))
    print("Flag_RD:"+str(p.rd))
    print("Flag_RA:"+str(p.ra))
    print("Flag_Z:"+str(p.z))
    print("Flag_AD:"+str(p.ad))
    print("Flag_CD:"+str(p.cd))
    print("Flag_Rcode:"+str(p.rcode))
    print("QDcount:"+str(p.qdcount))
    print("ANcount:"+str(p.ancount))
    print("NScount:"+str(p.nscount))
    print("ARcount:"+str(p.arcount))
    print("------------------------------Question Section--------------------------------------------")
    qd = []
    qd.append(p.qd)
    print(qd)
    print("------------------------------Resource/Answer Section--------------------------------------")
    an = []
    an.append(p.an)
    print(an)
    print("------------------------------NS record Section--------------------------------------------")
    ns = []
    ns.append(p.ns)
    print(ns)
    print("------------------------------AR record Section--------------------------------------------")
    ar = []
    ar.append(p.ar)
    print(ar)



sniff(prn=findDNS)
