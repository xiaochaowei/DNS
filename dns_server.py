# coding=utf-8
"""
LICENSE http://www.apache.org/licenses/LICENSE-2.0
"""
import datetime
import sys
import time
import threading
import traceback
import SocketServer
from dnslib import *
import socket
import random
from Crypto.Cipher import AES
from dnslib import zoneresolver

def readZone(fname, domain):
    record = {}
    with open(fname, 'r') as fid:
        resolver = zoneresolver.ZoneResolver(fid)
    record["auth"] = {} 
    record["auth"][domain] = []   
    for rr in resolver.zone:
        rtype = rr[2].rdata.__class__.__name__
        if rtype == "NS":
            record["auth"][domain].append(rr[2].rdata)
        elif rtype == "A":
            if not str(rr[2].rname).endswith(domain):
                dname = str(rr[2].rname) + domain
            else:
                dname = str(rr[2].rname)
            record[dname] = [rr[2].rdata]
    return record

def loadConfigure(fname = "name.conf"):
    domains = {}
    with open(fname, 'r') as fid:
        rows = fid.read().strip().split('\n')
        for row in rows:
            if row == "":
                continue
            tmp = row.split(' ')#0 domain 1: type 2: file or address
            domain = tmp[0]
            domains[domain] = {}
            if tmp[1] == "forward":
                domains[domain]["type"] = tmp[1]
                domains[domain]["forwarders"] = [tmp[2], int(tmp[3])]#check tmp2 ip address
            elif tmp[1] == "master":
                domains[domain]["type"] = tmp[1]
                domains[domain]["records"] = readZone(tmp[2], domain)
            else:
                print "unsupport type : ", tmp
    return domains


#pad a string to a length of multiple of 16
def pad_len_16(in_str):
    if len(in_str) % 16 != 0:
        pad_len = len(in_str) / 16 + 1
        return in_str.ljust(pad_len * 16)

#convert
def encodeurl(str_url, str_key):
    str_url = str_url.lower()
    AESobj = AES.new(pad_len_16(str_key), AES.MODE_CBC, 'This is an IV456')
    ciphertext = AESobj.encrypt(pad_len_16(str_url))
    encoder  = ''
    for c in ciphertext:
        encoder += bin(ord(c)).lstrip('0b')
    newurl = ''
    for i in range(len(str_url)):
        if encoder[i] == '1':
            newurl += str_url[i].upper()
        else:
            newurl += str_url[i]

    return newurl.strip()


class Cache:
    def __init__(self):
        self.c={}
    def get(self):
        return self.c
    def add(self, domain, replay):
        if not self.c.has_key(domain):
            self.c[domain] = {}
        # if not self.c[domain].has_key(replay.a.rname):
        self.c[domain][str(replay.a.rname)] = [replay.a.rdata]
        # self.c[domain][str(replay.a.rname)].append(replay.a.rdata)
        for rr in replay.auth:
            self.c[domain]["auth"] = {}
            if not self.c[domain]["auth"].has_key(str(rr.rname)):
                self.c[domain]["auth"][str(rr.rname)] = []
            self.c[domain]["auth"][str(rr.rname)].append(rr.rdata)
        for rr in replay.ar:
            # if not self.c[domain].has_key(rr.rname):
                # self.c[domain][str(rr.rname)] = []
            self.c[domain][str(rr.rname)] = [rr.rdata]
        print "cache update" 
        print self.c

def forward(replay, sock, address, port):
    # req_id = random.randint(0,50)
    req_id = 1
    qn = str(replay.q.qname).lower()
    req = DNSRecord(DNSHeader(id = req_id, qr = 1, aa = 0, ra = 0))
    #en_qn = encodeurl(qn, "asdf")
    en_qn = qn
    print "encode question domain: ", en_qn
    req.add_question(DNSQuestion(en_qn))
    # req = req.pack()
    # print req
    # sock.connect((dns2_address, dns2_port))
    sock.sendto(req.pack(), (address, port))
    # t1 = time.ctime()
    while(1):
        d = sock.recv(1024)
        resp = DNSRecord.parse(d.strip())
        # print resp
        print "TXID, resp: {}, req: {};".format(resp.header.id, req_id)
        print "Question domain, resp: {}, req: {};".format(resp.q.qname, en_qn)
        print "Answer domain, resp: {}, req: {};".format(resp.a.rname, en_qn)
        print "request packet: \n", req
        print "receive packet: \n",resp
        #check id 
        if resp.header.id == req_id \
            and resp.q.qname == en_qn:
            # and str(resp.a.rname) == en_qn:
            resp.a.rname = qn
            print "success"
            sock.close()
            break

    replay.add_answer(resp.a)
    valid_domains = []
    for r in resp.auth:
        valid_domains.append(str(r.rname))
    valid_domains = tuple(valid_domains)
    for rr in resp.ar:
        if str(rr.rname).endswith(valid_domains):
            print "bailiwick check success"
            print "Domain: {}, NS: {}".format( ",".join(list(valid_domains)), str(rr.rname))

            replay.add_ar(rr)
        else:
            print "bailiwick check fail"
            print "Domain: {}, NS: {}".format( ",".join(list(valid_domains)), str(rr.rname))
    for rr in resp.auth:
        replay.add_auth(rr)
    return replay
TTL = 1000
def dns_response(data):
    request = DNSRecord.parse(data)
    qname = request.q.qname
    qn = str(qname).lower()
    print "request query packet: ", request
    replay = DNSRecord(DNSHeader(id = request.header.id, qr = 1, aa = 0, ra = 0),  q = request.q) 
    flag = 0
    for domain in cache.get().keys():
        if qn.endswith(domain) or qn == domain:
            print "extract from cache"
            print cache.get()
            records = cache.get().get(domain)
            if records.has_key(qn):
                replay.add_answer(RR(rname = qname, rtype = request.q.qtype, rclass = 1, ttl = TTL, rdata = records[qn][0]))
                            ##AUTHOR INFORMATION 
                for rr in records["auth"]:
                    rrds = records["auth"][rr]# ns list 
                    for rrd in rrds:#ns
                        if records.has_key(str(rrd)):
                            replay.add_ar(RR(rname = str(rrd),  rtype = QTYPE.A, ttl = TTL, rclass = 1, rdata = records[str(rrd)][0] ))
                            replay.add_auth(RR(rname = rr, rtype = QTYPE.NS, ttl = TTL, rdata = rrd))

                print "retreive from cache!"
                return replay.pack()
            elif domains.has_key(domain) and domains[domain]["type"] == "master":
                            ##AUTHOR INFORMATION 
                for rr in records["auth"]:
                    rrds = records["auth"][rr]# ns list 
                    for rrd in rrds:#ns
                        if records.has_key(str(rrd)):
                            replay.add_ar(RR(rname = str(rrd),  rtype = QTYPE.A, ttl = TTL, rclass = 1, rdata = records[str(rrd)][0] ))
                            replay.add_auth(RR(rname = rr, rtype = QTYPE.NS, ttl = TTL, rdata = rrd))
                replay.add_answer(RR(rname = qname, rtype = request.q.qtype, rclass = 1, ttl = TTL, rdata =A(server_url)))

                print "retreive from cache!"
                return replay.pack()               
            else:
                ##forward
                try:
                    flag = 1
                    for rr in records["auth"]:
                        ns = str(records["auth"][rr][0])#ns list 
                        if not records.has_key(ns):
                            flag = 0
                            break
                        dns2_address =  str(records[ns][0])
                        print "cache dns2", dns2_address
                    if flag == 0:
                        break
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.bind((server_url, SENDPORT))
                    sock.settimeout(6)
                    dns2_port = 53
                    forward(replay, sock, dns2_address, dns2_port)
                    cache.add(domain, replay)
                    # print "cache update"
                    # print cache.get()
                    sock.close()
                    return replay.pack()
                except Exception as e:
                    print e
                    sock.close()
                    return replay.pack()

            

    #find in zone or forward    
    for domain in domains:
        print qn, domain
        if qn.endswith(domain) or qn == domain:
            domain_ins = domains[domain]
            if domain_ins["type"] == "master":
                #...
                print "zone type master, retrieve form local server"
                records = domain_ins["records"]
                print records, qn
                for rr in records["auth"]:
                    rrds = records["auth"][rr] # ns 
                    for rrd in rrds:
                        if records.has_key(str(rrd)): #contian ns
                            replay.add_ar(RR(rname = str(rrd), rtype = QTYPE.A, ttl = TTL, rclass = 1, rdata = records[str(rrd)][0]))
                            replay.add_auth(RR(rname = rr, rtype = QTYPE.NS, ttl = TTL, rclass = 1, rdata = rrd))
                if not records.has_key(qn):
                    replay.add_answer(RR(rname = qname, rtype = request.q.qtype, rclass = 1, ttl = TTL, rdata = A(server_url)))
                    return replay.pack()
                replay.add_answer(RR(rname = qname, rtype = request.q.qtype, rclass = 1, ttl = TTL, rdata = records[qn][0]))

                cache.add(domain, replay)
                print "Add cache"
                print cache.get()
                return replay.pack()
            elif domain_ins['type'] == "forward":
                dns2_address = domain_ins["forwarders"][0]
                dns2_port = domain_ins["forwarders"][1]
                print "zone type fowarder, forward to Addr: {}, Port: {}".format(dns2_address, dns2_port)
                try:

                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.bind((server_url, SENDPORT))
                    sock.settimeout(4)                  
                    forward(replay, sock, dns2_address, dns2_port)
                    cache.add(domain, replay)
                    sock.close()
                    return replay.pack()

                except Exception as e:
                    print e
                    sock.close()
                    # (socket.SHUT_RDWR)
                    return replay.pack()
            break

    return replay.pack()

class BaseRequestHandler(SocketServer.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        print "\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
                                               self.client_address[1])
        try:
            data = self.get_data()
            # print len(data), data.encode('hex')  # repr(data).replace('\\x', '')[1:-1]
            # dns_response(data)
            pack = dns_response(data)
            try:
                # time.sleep(1)
                self.send_data(pack)
            except Exception as e:
                pass
        except Exception:
            traceback.print_exc(file=sys.stderr)

class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()#receive data

    def send_data(self, data):
        #request[1] == scoket 

        return self.request[1].sendto(data, self.client_address) #send data


if __name__ == '__main__':
    print "Starting nameserver..."
    PORT =11111
    domains = loadConfigure()
    cache = Cache()
    SENDPORT = 12345
    server_url = "192.168.8.148"
    servers = [
        SocketServer.ThreadingUDPServer(("", PORT), UDPRequestHandler),
        #SocketServer.ThreadingTCPServer(('', PORT), TCPRequestHandler),
    ]
    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print "%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name)

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

