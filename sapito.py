#!/usr/bin/env python
# Seba Garcia whatever
# Vero Valeros is coauthor

from os import listdir
from os.path import isfile, join
import pickle
import argparse
import sys
from datetime import datetime
from scapy.all import *


def do(pkt):
    """
    Do something
    """
    if IP in pkt and UDP in pkt:
        if pkt[UDP].dport == 5353:
            shw = pkt[Ether].src
            srcip = pkt[IP].src
            UDPlayer = pkt[UDP]
            #len = UDPlayer.len
            if DNS in UDPlayer:
                DNSlayer = pkt[UDP][DNS]
                # fields = DNSlayer.fields # length, id, qtype, name, qd, an, ar qr, opcode, aa,tc,rd,ra,z,ad,cd,rcode,qdcount,ancount,nscount,arcount
                # Amount of Questions: DNSlayer.qdcount
                amount_of_questions = DNSlayer.qdcount
                amount_of_additional_records = DNSlayer.arcount
                amount_of_answers = DNSlayer.ancount
                print('SrcMAC: {}, SrcIP: {}. Name: , #Questions: {}. #Additional Records {}. #Answers: {}'.format(shw, srcip, amount_of_questions, amount_of_additional_records, amount_of_answers))
                question_name = DNSlayer.fields['qd']

                # Process the questions
                for pos in range(0,amount_of_questions):
                    print('\tQuestion: {}'.format(question_name.qname.decode('utf-8')))
                    question_name = question_name.payload

                # Process the Answers
                answers_name = DNSlayer.fields['an']
                for pos in range(0,amount_of_answers):
                    #print('\tAnswer record Type: {}. Rdata name: {}'.format(answers_name.name, answers_name.rdata.decode('utf-8')))
                    if type(answers_name.rdata) == bytes:
                        print('\tAnswer record Type: {}. Rdata name: {}'.format(answers_name.name, answers_name.rdata.decode('utf-8')))
                    else:
                        print('\tAnswer record Type: {}. Rdata name: {}'.format(answers_name.name, answers_name.rdata))
                    answers_name = answers_name.payload
                # Find if the Apple is using the airdrop
                # 	Answer record Type: DNS Resource Record. Rdata name: model=MacBookAir7,2osxvers=18
                # 	Answer record Type: DNS Resource Record. Rdata name: 2deae6e5bd95._airdrop._tcp.local.




                # Process the Additional records
                # Amount of additional records
                additional_name = DNSlayer.fields['ar']
                for pos in range(0,amount_of_additional_records):
                    if type(additional_name) == DNSRROPT:
                        print('\tAdditional record Name: {}. Rdata name: {}'.format(additional_name.name, additional_name.rdata[0].name))
                    elif type(additional_name) == DNSRRNSEC:
                        print('\tAdditional record Name: {}. RRName: {}'.format(additional_name.name, additional_name.rrname.decode('utf-8')))
                        # This may be a DNS PTR style ipv6
                    elif type(additional_name) == DNSRR:
                        if type(additional_name.rdata) == bytes:
                            print('\tAdditional record Name: {}. Rdata Bytes: {}'.format(additional_name.name, additional_name.rdata))
                        elif type(additional_name.rdata) == dict:
                            print('\tAdditional record Name: {}. Rdata Name: {}'.format(additional_name.name, additional_name.rdata[0].name))
                    elif type(additional_name) == DNSRRSRV:
                        print('DNSRRSRV')
                    else:
                        # Probably NoneType
                        print('Attention! Other type: {}'.format(type(additional_name)))
                    additional_name = additional_name.payload
                # Process the records
                # Additional record Name: DNS Resource Record. Rdata Bytes: b'rpBA=2D:F6:28:9B:87:99rpAD=82ae95302041rpHI=85e0df6055a0rpHN=2d48a2585755rpVr=164.16rpHA=0736452b945f'
                # Additional record Name: DNS Resource Record. Rdata Bytes: b'model=MacBookAir7,2osxvers=18'




# Main
####################
if __name__ == '__main__':  
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='Amount of verbosity. This shows more info about the results.', action='store', required=False, type=int)
    parser.add_argument('-d', '--debug', help='Amount of debugging. This shows inner information about the flows.', action='store', required=False, type=int)
    parser.add_argument('-r', '--readfile', help='Name of the pcap file to read.', action='store', required=False, type=str)
    parser.add_argument('-i', '--interface', help='Name of the interface to use.', action='store', required=False, type=str)

    args = parser.parse_args()

    if args.interface:
        sniff(iface=args.interface,prn=do,store=0)
    elif args.readfile:
        sniff(offline=args.readfile,prn=do,store=0)


