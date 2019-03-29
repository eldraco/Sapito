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
import re

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    IMPORTANT = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

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
                # TODO: Find the Authoritative Nameservers

                print('SrcMAC: {}, SrcIP: {}. #Questions: {}. #Additional Records {}. #Answers: {}'.format(shw, srcip, amount_of_questions, amount_of_additional_records, amount_of_answers))
                question_name = DNSlayer.fields['qd']

                # Process the questions
                for pos in range(0,amount_of_questions):
                    print('\tQuestion: {}'.format(question_name.qname.decode('utf-8')))
                    question_name = question_name.payload

                # Process the Answers
                answers_name = DNSlayer.fields['an']
                for pos in range(0,amount_of_answers):
                    # Do we have rdata?
                    if type(answers_name) == DNSRR:
                        if type(answers_name.rdata) == bytes:
                            print('\tAnswer Type: {}. Rdata name: {}'.format(answers_name.name, answers_name.rdata.decode('utf-8')))
                            details = answers_name.rdata.decode('utf-8').split(',')
                            for data1 in details:
                                # The split works even if there is no = in the string. In that case the string is returned inside an array
                                tuple = data1.split('=')
                                if 'model' in tuple[0].lower():
                                    if 'macbook' in tuple[1].lower():
                                        print(bcolors.IMPORTANT + '\t\tThe model of the MacBook is {}'.format(tuple[1]) + bcolors.ENDC)
                                    # Now process all the models of ipads we know. Data from https://www.theiphonewiki.com
                                    elif 'J208AP' in tuple[1]:
                                        print(bcolors.IMPORTANT + '\t\tThis is an iPad Pro (10.5-inch) (iPad7,4). Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                    elif 'J321AP' in tuple[1]:
                                        print(bcolors.IMPORTANT + '\t\tThis is an iPad Pro (12.9-inch) (3rd generation) Wi-Fi + Cellular model. It has 4 GB RAM and is available with 64, 256 and 512 GB of storage. Its identifier is iPad8,7. Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                    elif 'J127AP' in tuple[1]:
                                        print(bcolors.IMPORTANT + '\t\tThis is an iPad Pro (9.7-inch) (iPad6,3). Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                    elif 'J81AP' in tuple[1]:
                                        print(bcolors.IMPORTANT + '\t\tThis is the iPad Air 2 (iPad5,3). Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                    elif 'J72bAP' in tuple[1]:
                                        print(bcolors.IMPORTANT + '\t\tThis is the iPad (6th generation) (iPad7,6). Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                    elif 'J71bAP' in tuple[1]:
                                        print(bcolors.IMPORTANT + '\t\tThis is the iPad (6th generation) (iPad7,5). Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                    elif 'J128AP' in tuple[1]:
                                        print(bcolors.IMPORTANT + '\t\tThis is the iPad Pro (9.7-inch) (iPad6,4). Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                    elif 'J82AP' in tuple[1]:
                                        print(bcolors.IMPORTANT + '\t\tThis is the iPad Air 2 (iPad5,4). Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                    elif 'J318AP' in tuple[1]:
                                        print(bcolors.IMPORTANT + '\t\tThis is the iPad Pro (11-inch) Wi-Fi + Cellular model. It has 4 GB RAM and is available with 64, 256 and 512 GB of storage. Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                    elif 'J' in tuple[1] and 'AP' in tuple[1]:
                                        print(bcolors.IMPORTANT + '\t\tAn Apple device that we don\'t know!!. Search it manually in https://www.theiphonewiki.com. Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                    else:
                                        print('\t\tThe model of the device is {}'.format(tuple[1]))
                                elif 'osxvers' in tuple[0].lower():
                                    # Sometimes the str is broken wit 'ecolor' at the end and some 3 numbers
                                    try:
                                        temp = tuple[1].split('ecolor')[0]
                                    except TypeError:
                                        temp = tuple[1]
                                    print(bcolors.IMPORTANT + '\t\tThe osx version is {}'.format(temp) + bcolors.ENDC)
                                elif 'Elmedia Video Player' in tuple[0] and 'airplay' in tuple[0]:
                                    print('\t\tAirplay Enabled in this host.')

                                elif len(tuple) == 1:
                                    # Its a text, but not formated with , or =. so just interpret it.
                                    print('\t\tData to process: {}'.format(tuple[0]))
                                else:
                                    print('\t\tother data here?: {}'.format(tuple))
                        else:
                            print('\tAnswer Type: {}. Rdata name: {}'.format(answers_name.name, answers_name.rdata))
                    elif type(answers_name) == DNSRRSRV:
                        print('\tAnswer Type: {}. Target: {}. RRname: {}'.format(answers_name.name, answers_name.target.decode('utf-8'), answers_name.rrname.decode('utf-8')))
                        print('\t\tData to process: {}'.format(answers_name.target.decode('utf-8')))
                        print('\t\tData to process: {}'.format(answers_name.rrname.decode('utf-8')))
                    answers_name = answers_name.payload


                # Process the Additional records
                # Amount of additional records
                additional_name = DNSlayer.fields['ar']
                for pos in range(0,amount_of_additional_records):
                    if type(additional_name) == DNSRROPT:
                        print('\tAdditional Type: {}. Rdata name: {}'.format(additional_name.name, additional_name.rdata[0].name))
                    elif type(additional_name) == DNSRRNSEC:
                        print('\tAdditional Type: {}. RRName: {}'.format(additional_name.name, additional_name.rrname.decode('utf-8')))
                        # This may be a DNS PTR style ipv6
                    elif type(additional_name) == DNSRR:
                        if type(additional_name.rdata) == bytes:
                            print('\tAdditional Type: {}. Rdata Bytes: {}'.format(additional_name.name, additional_name.rdata))
                            # Additional record Name: DNS Resource Record. Rdata Bytes: b'rpBA=2D:F6:28:9B:87:99rpAD=82ae95302041rpHI=85e0df6055a0rpHN=2d48a2585755rpVr=164.16rpHA=0736452b945f'
                            rdata = additional_name.rdata.decode('utf-8')
                        elif type(additional_name.rdata) == dict:
                            print('\tAdditional Type: {}. Rdata Name: {}'.format(additional_name.name, additional_name.rdata[0].name))
                    elif type(additional_name) == DNSRRSRV:
                        print('\tAdditional Type: {}. Target: {}. RRname: {}'.format(additional_name.name, additional_name.target.decode('utf-8'), additional_name.rrname.decode('utf-8')))
                        print('\t\tData to process: {}'.format(additional_name.target.decode('utf-8')))
                        print('\t\tData to process: {}'.format(additional_name.rrname.decode('utf-8')))
                    else:
                        # Probably NoneType
                        print('Attention! Other type: {}'.format(type(additional_name)))
                    additional_name = additional_name.payload




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


