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
import macvendor

class bcolors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
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
            shw = pkt[Ether].src.upper()
            mac_vendor = macvendor.get_all(shw).manuf_long
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

                print(bcolors.HEADER + 'SrcMAC: {} ({}), SrcIP: {}. #Questions: {}. #Additional Records {}. #Answers: {}'.format(shw, mac_vendor, srcip, amount_of_questions, amount_of_additional_records, amount_of_answers) + bcolors.ENDC)
                question_name = DNSlayer.fields['qd']

                # Process the questions
                if amount_of_questions:
                    print('\tQuestions:')
                for pos in range(0,amount_of_questions):
                    if args.debug:
                        print('\t\t[Debug] Question Type: {}. Payload: {}'.format(question_name.qname, question_name.payload))
                    print('\t\t{}'.format(question_name.qname.decode('utf-8')))
                    question_name = question_name.payload

                # Process the Answers
                if amount_of_answers:
                    print('\tAnswers:')
                    answers_name = DNSlayer.fields['an']
                    # Process each answer one after the other. They are nested, so we need to process them by changing the value of answers_name on each loop
                    for pos in range(0,amount_of_answers):
                        if args.debug:
                            try:
                               print('\t\t[Debug] Answer Type: {}. Rdata: {}'.format(answers_name.name, answers_name.rdata))
                            except AttributeError:
                                print('\t\t[Debug] Answer Type: {}.'.format(answers_name.name))

                        # Process Generic DNSRR (Resource Records)
                        if type(answers_name) == DNSRR:

                            # There are many types of DNSRR, such as PTR
                            type_of_record = answers_name.type

                            # PTR
                            if type_of_record == 12: # As a RR, this is a PTR type
                                # If we have data in the rdata...
                                if type(answers_name.rdata) == bytes and answers_name.rdata:
                                    # Data can be interpreted in many ways. Lets try some.
                                    rdata = answers_name.rdata.decode('utf-8')
                                    comma_data = rdata.split(',')
                                    if len(comma_data) > 1:
                                        # It was split by , as Apple uses
                                        # Parse the rdata trying to understand each piece of information.
                                        for data1 in comma_data:
                                            # The split works even if there is no = in the string. In that case the string is returned inside an array
                                            tuple = data1.split('=')
                                            if 'model' in tuple[0].lower():
                                                if 'macbook' in tuple[1].lower():
                                                    print(bcolors.WARNING + '\t\tThe model of the MacBook is {}'.format(tuple[1]) + bcolors.ENDC)
                                                # Now process all the models of ipads we know. Data from https://www.theiphonewiki.com
                                                elif 'J208AP' in tuple[1]:
                                                    print(bcolors.WARNING + '\t\tThis is an iPad Pro (10.5-inch) (iPad7,4). Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                                elif 'J321AP' in tuple[1]:
                                                    print(bcolors.WARNING + '\t\tThis is an iPad Pro (12.9-inch) (3rd generation) Wi-Fi + Cellular model. It has 4 GB RAM and is available with 64, 256 and 512 GB of storage. Its identifier is iPad8,7. Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                                elif 'J127AP' in tuple[1]:
                                                    print(bcolors.WARNING + '\t\tThis is an iPad Pro (9.7-inch) (iPad6,3). Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                                elif 'J81AP' in tuple[1]:
                                                    print(bcolors.WARNING + '\t\tThis is the iPad Air 2 (iPad5,3). Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                                elif 'J72bAP' in tuple[1]:
                                                    print(bcolors.WARNING + '\t\tThis is the iPad (6th generation) (iPad7,6). Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                                elif 'J71bAP' in tuple[1]:
                                                    print(bcolors.WARNING + '\t\tThis is the iPad (6th generation) (iPad7,5). Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                                elif 'J128AP' in tuple[1]:
                                                    print(bcolors.WARNING + '\t\tThis is the iPad Pro (9.7-inch) (iPad6,4). Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                                elif 'J82AP' in tuple[1]:
                                                    print(bcolors.WARNING + '\t\tThis is the iPad Air 2 (iPad5,4). Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                                elif 'J318AP' in tuple[1]:
                                                    print(bcolors.WARNING + '\t\tThis is the iPad Pro (11-inch) Wi-Fi + Cellular model. It has 4 GB RAM and is available with 64, 256 and 512 GB of storage. Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                                elif 'J96AP' in tuple[1]:
                                                    print(bcolors.WARNING + '\t\tThis is the iPad mini 4 (iPad5,1). Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                                elif 'J207AP' in tuple[1]:
                                                    print(bcolors.WARNING + '\t\tThis is the iPad Pro (10.5-inch) (iPad7,3). Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                                elif 'J' in tuple[1] and 'AP' in tuple[1]:
                                                    print(bcolors.WARNING + '\t\tAn Apple device that we don\'t know!!. Search it manually in https://www.theiphonewiki.com. Model Number: {}'.format(tuple[1]) + bcolors.ENDC)
                                                else:
                                                    print('\t\tThe model of the device is {}'.format(tuple[1]))
                                            elif 'osxvers' in tuple[0].lower():
                                                # Sometimes the str is broken wit 'ecolor' at the end and some 3 numbers
                                                try:
                                                    temp = tuple[1].split('ecolor')[0]
                                                except TypeError:
                                                    temp = tuple[1]
                                                print(bcolors.WARNING + '\t\tThe osx version is {}'.format(temp) + bcolors.ENDC)
                                            elif len(tuple) == 1:
                                                # Only one position of text left. True when we receive only one piece of text that can not be spltted, or for the last part after the split
                                                try:
                                                    # In some rdata, after splitting with , we have some numbers at the end that we don't know what they are...
                                                    int(tuple[0])
                                                    continue
                                                except ValueError:
                                                    # Not a number
                                                    pass
                                                # Its a text, but not formated with , or =. so just print it.
                                                print('\t\tAnswer Type: {}. Rdata name: {}'.format(answers_name.name, answers_name.rdata.decode('utf-8')))
                                                print('\t\t\tData to process (DNSRR): {}'.format(tuple[0]))
                                            else:
                                                # We should not be here
                                                print('\t\tOther Answer data here not processed?: {}'.format(tuple))
                                        # Out of the for
                                    else:
                                        # It was not splitted by ,
                                        if '_homekit' in rdata:
                                            print(bcolors.WARNING + '\t\tThis host knows the Apple Homekit with id: {}'.format(rdata.split('.')[0]) + bcolors.ENDC)
                                        elif '_companion-link' in rdata:
                                            # Sometimes the companion-link DO have a name of device...
                                            if '_companion-link' in rdata.split('.')[1]:
                                                print(bcolors.WARNING + '\t\tThis host knows about the device called {} that has AirDrop active. And maybe other services from Apple.'.format(rdata.split('.')[0]) + bcolors.ENDC)
                                            # Sometimes the companion-link does not have a name of device...
                                            elif '_companion-link' in rdata.split('.')[0]:
                                                print(bcolors.WARNING + '\t\tThis host has AirDrop activated.'.format(rdata.split('.')[0]) + bcolors.ENDC)
                                        elif 'Elmedia Video Player' in rdata and 'airplay' in rdata:
                                            print('\t\tAirplay Enabled in this host.')
                                        elif 'mobdev' in rdata:
                                            inner_data = rdata.split('.')
                                            if len(inner_data) > 4:
                                                # Sometimes this record comes only with all the data
                                                protocol = rdata.split('.')[-3].split('_')[1]
                                                name_data = answers_name.rrname.decode('utf-8').split('.')
                                                location = rdata.split('.')[-5]
                                                # Check if the location really has the mac and IP addr
                                                if len(location.split('@')) > 1:
                                                    # It does
                                                    macaddr = location.split('@')[0]
                                                    ipaddr = location.split('@')[1]
                                                    if len(name_data) > 5:
                                                        # We have a name for the service
                                                        name = answers_name.rrname.decode('utf-8').split('.')[-6]
                                                        sub_name = answers_name.rrname.decode('utf-8').split('.')[-5]
                                                        print(bcolors.WARNING + '\t\t\tThis host has a PTR record to an iTunes WiFi Sync service called {}, on MAC {}, and IP {} using protocol {}'.format(name, macaddr, ipaddr, protocol) + bcolors.ENDC)
                                                    else:
                                                        # We don't have a name for the service
                                                        print(bcolors.WARNING + '\t\t\tThis host has a PTR record to an iTunes WiFi Sync service, on MAC {}, and IP {} using protocol {}'.format(macaddr, ipaddr, protocol) + bcolors.ENDC)
                                                else:
                                                    # We don't have the mac and ip addreess
                                                    if len(name_data) > 5:
                                                        # We have a name for the service
                                                        name = answers_name.rrname.decode('utf-8').split('.')[-6]
                                                        sub_name = answers_name.rrname.decode('utf-8').split('.')[-5]
                                                        print(bcolors.WARNING + '\t\t\tThis host has a PTR record to an iTunes WiFi Sync service called {} using protocol {}'.format(name, protocol) + bcolors.ENDC)
                                                    else:
                                                        # We don't have a name for the service
                                                        print(bcolors.WARNING + '\t\t\tThis host has a PTR record to an iTunes WiFi Sync service, using protocol {}'.format(protocol) + bcolors.ENDC)
                                            else:
                                                # Sometimes this record comes only with the name!
                                                name = answers_name.rrname.decode('utf-8').split('.')[-5]
                                                app_protocol = answers_name.rrname.decode('utf-8').split('.')[-4]
                                                protocol = answers_name.rrname.decode('utf-8').split('.')[-3].split('_')[1]
                                                print(bcolors.WARNING + '\t\t\tThis host has a PTR record to an iTunes WiFi Sync service called {}, using the application protocol {} and transport protocol {}'.format(name, app_protocol, protocol) + bcolors.ENDC)
                                        elif len(rdata.split('.')) == 3:
                                            # This means that we only have a name and then .local.
                                            print(bcolors.IMPORTANT + '\t\tThe name of this device by PTR is {}'.format(rdata.split('.')[0]) + bcolors.ENDC)
                                        else:
                                            print('\t\tAnswer Type: {}. Rdata name: {}'.format(answers_name.name, answers_name.rdata.decode('utf-8')))
                                            print('\t\t\tData to process: {}'.format(answers_name.rdata.decode('utf-8')))
                                else:
                                    # In case we receive something not formated as a Bytes structure
                                    print('\t\tWeird situation. Check. Answer Type (str): {}. Rdata name: {}'.format(answers_name.name, answers_name.rdata))
                            # Type TXT
                            elif type_of_record == 16: # As a RR, this is a TXT type
                                name = answers_name.rrname.decode('utf-8')
                                data = answers_name.rdata.decode('utf-8')
                                print('\t\tAnswer Type: TXT. RName: {}. Rdata: {}'.format(name, data))
                                print('\t\t\tTo Process. RName: {}. Rdata: {}'.format(name, data))
                            # Type A
                            elif type_of_record == 1: # As a RR, this is a A type
                                name = answers_name.rrname.decode('utf-8')
                                ip = answers_name.rdata
                                print(bcolors.WARNING + '\t\tThe IPv4 address of this device named {} is {}'.format(name, ip) + bcolors.ENDC)
                            # Type AAAA
                            elif type_of_record == 28: # As a RR, this is a AAAA type
                                name = answers_name.rrname.decode('utf-8')
                                ip = answers_name.rdata
                                print(bcolors.WARNING + '\t\tThe IPv6 address of this device named {} is {}'.format(name, ip) + bcolors.ENDC)
                            # Type NSEC
                            elif type_of_record == 47: # As a RR, this is a NSEC type
                                name = answers_name.rrname.decode('utf-8')
                                data = answers_name.rdata.decode('utf-8')
                                print('\t\tAnswer Type: NSEC. RName: {}. Rdata: {}'.format(name, data))
                                print('\t\t\tTo Process. RName: {}. Rdata: {}'.format(name, data))
                            # Type NS
                            elif type_of_record == 2: # As a RR, this is a NS
                                name = answers_name.rrname.decode('utf-8')
                                data = answers_name.rdata.decode('utf-8')
                                print('\t\tAnswer Type: NS. RName: {}. Rdata: {}'.format(name, data))
                                print('\t\t\tTo Process. RName: {}. Rdata: {}'.format(name, data))
                            # Type CNAME
                            elif type_of_record == 5: # As a RR, this is a CNAME
                                name = answers_name.rrname.decode('utf-8')
                                data = answers_name.rdata.decode('utf-8')
                                print('\t\tAnswer Type: CNAME. RName: {}. Rdata: {}'.format(name, data))
                                print('\t\t\tTo Process. RName: {}. Rdata: {}'.format(name, data))
                            # Type SOA
                            elif type_of_record == 6: # As a RR, this is a SOA
                                name = answers_name.rrname.decode('utf-8')
                                data = answers_name.rdata.decode('utf-8')
                                print('\t\tAnswer Type: CNAME. RName: {}. Rdata: {}'.format(name, data))
                                print('\t\t\tTo Process. RName: {}. Rdata: {}'.format(name, data))
                            # Type HINFO
                            elif type_of_record == 13: # As a RR, this is a HINFO
                                name = answers_name.rrname.decode('utf-8')
                                data = answers_name.rdata.decode('utf-8')
                                print('\t\tAnswer Type: HINFO. RName: {}. Rdata: {}'.format(name, data))
                                print('\t\t\tTo Process. RName: {}. Rdata: {}'.format(name, data))
                            # Type MX
                            elif type_of_record == 15: # As a RR, this is a MX
                                name = answers_name.rrname.decode('utf-8')
                                data = answers_name.rdata.decode('utf-8')
                                print('\t\tAnswer Type: MX. RName: {}. Rdata: {}'.format(name, data))
                                print('\t\t\tTo Process. RName: {}. Rdata: {}'.format(name, data))
                            # Type RP
                            elif type_of_record == 17: # As a RR, this is a RP
                                name = answers_name.rrname.decode('utf-8')
                                data = answers_name.rdata.decode('utf-8')
                                print('\t\tAnswer Type: RP. RName: {}. Rdata: {}'.format(name, data))
                                print('\t\t\tTo Process. RName: {}. Rdata: {}'.format(name, data))
                            # Type OPT
                            elif type_of_record == 41: # As a RR, this is a OPT
                                name = answers_name.rrname.decode('utf-8')
                                data = answers_name.rdata.decode('utf-8')
                                print('\t\tAnswer Type: OPT. RName: {}. Rdata: {}'.format(name, data))
                                print('\t\t\tTo Process. RName: {}. Rdata: {}'.format(name, data))
                            # Type RRSIG
                            elif type_of_record == 46: # As a RR, this is a RRSIG
                                name = answers_name.rrname.decode('utf-8')
                                data = answers_name.rdata.decode('utf-8')
                                print('\t\tAnswer Type: RSIG. RName: {}. Rdata: {}'.format(name, data))
                                print('\t\t\tTo Process. RName: {}. Rdata: {}'.format(name, data))
                            # Type NSEC3
                            elif type_of_record == 50: # As a RR, this is a NSEC3
                                name = answers_name.rrname.decode('utf-8')
                                data = answers_name.rdata.decode('utf-8')
                                print('\t\tAnswer Type: NSEC3. RName: {}. Rdata: {}'.format(name, data))
                                print('\t\t\tTo Process. RName: {}. Rdata: {}'.format(name, data))
                            # Type TLSA
                            elif type_of_record == 52: # As a RR, this is a TLSA
                                name = answers_name.rrname.decode('utf-8')
                                data = answers_name.rdata.decode('utf-8')
                                print('\t\tAnswer Type: TLSA. RName: {}. Rdata: {}'.format(name, data))
                                print('\t\t\tTo Process. RName: {}. Rdata: {}'.format(name, data))
                            # Type SPF
                            elif type_of_record == 99: # As a RR, this is a SPF
                                name = answers_name.rrname.decode('utf-8')
                                data = answers_name.rdata.decode('utf-8')
                                print('\t\tAnswer Type: SPF. RName: {}. Rdata: {}'.format(name, data))
                                print('\t\t\tTo Process. RName: {}. Rdata: {}'.format(name, data))
                            else:
                                print('\t\tWe have a new type of TXT type of answer. Check')

                        # In the answer section, SRV records say where you can find this resource
                        elif type(answers_name) == DNSRRSRV:
                            print('\t\tServices Offered in the Answers:')
                            type_of_record = answers_name.type
                            # Type SRV
                            if type_of_record == 33: # This is a SRV

                                rrname = answers_name.rrname.decode('utf-8')
                                data = rrname.split('.')
                                service = data[-4]
                                protocol = data[-3].split('_')[1]
                                location = data[-5]
                                if len(location.split('@')) > 1:
                                    # The location really has a mac and IP
                                    macaddr = location.split('@')[0]
                                    ipaddr = location.split('@')[1]

                                # Do we have an rdata?
                                if hasattr(answers_name, 'rdata'):
                                    # We do have the rdata

                                    if type(answers_name.rdata) == bytes:
                                        # Values like a name
                                        rdata = answers_name.rdata.decode('utf-8')
                                        try:
                                            name = rdata.split('.')[-3]
                                        except IndexError:
                                            # Some rdata do not have the .local, only the name.
                                            name = rdata.split('.')[0]
                                    else:
                                        # Values like an AAAA address
                                        rdata = answers_name.rdata
                                else:
                                    # We don't have the rdata. Some devices do not send it
                                    name = answers_name.target.decode('utf-8').split('.')[-3]

                                if '_apple' in service:
                                    if hasattr(answers_name, 'rdata') and type(answers_name.rdata) == bytes:
                                        # Values like a name b'pepe'. There is no extra data
                                        if 'mobdev2' in service:
                                            print(bcolors.WARNING + '\t\t\tThis host named {} offers the service iTunes WiFi Sync in the MAC {}, IP {}, protocol {}'.format(name, macaddr, ipaddr, protocol ) + bcolors.ENDC)
                                        else:
                                            print(bcolors.WARNING + '\t\t\tThis host named {} offers the service {} in the MAC {}, IP {}, protocol {}'.format(name, service, macaddr, ipaddr, protocol ) + bcolors.ENDC)
                                    elif not hasattr(answers_name, 'rdata'):
                                        # Values like an AAAA address
                                        # Here the rdata has an IP address
                                        if 'mobdev2' in service:
                                            print(bcolors.WARNING + '\t\t\tThis host offers the service iTunes WiFi Sync in the MAC {}, IP {}, protocol {}. As name was offered the IP {}'.format(macaddr, ipaddr, protocol, rdata ) + bcolors.ENDC)
                                        else:
                                            print(bcolors.WARNING + '\t\t\tThis host offers some service ??? in the MAC {}, IP {}, protocol {}. As name was offered the IP {}'.format(macaddr, ipaddr, protocol, rdata ) + bcolors.ENDC)
                                elif '_amzn' in service:
                                    # Example: amzn.dmgr:806A9BE922A574669B9299828FD6B3D3:U/5Z9LxhBX:79035._amzn-wplay._tcp.local.
                                    name = answers_name.target.decode('utf-8').split('.')[:-2][0]
                                    data = answers_name.rrname.decode('utf-8').split('.')[:-4]
                                    if 'wplay' in service:
                                        print(bcolors.WARNING + '\t\t\tThis host named {} (name based on its IP) offers the service Amazon FireTV with data {}'.format(name, data) + bcolors.ENDC)
                                elif '_raop' in service:
                                    # Service for remote audio
                                    if len(location.split('@')) < 2:
                                        # Some devices do not send a mac at all nor ip, only a name
                                        print(bcolors.WARNING + '\t\t\tThis host named {} offers the service of Remote Audio Output Protocol on the device named {}'.format(name, macaddr, location) + bcolors.ENDC)

                                    else:
                                        # Some devices do not send both mac and the IP address but a mac and a 'name'
                                        if len(ipaddr.split('.')) < 3:
                                            print(bcolors.WARNING + '\t\t\tThis host named {} offers the service of Remote Audio Output Protocol on the MAC address {} and device with name {}'.format(name, macaddr, ipaddr) + bcolors.ENDC)
                                        else:
                                            print(bcolors.WARNING + '\t\t\tThis host named {} offers the service of Remote Audio Output Protocol on the MAC address {} with IP adddress {}'.format(name, macaddr, ipaddr) + bcolors.ENDC)

                            else:
                                print('\t\t\tUnknown SRV Type. Target: {}. RRname: {}'.format(answers_name.target.decode('utf-8'), answers_name.rrname.decode('utf-8')))
                                print('\t\t\t\tData to process (DNSRRSRV): {}'.format(answers_name.target.decode('utf-8')))
                                print('\t\t\t\tData to process (DNSRRSRV): {}'.format(answers_name.rrname.decode('utf-8')))

                        # In the answer section, TXT records give additional info about a resource reoord
                        elif type(answers_name) == DNSRRTXT:
                            print('\t\t\tType {}. '.format(answers.name))

                        # Loop
                        answers_name = answers_name.payload


                # Process the Additional records
                # Amount of additional records
                if amount_of_additional_records:
                    print('\tAdditional Records:')
                    additional_name = DNSlayer.fields['ar']
                    for pos in range(0,amount_of_additional_records):
                        if type(additional_name) == DNSRROPT:
                            if args.debug:
                                print('\t\t[Debug] Additional Record. Type: {}. Rdata: {}'.format(additional_name.name, additional_name.rdata))
                            print('\t\tType: {}. Rdata name: {}'.format(additional_name.name, additional_name.rdata[0].name))
                        elif type(additional_name) == DNSRRNSEC:
                            if args.debug:
                                print('\t\t[Debug] Additional Record. Type: {}. RRname: {}'.format(additional_name.name, additional_name.rrname))
                            print('\t\tType: {}. RRName: {}'.format(additional_name.name, additional_name.rrname.decode('utf-8')))
                        elif type(additional_name) == DNSRR:
                            if args.debug:
                                print('\t\t[Debug] Additional Record. Type: {}. Rdata: {}'.format(additional_name.name, additional_name.rdata))
                            # If its a Bytes structure and is not empty
                            if type(additional_name.rdata) == bytes and additional_name.rdata:
                                print('\t\tType: {}. Rdata Bytes: {}'.format(additional_name.name, additional_name.rdata))
                                # Lets parts this shit of string b'rpBA=2D:F6:28:9B:87:99rpAD=82ae95302041rpHI=85e0df6055a0rpHN=2d48a2585755rpVr=164.16rpHA=0736452b945f'
                                rdata = additional_name.rdata.decode('utf-8').split('=')
                                values = {}
                                temp_name = rdata[0]
                                for data in rdata[1:]:
                                    values[temp_name] =  data[:-4]
                                    temp_name = data[-4:]
                                # To the last, add the last 4 bytes
                                values[list(values.keys())[-1]] += temp_name
                                # Print now
                                for key in values:
                                    print('\t\t\tName: {}. Value: {}'.format(key, values[key]))

                            elif type(additional_name.rdata) == dict:
                                print('\t\tType: {}. Rdata Name: {}'.format(additional_name.name, additional_name.rdata[0].name))
                        elif type(additional_name) == DNSRRSRV:
                            print('\t\tType: {}. Target: {}. RRname: {}'.format(additional_name.name, additional_name.target.decode('utf-8'), additional_name.rrname.decode('utf-8')))
                            print('\t\t\tData to process: {}'.format(additional_name.target.decode('utf-8')))
                            print('\t\t\tData to process: {}'.format(additional_name.rrname.decode('utf-8')))
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
    parser.add_argument('-f', '--filter', help='Tcpdump style filter to use.', action='store', required=False, type=str)

    args = parser.parse_args()

    # Reload the file of Mac vendors
    macvendor.refresh()

    if args.interface:
        sniff(iface=args.interface,prn=do,store=0, filter=args.filter)
    elif args.readfile:
        sniff(offline=args.readfile,prn=do,store=0, filter=args.filter)


