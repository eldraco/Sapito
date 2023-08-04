#!/usr/bin/env python
# Authors:
# Sebastian Garcia, sebastian.garcia@agents.fel.cvut.cz, eldraco@gmail.com
# Veronica Valeros, vero.valeros@gmail.com, valerver@fel.cvut.cz
# Stratosphere Laboratory, Czech Technical University in Prague

import argparse
import macvendor
from scapy.all import *
from datetime import datetime

class bcolors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    IMPORTANT = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    NORMAL = '\033[8m'

# Store info about the clients
# The format of the clients is: {'MAC': 'name'}
clients = {}

def add_client(shw, srcip, name='unknown'):
    """ Add client to our list"""
    try:
        data = clients[shw]
        if 'unknown' in data['name']:
            data['name'] = name
            clients[shw] = data
    except KeyError:
        data = {}
        data['srcip'] = srcip
        data['name'] = name
        clients[shw] = data

def get_client(shw):
    """ Get the client """
    return clients[shw]

def do(pkt):
    """
    Do something
    """
    if IP in pkt and UDP in pkt:
        if pkt[UDP].dport == 5353:
            shw = pkt[Ether].src.upper()
            mac_vendor = macvendor.get_all(shw).manuf_long
            srcip = pkt[IP].src
            add_client(shw, srcip)
            UDPlayer = pkt[UDP]
            #len = UDPlayer.len
            if DNS in UDPlayer:
                DNSlayer = pkt[UDP][DNS]
                # The DNSlayer.fields are:
                #  - length,id,qtype,name,qd,an,ar qr,opcode,
                #    aa,tc,rd,ra,z,ad,cd,rcode,qdcount,ancount,
                #    nscount,arcount
                num_questions = DNSlayer.qdcount
                num_additional_records = DNSlayer.arcount
                num_answers = DNSlayer.ancount
                # TODO: Find the Authoritative Nameservers

                print(bcolors.HEADER + f"\033[36m{datetime.now()}\033[95m | SrcMAC: \033[36m{shw}\033[95m | Vendor: \033[36m{mac_vendor}\033[95m | SrcIP: \033[36m{srcip}\033[95m | Name: \033[36m{get_client(shw)['name']}\033[95m | Questions: \033[36m{num_questions}\033[95m | Additional Records: \033[36m{num_additional_records}\033[95m | Answers: \033[36m{num_answers}\033[95m" + bcolors.ENDC)
                try:
                    question_name = DNSlayer.fields['qd']
                except KeyError:
                    return True


                #####################
                # Process the questions
                #
                print(bcolors.HEADER + f' > Questions: \033[36m{num_questions}\033[95m' + bcolors.ENDC)
                for pos in range(0,num_questions):
                    if args.debug:
                        print('\t\t[Debug] Question Type: {}. Payload: {}'.format(question_name.qname, question_name.payload))
                    try:
                        print('\t\t{}'.format(question_name.qname.decode('utf-8')))
                    except AttributeError:
                        # Some versions of scapy do not give a Byte String
                        print('\t\t{}'.format(question_name))
                    try:
                        question_name = question_name.payload
                    except AttributeError:
                        question_name = ""


                #####################
                # Process the Answers
                #
                print(bcolors.HEADER + f' > Answers: \033[36m{num_answers}\033[95m' + bcolors.ENDC)
                # We will try to parse these answers by type
                if num_answers:
                    try:
                        answers_name = DNSlayer.fields['an']
                    except KeyError:
                        return True

                    # To process the answers we need to iterate over all of them
                    #  - Process each answer one after the other.
                    #  - They are nested, so we need to process them by changing
                    #    the value of answers_name on each loop
                    for pos in range(0,num_answers):
                        rdata = False
                        rrname = False

                        # See if the rdata come as byte strings or not
                        if hasattr(answers_name, 'rdata'):
                            if type(answers_name.rdata) == list:
                                rdata = answers_name.rdata
                            elif type(answers_name.rdata) == bytes:
                                # See the conversion to list with []
                                rdata = [answers_name.rdata.decode('utf-8')]
                            else:
                                # See the conversion to list with []
                                rdata = [answers_name.rdata]
                        else:
                            rdata = False

                        # See if the rrname come as byte strings or not
                        try:
                            rrname = answers_name.rrname.decode('utf-8')
                        except AttributeError:
                            # Some versions of scapy do not give a Byte String
                            rrname = answers_name.rrname

                        if args.debug:
                            try:
                                print('\t\t[Debug] Answer Type: {}. Rdata: {}'.format(answers_name.name, rdata))
                            except AttributeError:
                                print('\t\t[Debug] Answer Type: {}.'.format(answers_name.name))

                        # Process Generic DNSRR (Resource Records)
                        if type(answers_name) == DNSRR:

                            # There are many types of DNSRR, such as PTR
                            type_of_record = answers_name.type

                            # PTR
                            if type_of_record == 12: # As a RR, this is a PTR type

                                # If we have data in the rdata...
                                if rdata:
                                    # There may be one or more rdata parts, so just iterate over them.
                                    for inner_data in rdata:
                                        comma_data = inner_data.split(',')
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
                                                else:
                                                    # We should not be here
                                                    print('\t\tOther Answer data here not processed?: {}'.format(tuple))
                                            # Out of the for
                                        else:
                                            # It was not splitted by ,
                                            if '_homekit' in inner_data:
                                                print(bcolors.WARNING + '\t\tThis host knows the Apple Homekit with id: {}'.format(inner_data.split('.')[0]) + bcolors.ENDC)
                                            elif '_companion-link' in inner_data:
                                                # Sometimes the companion-link DO have a name of device...
                                                if '_companion-link' in inner_data.split('.')[1]:
                                                    print(bcolors.WARNING + '\t\tThis host knows about the device named {} that has AirDrop active. And maybe other services from Apple.'.format(inner_data.split('.')[0]) + bcolors.ENDC)
                                                # Sometimes the companion-link does not have a name of device...
                                                elif '_companion-link' in inner_data.split('.')[0]:
                                                    print(bcolors.WARNING + '\t\tThis host has AirDrop activated.'.format(inner_data.split('.')[0]) + bcolors.ENDC)
                                            elif 'Elmedia Video Player' in inner_data and 'airplay' in inner_data:
                                                print('\t\tAirplay Enabled in this host.')
                                            elif 'mobdev' in inner_data:
                                                more_inner_data = inner_data.split('.')
                                                if len(more_inner_data) > 4:
                                                    # Sometimes this record comes only with all the data
                                                    protocol = more_inner_data[-3].split('_')[1]
                                                    name_data = rrname.split('.')
                                                    location = more_inner_data[-5]
                                                    # Check if the location really has the mac and IP addr
                                                    if len(location.split('@')) > 1:
                                                        # It does
                                                        macaddr = location.split('@')[0]
                                                        ipaddr = location.split('@')[1]
                                                        if len(name_data) > 5:
                                                            # We have a name for the service
                                                            name = rrname.split('.')[-6]
                                                            sub_name = rrname.split('.')[-5]
                                                            print(bcolors.WARNING + '\t\t\tThis host has a PTR record to an iTunes WiFi Sync service named {}, on MAC {}, and IP {} using protocol {}'.format(name, macaddr, ipaddr, protocol) + bcolors.ENDC)
                                                        else:
                                                            # We don't have a name for the service
                                                            print(bcolors.WARNING + '\t\t\tThis host has a PTR record to an iTunes WiFi Sync service, on MAC {}, and IP {} using protocol {}'.format(macaddr, ipaddr, protocol) + bcolors.ENDC)
                                                    else:
                                                        # We don't have the mac and ip addreess
                                                        if len(name_data) > 5:
                                                            # We have a name for the service
                                                            name = rrname.split('.')[-6]
                                                            sub_name = rrname.split('.')[-5]
                                                            print(bcolors.WARNING + '\t\t\tThis host has a PTR record to an iTunes WiFi Sync service named {} using protocol {}'.format(name, protocol) + bcolors.ENDC)
                                                        else:
                                                            # We don't have a name for the service
                                                            print(bcolors.WARNING + '\t\t\tThis host has a PTR record to an iTunes WiFi Sync service, using protocol {}'.format(protocol) + bcolors.ENDC)
                                                else:
                                                    # Sometimes this record comes only with the name!
                                                    name = rrname.split('.')[-5]
                                                    app_protocol = rrname.split('.')[-4]
                                                    protocol = rrname.split('.')[-3].split('_')[1]
                                                    print(bcolors.WARNING + '\t\t\tThis host has a PTR record to an iTunes WiFi Sync service named {}, using the application protocol {} and transport protocol {}'.format(name, app_protocol, protocol) + bcolors.ENDC)
                                            elif len(inner_data.split('.')) == 3:
                                                # This means that we only have a name and then .local.
                                                name = inner_data.split('.')[0]
                                                print(bcolors.IMPORTANT + '\t\tThe name of this device by PTR is {}'.format(name) + bcolors.ENDC)
                                                add_client(shw, srcip, name)
                                            else:
                                                print('\t\tAnswer Type: {}. Rdata to process: {}'.format(answers_name.name, inner_data))
                                else:
                                    # In case we receive something not formated as a Bytes structure
                                    print('\t\tWeird situation. No rdata?. Check. Answer Type (str): {}. Rdata name: {}'.format(answers_name.name, rdata))

                            # Type TXT
                            elif type_of_record == 16: # As a RR, this is a TXT type
                                try:
                                    protocol = rrname.split('.')[-3].split('_')[1]
                                    service = rrname.split('.')[-4]
                                    name = rrname.split('.')[-5]
                                    if 'companion-link' in service:
                                        print(bcolors.WARNING + '\t\tThis host named {}, offers the service of AirDrop using protocol {}.'.format(name, protocol) + bcolors.ENDC)
                                        # Example of rdata: [b'rpBA=92:66:E0:E7:19:13', b'rpVr=164.16', b'rpAD=523dffb16051']
                                        for inner_data in rdata:
                                            try:
                                                temp_inner_data = inner_data.decode('utf-8').split('=')
                                                print('\t\t\tVariable {}, Data: {}.'.format(temp_inner_data[0], temp_inner_data[1]))
                                            except:
                                                # Maybe rdata is not spliteable with =? or is not a bytes?
                                                print('\t\tAnswer Type: TXT that we couldn\'t parse. Check 1. RName: {}. Rdata to process: {}'.format(rrname, rdata))
                                    elif '_device-info' in service:
                                        # Example: [b'model=MacBookPro14,1', b'osxvers=18', b'ecolor=157,157,160']
                                        print(bcolors.WARNING + '\t\tThis host is a:' + bcolors.ENDC)
                                        for inner_data in rdata:
                                            try:
                                                temp_inner_data = inner_data.decode('utf-8').split('=')
                                                if 'model' in temp_inner_data[0] and 'mac' in temp_inner_data[1].lower():
                                                    print(bcolors.WARNING + '\t\t\tMacBook model: {}'.format(temp_inner_data[1]) + bcolors.ENDC)
                                                elif 'osx' in temp_inner_data[0]:
                                                    print(bcolors.WARNING + '\t\t\tOSX Version: {}'.format(temp_inner_data[1]) + bcolors.ENDC)
                                                elif 'color' in temp_inner_data[0]:
                                                    print(bcolors.WARNING + '\t\t\tSome colors data: {}'.format(temp_inner_data[1]) + bcolors.ENDC)
                                            except:
                                                # Maybe rdata is not spliteable with =? or is not a bytes?
                                                print('\t\tAnswer Type: TXT that we couldn\'t parse. Check 11. RName: {}. Rdata to process: {}'.format(rrname, rdata))
                                    elif '_airdrop' in service:
                                        # Example rdata: [b'flags=507']
                                        print(bcolors.WARNING + '\t\tThis host offers the AirDrop service with data: {}'.format(rdata[0].decode('utf-8')) + bcolors.ENDC)
                                    else:
                                        print('\t\tAnswer Type: TXT that we couldn\'t parse. Check 2. RName: {}. Rdata to process: {}'.format(rrname, rdata))
                                except:
                                    print('\t\tAnswer Type: TXT that we couldn\'t parse. Check 3. RName: {}. Rdata to process: {}'.format(rrname, rdata))

                            # Type A
                            elif type_of_record == 1: # As a RR, this is a A type
                                name = rrname
                                ip = rdata
                                print(bcolors.WARNING + '\t\tThe IPv4 address of this device named {} is {}'.format(name, ip) + bcolors.ENDC)
                            # Type AAAA
                            elif type_of_record == 28: # As a RR, this is a AAAA type
                                name = rrname
                                ip = rdata
                                print(bcolors.WARNING + '\t\tThe IPv6 address of this device named {} is {}'.format(name, ip) + bcolors.ENDC)
                            # Type NSEC
                            elif type_of_record == 47: # As a RR, this is a NSEC type
                                print('\t\tAnswer Type: NSEC. RName: {}. Rdata to process: {}'.format(rrname, rdata))
                            # Type NS
                            elif type_of_record == 2: # As a RR, this is a NS
                                print('\t\tAnswer Type: NS. RName: {}. Rdata to process: {}'.format(rrname, rdata))
                            # Type CNAME
                            elif type_of_record == 5: # As a RR, this is a CNAME
                                print('\t\tAnswer Type: CNAME. RName: {}. Rdata to process: {}'.format(rrname, rdata))
                            # Type SOA
                            elif type_of_record == 6: # As a RR, this is a SOA
                                print('\t\tAnswer Type: SOA. RName: {}. Rdata to process: {}'.format(rrname, rdata))
                            # Type HINFO
                            elif type_of_record == 13: # As a RR, this is a HINFO
                                print('\t\tAnswer Type: HINFO. RName: {}. Rdata to process: {}'.format(rrname, rdata))
                            # Type MX
                            elif type_of_record == 15: # As a RR, this is a MX
                                print('\t\tAnswer Type: MX. RName: {}. Rdata to process: {}'.format(rrname, rdata))
                            # Type RP
                            elif type_of_record == 17: # As a RR, this is a RP
                                print('\t\tAnswer Type: RP. RName: {}. Rdata to process: {}'.format(rrname, rdata))
                            # Type OPT
                            elif type_of_record == 41: # As a RR, this is a OPT
                                print('\t\tAnswer Type: OPT. RName: {}. Rdata to process: {}'.format(rrname, rdata))
                            # Type RRSIG
                            elif type_of_record == 46: # As a RR, this is a RRSIG
                                print('\t\tAnswer Type: RSIG. RName: {}. Rdata to process: {}'.format(rrname, rdata))
                            # Type NSEC3
                            elif type_of_record == 50: # As a RR, this is a NSEC3
                                print('\t\tAnswer Type: NSEC. RName: {}. Rdata to process: {}'.format(rrname, rdata))
                            # Type TLSA
                            elif type_of_record == 52: # As a RR, this is a TLSA
                                print('\t\tAnswer Type: TLSA. RName: {}. Rdata to process: {}'.format(rrname, rdata))
                            # Type SPF
                            elif type_of_record == 99: # As a RR, this is a SPF
                                print('\t\tAnswer Type: SPF. RName: {}. Rdata to process: {}'.format(rrname, rdata))
                            else:
                                print('\t\tWe have a new type of TXT type of answer. Check')

                        # In the answer section, SRV records say where you can find this resource
                        elif type(answers_name) == DNSRRSRV:
                            print('\t\tServices Offered in the Answers:')
                            type_of_record = answers_name.type
                            # Type SRV
                            if type_of_record == 33: # This is a SRV

                                split_rrname = rrname.split('.')
                                service = split_rrname[-4]
                                try:
                                    protocol = split_rrname[-3].split('_')[1]
                                except IndexError:
                                    # Some records do not send the _
                                    protocol = split_rrname[-3]
                                try:
                                    location = split_rrname[-5]
                                except IndexError:
                                    # Some records do not have the location here
                                    location = False
                                if len(location.split('@')) > 1:
                                    # The location really has a mac and IP
                                    macaddr = location.split('@')[0]
                                    ipaddr = location.split('@')[1]

                                if '_apple' in service:
                                    if hasattr(answers_name, 'rdata') and type(answers_name.rdata) == bytes:
                                        # Values like a name b'pepe'. There is no extra data
                                        name = rdata
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
                                    try:
                                        name = answers_name.target.decode('utf-8').split('.')[:-2][0]
                                    except IndexError:
                                        # Some records come empty...
                                        name = ''
                                    data = rrname.split('.')[:-4]
                                    if 'wplay' in service:
                                        print(bcolors.WARNING + '\t\t\tThis host named {} (name based on its IP) offers the service Amazon FireTV with data {}'.format(name, data) + bcolors.ENDC)
                                elif '_airdrop' in service:
                                    # Service for airdrop from Apple
                                    airdrop_instance = rrname.split('.')[-5]
                                    target = answers_name.target.decode('utf-8').split('.')[-3]
                                    if type(rdata[0]) == bytes:
                                        data = rdata[0].decode('utf-8')
                                    else:
                                        data = rdata[0]
                                    print(bcolors.WARNING + '\t\t\tThis host offers the service AirDrop, instance name {}, target {} and data {}'.format(airdrop_instance, target, data) + bcolors.ENDC)
                                elif '_raop' in service:
                                    # Service for remote audio
                                    # Not sure about this name????
                                    name = rdata
                                    if len(location.split('@')) < 2:
                                        # Some devices do not send a mac at all nor ip, only a name
                                        # Bug to solve:
                                        # In home1.pcap
                                        # SrcMAC: B8:27:EB:ED:0C:2F (Raspberry Pi Foundation), SrcIP: 10.0.0.43. Name: Pi . #Questions: 0. #Additional Records 0. #Answers: 28
                                        # This host named ['Pi._sftp-ssh._tcp.local.'] offers the service of Remote Audio Output Protocol on the MAC address B827EBED0C2F and device with name Pi


                                        print(bcolors.WARNING + '\t\t\tThis host named {} offers the service of Remote Audio Output Protocol on the device named {}'.format(name, macaddr, location) + bcolors.ENDC)

                                    else:
                                        # Some devices do not send both mac and the IP address but a mac and a 'name'
                                        if len(ipaddr.split('.')) < 3:
                                            print(bcolors.WARNING + '\t\t\tThis host named {} offers the service of Remote Audio Output Protocol on the MAC address {} and device with name {}'.format(name, macaddr, ipaddr) + bcolors.ENDC)
                                        else:
                                            print(bcolors.WARNING + '\t\t\tThis host named {} offers the service of Remote Audio Output Protocol on the MAC address {} with IP adddress {}'.format(name, macaddr, ipaddr) + bcolors.ENDC)

                            else:
                                print('\t\t\tUnknown SRV Type. Target: {}. RRname: {}'.format(answers_name.target.decode('utf-8'), rrname))
                                print('\t\t\t\tData to process (DNSRRSRV): {}'.format(answers_name.target.decode('utf-8')))
                                print('\t\t\t\tData to process (DNSRRSRV): {}'.format(rrname))

                        # In the answer section, TXT records give additional info about a resource reoord
                        elif type(answers_name) == DNSRRTXT:
                            print('\t\t\tType {}. '.format(answers.name))

                        # Loop
                        answers_name = answers_name.payload



                #####################
                # Process the Additional records
                # 
                print(bcolors.HEADER + f' > Additional Records: \033[36m{num_additional_records}\033[95m' + bcolors.ENDC)
                # Amount of additional records
                if num_additional_records:
                    additional_name = DNSlayer.fields['ar']

                    # Some rdata comes as a list and some as a string. Lets convert the string into a list
                    if hasattr(additional_name, 'rdata'):
                        if type(additional_name.rdata) == list:
                            try:
                                rdata = additional_name.rdata
                            except IndexError:
                                # Some DNSRROPT records send an empty list.
                                rdata = False
                        elif type(additional_name.rdata) == bytes:
                            # See the conversion to list with []
                            rdata = [additional_name.rdata.decode('utf-8')]
                        else:
                            # See the conversion to list with []
                            rdata = [additional_name.rdata]
                    else:
                        rdata = False

                    # See if the rrname come as byte strings or not
                    try:
                        rrname = additional_name.rrname.decode('utf-8')
                    except AttributeError:
                        # Some versions of scapy do not give a Byte String
                        rrname = additional_name.rrname



                    for pos in range(0,num_additional_records):
                        if args.debug:
                            print('\t\t[Debug] Additional Record. Type: {}. Rdata: {}. RRname: {}'.format(additional_name.name, rdata, rrname))

                        if type(additional_name) == DNSRROPT:
                            print('\t\tType: {}. Rdata name: {}'.format(additional_name.name, rdata))

                        elif type(additional_name) == DNSRRNSEC:
                            print('\t\tType: {}. RRName: {}'.format(additional_name.name, rrname))

                        elif type(additional_name) == DNSRR:
                            print('\t\tType: {}. Rdata Bytes: {}'.format(additional_name.name, rdata))
                            # We may have rdata as a list with several parts.
                            for list_data in rdata:
                                # If each part of rdata is bytes, convert it
                                if type(list_data) == bytes:
                                    list_data = list_data.decode('utf-8')
                                # If we have rdata and is formated with =
                                if len(list_data.split('=')) > 1:
                                    # Lets parts this shit of string b'rpBA=2D:F6:28:9B:87:99rpAD=82ae95302041rpHI=85e0df6055a0rpHN=2d48a2585755rpVr=164.16rpHA=0736452b945f'
                                    inner_rdata = list_data.split('=')
                                    values = {}
                                    temp_name = inner_rdata[0]
                                    for data in inner_rdata[1:]:
                                        values[temp_name] =  data[:-4]
                                        temp_name = data[-4:]
                                    # To the last, add the last 4 bytes
                                    values[list(values.keys())[-1]] += temp_name
                                    # Print now
                                    for key in values:
                                        print('\t\t\tName: {}. Value: {}'.format(key, values[key]))

                        elif type(additional_name) == DNSRRSRV:
                            print('\t\tType: {}. Target: {}. RRname: {}'.format(additional_name.name, additional_name.target.decode('utf-8'), rrname))
                            print('\t\t\tData to process: {}'.format(additional_name.target.decode('utf-8')))
                            print('\t\t\tData to process: {}'.format(rrname))
                        else:
                            # Probably NoneType
                            print('Attention! Other type: {}'.format(type(additional_name)))
                        additional_name = additional_name.payload




# Main
####################
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-v',
                        '--verbose',
                        help='Verbosity level. This shows more info about the results.',
                        action='store',
                        required=False,
                        type=int)
    parser.add_argument('-d',
                        '--debug',
                        help='Debugging level. This shows inner information about the flows.',
                        action='store',
                        required=False,
                        type=int)
    parser.add_argument('-r',
                        '--readfile',
                        help='Name of the pcap file to read.',
                        action='store',
                        required=False,
                        type=str)
    parser.add_argument('-i',
                        '--interface',
                        help='Name of the interface to use.',
                        action='store',
                        required=False,
                        type=str)
    parser.add_argument('-f',
                        '--filter',
                        help='Tcpdump style filter to use.',
                        action='store',
                        required=False,
                        type=str)

    args = parser.parse_args()

    # Reload the file of Mac vendors
    macvendor.refresh()

    if args.interface:
        sniff(iface=args.interface, prn=do, store=0, filter=args.filter)
    elif args.readfile:
        sniff(offline=args.readfile,prn=do,store=0, filter=args.filter)
