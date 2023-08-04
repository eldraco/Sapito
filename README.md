# Sapito 
[![Docker Image CI](https://github.com/eldraco/Sapito/actions/workflows/docker-image.yml/badge.svg)](https://github.com/eldraco/Sapito/actions/workflows/docker-image.yml)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/eldraco/Sapito/master)
![Docker Pulls](https://img.shields.io/docker/pulls/stratosphereips/sapito?color=green)

Authors: Sebastian Garcia (eldraco@gmail.com, @eldracote), Veronica Valeros (vero.valeros@gmail.com, @verovaleros)

## About Sapito

Sapito is a multicast DNS (mDNS) sniffer and interpreter written in Python. Sapito sniffs packets from a pcap or interface and interprets the findings. This means that Sapito is able to understand the mDNS questions and answers, making sense of the messages. It can also identify certain devices, like finding MacOS computers and several type of iPads. The color-coded output helps to highlight important information.



If you find a bug, please report it along with the output of the tool to eldraco@gmail.com. If you have the pcap with the offending packets, it would be extremely useful if you send it along with the bug report. 

![Default Options](https://github.com/eldraco/Sapito/blob/master/media/sapito-gif.gif?raw=true)

## Docker Image

Sapito has a public Docker image with the latest version on DockerHub, which runs well on Linux systems (MacOS not supported yet).

To run Sapito:

```bash
docker run --rm --network host --name sapito -it stratosphereips/sapito:latest  python3 sapito.py -i <interface>
```


# Background Information About Some Services

## About Bonjour Services


### ._airplay._tcp.local

> This is a Bonjour advertisement for the network service that enables AirPlay of video content. I.e. this allows iOS devices to discover the Apple TV as a "remote display" that it can display video on.

### ._mediaremotetv._tcp.local

> This is one of the network services that makes the Apple TV Remote work - i.e. the app or Control Center built-in feature for remote controlling Apple TV devices from iPhones and iPads. This service is advertised on the network via Bonjour to ensure that iOS devices can discover the AppleTV.

### ._companion-link._tcp.local

> This service is seemingly not documented by Apple, but seems involved in making the AirPlay 2 system work.

### ._raop._tcp.local

> This network service is called Remote Audio Output Protocol. It is essentially saying that the AppleTV works as an AirPlay audio receiver. This Bonjour advertisement allows iOS devices to discover the Apple TV as a "speaker" that you can send audio to.

### ._sleep-proxy._udp.local

> This is a Bonjour Sleep Proxy. The idea is that the AppleTV can respond to various network queries for other devices that are currently in low-power mode to lower energy usage. For example it could be a Mac offering a shared iTunes library or a shared printer. The AppleTV can then answer network requests for these servers while the Mac is in sleep mode - for example allowing the user to list the shared printers available on the network. However, when the user chooses to print something, the AppleTV will wake up the Mac and transfer the request to it.

### _homekit._tcp.local

> This is a network service regarding HomeKit, Apple's system for communicating with and controlling devices in the home. Think controllable light bulbs, shades, door bells, whatever. The AppleTV works as a proxy in such a setting such that the user can control devices remotely (i.e. while not at home) even though the devices might be Bluetooth only and out of range. Note that ordinary HomeKit devices on the network advertise as _hap._tcp instead.

### ._touch-able._tcp.local

> This is another of the network services that makes the Apple TV Remote work. This service concerns device authentication. I.e. if you want to for example play a Youtube video on the Apple TV, the Apple TV can require that the device is authenticated before being allowed to do so. In practice authentications work by the Apple TV displaying a PIN-code on the TV that the user enters on the iOS device. This PIN-code is transferred using the service advertised as "touch-able" to authenticate the device.


## Why some packets have a question and answers in the same packet?

Because of Known-Answer suppression[^1]:

    Known-Answer Suppression

       When a Multicast DNS querier sends a query to which it already knows
       some answers, it populates the Answer Section of the DNS query
       message with those answers.

       Generally, this applies only to Shared records, not Unique records,
       since if a Multicast DNS querier already has at least one Unique
       record in its cache then it should not be expecting further different
       answers to this question, since the Unique record(s) it already has
       comprise the complete answer, so it has no reason to be sending the
       query at all.  In contrast, having some Shared records in its cache
       does not necessarily imply that a Multicast DNS querier will not 
       receive further answers to this query, and it is in this case that it
       is beneficial to use the Known-Answer list to suppress repeated
       sending of redundant answers that the querier already knows.

[^1]: ‘RFC 6762: Multicast DNS’. https://www.rfc-editor.org/rfc/rfc6762#section-7.1 (accessed Oct. 01, 2022).
