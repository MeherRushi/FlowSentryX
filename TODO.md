# Leveraging XDP for DOS and DDOS Mitigation

This I like a rough structure of like how I want the reame  to turn out to be
I also want to maintain a wiki guidance page for this. But I am not really sure what to write there

So we will also put a label saying that this repo is in the development phase
We will add a check list of things that is supposed to be attached

Okay, so Initially we will talk about what this project is - 
    - It is supposed to be an Layer 3 and 4 open source DOS and DDOS mitigation framework (I am guessing till Layer 4 only cause
    we will be dealing with TCP, UDP and ICMP packets at max and we need to figure out ways to stop such attacks). So we plan
    to write a few modules which are xdp programs that can be dynamically loaded on to the kernel
    and they will do the job of preventing the cybersec attacks.

There will be a section for How to install/run the program - This can be left blank for now
but I am guessing that I will have to write rules regarding having all the dependencies pre-installed 
and then git cloning and then I will also need to tell the commands to be executed

or I can write a shell script for the same. I am not quite sure if I need to look into docker and stuff for this

So initially for Now we will focus of developing the framework for single source DOS mitigation.
THere will be a seciton regarding what is DOS attack and what are the basic types of DOS and the list of 
attacks that can be prevented by this frameowrk - THis will probably include Ping of Death, etc.

We will also mention about the system architecture and the algorithm that we will be planing to use to 
mitigate this attack

Algorithm - We will mostly look into rate limiting algorithms - Mostly a simple one 
Archeticuture - Currently here is the idea for the architecuture

    Kernel Space programs : 
        We will have a few kernel space programs running , they will mainly perform the following tasks
        - They will be a program to parse various packets and keep count of packets per Layer 4 protocol.
        I probably have to keep like a map with IP address as the key and like each IP can have different
        protocol and a count for each protocol packet.


        - Okay so for layer 4 it will be very difficult cause let's say one IP is sending TCP, UDP and ICMP and
        like we might need to identify which protocol one to drop or do we just drop the packets from the IP???

        - I am slightly confused - I am assuming we have will proceed with taking up a layer 3 DOS mitigation system
        - So in layer 3 - we need like to maintain a map with the IP adress and the rate of packet arrival

        ------------------------------------
        |Key(IP)    | Value(rate or count) |
        ------------------------------------
        |  10.0.0.3    |       56          |
        |  192.2.3.8   |       98          |
        ------------------------------------

        If count exceeds a threshold we will add the IP into another map called the blacklist map. All the packets from that map are going to be dropped. We will update that map every 10 minutes i.e after a certain time we can remove the IP from the blacklist

        I believe I will also maintain a timer which will clock and reset every 60 seconds. And if the 
        count of any of these execds a particular limit then, I will drop the packet , else after every 1 minute
        I will update the map back to 0. 

        See there are 3 ideas : 

        1. Completly in the Kernel - Write kernel programs to keep count and update the eBPF maps as the packets keep coming
        And write like a code to refresh the map every few minutes within the kernel itself. I will probably make the Threshold, 
        the timer and limits customizatble as taking them as user arguments if required. If I can write a refresh map every few minute in the kernel code then that will be brilliant. I would also need to maintain a different a map with only IP's which are blacklisted

        I am not sure if we need a user space program. Except for like maybe like a stats program where I keep printing it on the terminal. We can look at alternatives for that as well. One that comes to my mind is just usign bpf_printk() to get logs and
        just cat the output from trace_pipe or use bpftool or like just write a small script to redirect the ouput there


        2. Writing both user space and Kernel space programs : So, here I will probably write the map updatation on packet arrival 
        in the kernel space itself and the packet drop code if it exceeds the threshold also in the kernel itself. however, I might want to write the Updating my map every few minutes part in the user space. I am not quite sure if this will be helpful or not. In the talk with Senior , he has mentioned about doing this. But I am not quite sure what to proceed with as I don't see any peculiar advantage of doing this. Al

        3. In Case we implement a computationally heavy rate limiting algorithm - Which we are planning to implement like a relatively standard yet simple one - we would need to write in the user space and then keep updating the map from there, only the count and some basic info will be extracted in the kernel space. 

        Okay so most probably the rate limiting algorithm that we will be using is the static window or sliding window algorithm

        So by tonight we can draw a system architecture diagram. 

Finally, I also want to add a lot of references for my learning. I will probably link it to the 
Learning eBPF and XDP repo. I am not sure whether I should add references for this work or not.


### Title : FlowSentryX

#### Description : It is a XDP-based L3 DOS and DDOS Mitigation Framework

For now we are doing layer 3 based DOS mitigation

### System Architecture

- **Kernel Space Program** : 
   - _Packet Parsing_ - Write programs for parsing the packets and doing the checks.
   - _Map Creation and updation_ 
      - The plan is to create 2 Maps - Rate of Packet Arrival(per sec) per IP, and a normal Black listed IP table.
      - The packet arrival per IP per sec table is going to be updated with the count of the packet and then we need to refresh the table every one second for now - The algorithm that is going to be used is the simple Fixed window algorithm. 
      - We pick the blacklisted to the BlackList IP table and drop the packets for that particular IP.  
   - _I think that is it_

- **User Space Program** :
   - _Clear the BlackList IP table_ - 
   - _Read the data_ from the table and print it in a nice format maybe

   Upcoming plans for user space :
   
   _Configuration and Management_: In the user space, you can create a management component for configuring the threshold values and maintaining the blocklist. You can use user-level tools or scripts to configure the XDP program parameters.

   _Reporting and Logging_: Implement logging and reporting mechanisms in user space to monitor the status of your DDoS prevention system. You can store logs, generate alerts, and maintain historical data.

   _Dynamic Rules Management_: You can create a user space component that communicates with the kernel space to add or remove IP addresses from the blocklist dynamically.


 
   
 
 
 
 

















# XDP-based DOS and DDOS Mitigation Framework

## Table of Contents
1. [Overview](#overview)
   - [Project Description](#project-description)
   - [Why DOS/DDOS Mitigation?](#why-dosddos-mitigation)
2. [Installation and Usage](#installation-and-usage)
   - [Prerequisites](#prerequisites)
   - [Installation](#installation)
   - [Usage](#usage)
3. [System Architecture](#system-architecture)
   - [Components](#components)
4. [Rate Limiting Algorithm](#rate-limiting-algorithm)
   - [Static Window Rate Limiting](#static-window-rate-limiting)
5. [Implementation Approaches](#implementation-approaches)
   - [Option 1: Kernel-Only Implementation](#option-1-kernel-only-implementation)
   - [Option 2: User-Kernel Combination](#option-2-user-kernel-combination)
   - [Option 3: Computationally Heavy Algorithm](#option-3-computationally-heavy-algorithm)
6. [References](#references)
7. [Project Status](#project-status)
8. [Contribution](#contribution)
9. [License](#license)
10. [Contact](#contact)
11. [Acknowledgments](#acknowledgments)

## Overview

### Project Description
The XDP-based DOS and DDOS Mitigation Framework is an open-source solution designed to protect your network infrastructure from Denial of Service (DOS) and Distributed Denial of Service (DDOS) attacks at Layer 3 and 4. These attacks are a significant threat to network stability, and our framework aims to provide an efficient and customizable defense mechanism.

### Why DOS/DDOS Mitigation?
DOS and DDOS attacks can disrupt your network, causing downtime and financial losses. Our framework helps you safeguard your infrastructure by efficiently filtering malicious traffic, ensuring your network remains operational.

## Installation and Usage

### Prerequisites
Before installing the framework, make sure you have the following prerequisites installed:

- List of dependencies (e.g., Linux kernel version, eBPF tools, etc.)

### Installation
To install the framework, follow these steps:

1. Step-by-step installation instructions.
2. Include any scripts or commands necessary for setup.

### Usage
Provide guidance on how to use the framework:

1. Command-line options and arguments.
2. Configuration files if applicable.
3. Example usage scenarios.

## System Architecture

### Components
Explain the high-level architecture of the framework. Detail the key components involved, including:

- **Kernel Space Programs**: Programs running in the kernel to monitor incoming traffic, track packet rates, and enforce filtering rules.
   - Packet Parser: Parses incoming packets and categorizes them based on Layer 4 protocols.
   - Rate Tracker: Maintains a map of IP addresses and their packet rates.
   - Blacklist Manager: Adds IPs to a blacklist when their packet rates exceed a threshold.
- **User Space**: Describe the role of user space components (if any), such as statistics display and system interaction.

## Rate Limiting Algorithm

### Static Window Rate Limiting
Explain the rate limiting algorithm you plan to implement. Describe how it works and how it contributes to DOS/DDOS mitigation.

## Implementation Approaches

### Option 1: Kernel-Only Implementation
Detail the first implementation approach, including its pros and cons.

### Option 2: User-Kernel Combination
Explain the second implementation approach and discuss its advantages and disadvantages.

### Option 3: Computationally Heavy Algorithm
Outline the third implementation approach, specifying when and why it might be a preferred choice.

## References
List any learning resources, articles, or repositories that have influenced or inspired your project.

## Project Status
Indicate that the project is currently in the development phase. Share any ongoing development efforts and planned milestones.

## Contribution
Provide guidelines for potential contributors, including instructions for forking the repository, creating branches, and submitting pull requests.

## License
Specify the open-source license under which the project is distributed (e.g., MIT License).

## Contact
Include contact information for questions, suggestions, or collaboration.

## Acknowledgments
Give thanks to individuals or organizations that have supported or contributed to the project.


# Maps

So for now we are going to settle for a LRU_HASH type map. We will think about other stuff like LPM_trie later

okay okay okay, so we be doing packet dropping based on threshold value of per IP. If some IP bombards the server with an excess number of packets, drop it for a while. 

That's the plan


so we will have the following maps:
1) IPv4 stats map (key - IPV4 address and value is a struct with pps and bps and track_time - It is the time when the packet of a particular IP first comes)

2) IPv6 stats map (key - IPV6 address and value is a struct with pps and bps and track_time - It is the time when the packet of a particular IP comes)