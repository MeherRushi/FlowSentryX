# FlowSentryX

![Progress](https://img.shields.io/badge/Progress-20%25-orange)

### An XDP-based DOS and DDOS Mitigation Framework

**FlowSentryX** is an open-source XDP-based fast packet processing DOS and DDOS Mitigation Framework solution designed to protect your network infrastructure from Denial of Service (DOS) and Distributed Denial of Service (DDOS) attacks at Layer 3 & 4. 

> Current work is being done for Layer 3 based DOS and DDOS mitigation.

The framework is a collection of XDP programs which track your network traffic and parse packets till the IP layer and make the descision to drop packets from malicious IP addresses using different algorithms and models for DOS and DDOS mitigation.

We also plan to extend the ability BlackList IP addresses and write rules manually from the user space to block certain packets. The rules will be written in the config file which will be read by the xdp program and action will be taken accordingly, hence extending the framework to act as a _Basic Firewall_.

> Refine this text , use better words like packet inspection and filtering, Logging etc.



## Table of Contents
1. [Overview](#overview)
   - [Project Description](#project-description)
   - [Why DOS/DDOS Mitigation?](#why-dosddos-mitigation)
   - [Basic Firewall](#basic-firewall)
2. [Installation and Usage](#installation-and-usage)
   - [Prerequisites](#prerequisites)
   - [Installation](#installation)
   - [Usage](#usage)
3. [System Architecture](#system-architecture)
   - [Diagramtic Representation](#)
   - [Components](#components)
      - [User Space](#user-space)
      - [Kernel Space](#kernel-space)
      - [eBPF Maps and Datastructres](#)
   
4. [Rate Limiting Algorithms](#rate-limiting-algorithm)
   - [Fixed Window Rate Limiting](#1-fixed-window-rate-limiting)
   - [Sliding Window Rate Limiting](#2-sliding-window-rate-limiting)
   - [Token bucket Rate Limiting](#3-token-bucket-rate-limiting)  

5. [ML Model for DDOS mitigation](#)
   - [](#)
   - [](#)

6. [References](#references)
7. [Project Status](#project-status) 
8. [Contribution](#contribution)
9. [License](#license)
10. [Contact](#contact)
11. [Acknowledgments](#acknowledgments)



## Overview
### Project Description

**FlowSentryX** is an open-source XDP-based fast packet processing DOS and DDOS Mitigation Framework solution designed to protect your network infrastructure from Denial of Service (DOS) and Distributed Denial of Service (DDOS) attacks at Layer 3 & 4. 

This framework is a set of [xdp](https://www.iovisor.org/technology/xdp) programs that attaches to the Linux kernel's XDP hook through [(e)BPF](https://ebpf.io/) for fast packet processing. 

The XDP programs parse all the packets in the ingress network traffic till the IP layer and make the descision to drop packets from malicious IP addresses using some Rate Limiting Algorithms like token bucket algorithm, fixed window algorithm and sliding window algorithm for DOS attack mitigation and using the features extracted from the packets and passing them to a trained ML model in the user space for inference of deciding whether that particular IP was involved in the DDOS attack.

> Explain why XDP is faster and why we plan to use it.

> Describe the project in a little bit more detail and refine this.

### Why DOS/DDOS Mitigation?
DOS and DDOS attacks can disrupt your network, causing downtime and financial losses. Our framework helps you safeguard your infrastructure by efficiently filtering malicious traffic, ensuring your network remains operational.

 > Write about different Attach here the content from cloudfare blog
 - Ping of Death
 - Flood Attacks
 - Buffer overflow Attacks

 > Also Write in detail about DDOS attack

### Basic Firewall

> Fill this section with how we plan to extend our project to a stateless Firewall with Dynamic DOS and DDOS mitigation abilities.

We plan to extend the framework to an XDP based stateless Firewall, by allowing config files where the user can manually configure parameters such as the Threshold values and the time duration for black listing the IP address for the already existing features. We also plan to add Dynamic Rule Management to Manage dynamic rules and configurations, such as adding or removing IP addresses from the blocklist. This component can communicate with the kernel space to apply or remove rules as needed.

Also we plan to add config files which can be used to blacklist user configured IP's and rules to drop certain packets.

> Need a better description for the above


## Installation and Usage
**Note**: This section is under development.


> Add Link to the Dependencies.md page and also like a checklist version of required features


This section will provide clear instructions on how to install and run the framework. We'll include details on dependencies, installation commands, and sample usage commands. A setup script will be provided to simplify the installation process.

### Prerequisites
Before installing the framework, make sure you have the following prerequisites installed:

- List of dependencies (e.g., Linux kernel version, eBPF tools, etc.)
Refer to [Dependencies](Dependencies.md).
   Extracted Information required for Debian or Ubuntu

   Need to install
   - ✅ libxdp
   - ✅ xdp-tools 
   - ✅ libbpf
   - ✅ llvm
   - ✅ clang
   - ✅ libelf-dev
   - ✅ libpcap-dev 
   - ✅ build-essential
   - ✅ sudo apt-get install -y gcc-multilib (On x86_64 PC, the gcc-multilib debian package makes a symbol link at "/usr/include/asm" to "/usr/include/x86_64-linux-gnu".
   I guess that on the ARM32 system (Raspbian) /usr/include/asm might linked to /usr/include/aarch64-linux-gnu or arm-linux-gnueabihf)


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
The XDP-based DOS and DDOS Mitigation Framework operates at the network level to detect and mitigate attacks. The architecture involves the following components:

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
   - _Configuration and Management_: In the user space, you can create a management component for configuring the threshold values and maintaining the blocklist. You can use user-level tools or scripts to configure the XDP program parameters.
   - _Reporting and Logging_: Implement logging and reporting mechanisms in user space to monitor the status of your DDoS prevention system. You can store logs, generate alerts, and maintain historical data.
   - _Dynamic Rules Management_: You can create a user space component that communicates with the kernel space to add or remove IP addresses from the blocklist dynamically.

- **eBPF Maps and Datastructures**
    - We are planning to use BPF_HASH_ARRAY_TYPE map for storing the IP address and the Packet Per second
    - 


> Need a way better description for the above


## Rate Limiting Algorithms

### 1. Fixed Window Rate Limiting
We plan to implement a static window rate limiting algorithm. This algorithm tracks incoming packets and allows legitimate traffic while limiting excessive traffic from potential attackers.

### 2. Sliding Window Rate Limiting
We plan to implement a static window rate limiting algorithm. This algorithm tracks incoming packets and allows legitimate traffic while limiting excessive traffic from potential attackers.

### 3. Token Bucket Rate Limiting
We plan to implement a static window rate limiting algorithm. This algorithm tracks incoming packets and allows legitimate traffic while limiting excessive traffic from potential attackers.


## References
- [Learning eBPF and XDP Repository](https://example.com/learning-ebpf-xdp): This repository provided valuable insights into the technologies used in this project.

References and Literature Survey

1) Beginner/Intermediate/Adv Intro to eBPF by Bredan Greg : https://www.brendangregg.com/blog/2019-01-01/learn-ebpf-tracing.html
2) Basic Firewall building program : https://arthurchiao.art/blog/firewalling-with-bpf-xdp/#11-bpfxdp-in-a-nutshell 
3) IEEE executive project Network Monitoring with eBPF : https://github.com/advaithcurpod/network-monitoring-eBPF 
4) Theory Programming Kernel with eBPF: https://www.kerno.io/blog/programming-the-kernel-with-ebpf 
5) Art of writing eBPF code : https://sysdig.com/blog/the-art-of-writing-ebpf-programs-a-primer/ 
6) Amazing repo which is a collection of a lot of other references : https://github.com/zoidbergwill/awesome-ebpf#tutorials 
7) Resource List : https://qmonnet.github.io/whirl-offload/2016/09/01/dive-into-bpf/ 
8) Bredan Greg Blogs/books : https://www.brendangregg.com/blog/2019-01-01/learn-ebpf-tracing.html 
9) https://www.brendangregg.com/bpf-performance-tools-book.html 
10) https://www.brendangregg.com/systems-performance-2nd-edition-book.html
11) Iovisor bcc fundamentals : https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md  
12) XDP tutorial : https://github.com/xdp-project/xdp-tutorial/tree/master/basic01-xdp-pass 
13) BPF Internals : https://www.usenix.org/conference/lisa21/presentation/gregg-bpf 
14) Linux Torvalds repo bpf samples : https://github.com/torvalds/linux/tree/v4.20/samples/bpf 
15) Cilium Docs : https://docs.cilium.io/en/latest/bpf/ 
16) Kernel.org documentation : https://www.kernel.org/doc/html/latest/bpf/index.html 




Some Important papers: 

18) Fast Packet Processing with eBPF and XDP: Concepts, Code, Challenges, and Applications: (Main reference Paper) https://www.researchgate.net/publication/339084847_Fast_Packet_Processing_with_eBPF_and_XDP_Concepts_Code_Challenges_and_Applications
19) [A flow-based IDS using Machine Learning in eBPF (Reference for the ML part)](https://arxiv.org/pdf/2102.09980.pdf#:~:text=So%20far%20eBPF%20has%20been,machine%20learning%20entirely%20in%20eBPF.)
20) [CICIDS2017 dataset](https://www.kaggle.com/datasets/cicdataset/cicids2017)
21) [XDP in practice: integrating XDP into our DDoS mitigation pipeline:](https://netdevconf.org/2.1/papers/Gilberto_Bertin_XDP_in_practice.pdf)

Some related technologies and tools

22) eBPF Summit : https://ebpf.io/applications/
23) Once again: Amazing repo which is a collection of a lot of other references : https://github.com/zoidbergwill/awesome-ebpf#tutorials 
24) Cilium : https://github.com/cilium/cilium 


Some other resources

25) Basic Intro eBPF for complete beginners : https://www.youtube.com/watch?v=J_EehoXLbIU&ab_channel=Computerphile 
26) NetDev XDP talk : https://www.youtube.com/watch?v=iBkR4gvjxtE&ab_channel=netdevconf 
27) Linux-kernel-observability-ebpf https://sematext.com/blog/linux-kernel-observability-ebpf/ 
28) Ebpf-and-xdp-for-processing-packets-at-bare-metal-speed: https://sematext.com/blog/ebpf-and-xdp-for-processing-packets-at-bare-metal-speed/ 
29) Cilium : https://medium.com/@luishrsoares/getting-started-with-cilium-ebpf-778d00c113aa 

30) Hooking : https://en.wikipedia.org/wiki/Hooking 
31) eBPF.io : https://ebpf.io/what-is-ebpf/#development-toolchains

References from others (Didn't go through them)

32) https://www.youtube.com/watch?v=iBkR4gvjxtE 
33) https://blog.yadutaf.fr/2017/07/28/tracing-a-packet-journey-using-linux-tracepoints-perf-ebpf/ 
34) https://www.collabora.com/news-and-blog/blog/2019/04/05/an-ebpf-overview-part-1-introduction/ 
35) https://stackoverflow.com/questions/67553794/what-is-variable-attribute-sec-means 
36) https://bpietraga.me/experiments-with-writing-c-ebpf-code/ 
37) https://blogs.igalia.com/dpino/2019/01/10/the-express-data-path/
38) www.tigera.io%2Flearn%2Fguides%2Febpf%2Febpf-xdp%2F 
39) https://www.redhat.com/en/blog/using-express-data-path-xdp-red-hat-enterprise-linux-8 
40) https://stackoverflow.com/questions/55436213/how-can-i-get-the-bpf-helpers-h-header-file-for-my-linux-kernel 
41) https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/network-tracing-using-the-bpf-compiler-collection_configuring-and-managing-networking 
42) https://dev.to/satrobit/absolute-beginner-s-guide-to-bcc-xdp-and-ebpf-47oi 
43) https://www.mcorbin.fr/pages/xdp-introduction/ 


References regarding DOS

42) [What is DOS? - Cloudfare](https://www.cloudflare.com/en-gb/learning/ddos/glossary/denial-of-service/)
43) [Ping of Death](https://www.cloudflare.com/en-gb/learning/ddos/glossary/denial-of-service/)
44) [Types of DOS Attacks](https://www.educba.com/types-of-dos-attacks/)
45) To be added


Some cloudfare tools for reference:

46) [xdpcap - tcmdump with xdp packet filter](https://github.com/cloudflare/xdpcap)
47) [Rakelimit - UDP Packet filter - Blog - has other links](https://blog.cloudflare.com/building-rakelimit/)
48) [Rakelimit - Github Repo](https://github.com/cloudflare/rakelimit)
49) To be added

Some more papers and Articles:

50) [Signature based DDOS prevention in xdp](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=9511420)
51) [Signature-Based DDoS Attack Mitigation: Automated Generating Rules for
Extended Berkeley Packet Filter and Express Data Path](https://essay.utwente.nl/80125/1/vanwieren_MA_DACS.pdf)
52) [DoS and DDoS mitigations with eBPF, XDP and DPDK](https://www.slideshare.net/azilian/dos-and-ddos-mitigations-with-ebpf-xdp-and-dpdk)

Some repo's :

53) [eBPF-firewall repo](https://github.com/nikofil/ebpf-firewall/tree/master)

Rate Limiting Blogs:

54) [token bucket, fixed and sliding window ](https://dev.to/satrobit/rate-limiting-using-the-token-bucket-algorithm-3cjh)


> Need to reorder and neatly write it

## Project Status
This project is currently in the development phase. We are actively working on building the framework and welcome contributions from the open-source community.

## Contribution
If you'd like to contribute to the project, please follow these steps:
- Fork the repository.
- Create a new branch for your feature or bug fix.
- Make your changes and submit a pull request.

## License
This project is licensed under the [MIT License](LICENSE).

## Contact
If you have any questions, suggestions, or would like to collaborate, please feel free to contact us at [MeherRushi-Email](sudharushi0@gmail.com).

## Acknowledgments
We'd like to thank the open-source community for their support and contributions to this project.

