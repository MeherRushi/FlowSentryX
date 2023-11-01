# XDP-based (D)DOS Mitigation Framework

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
7. [Project Status](#project-status) <!-- 8. [Contribution](#contribution) -->
8. [License](#license)
9. [Contact](#contact)
10. [Acknowledgments](#acknowledgments)



## Overview
### Project Description
The XDP-based DOS and DDOS Mitigation Framework is an open-source solution designed to protect your network infrastructure from Denial of Service (DOS) and Distributed Denial of Service (DDOS) attacks at Layer 3 and 4. These attacks are a significant threat to network stability, and our framework aims to provide an efficient and customizable defense mechanism.


### Why DOS/DDOS Mitigation?
DOS and DDOS attacks can disrupt your network, causing downtime and financial losses. Our framework helps you safeguard your infrastructure by efficiently filtering malicious traffic, ensuring your network remains operational.

## Installation and Usage
**Note**: This section is under development.

This section will provide clear instructions on how to install and run the framework. We'll include details on dependencies, installation commands, and sample usage commands. A setup script will be provided to simplify the installation process.

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
The XDP-based DOS and DDOS Mitigation Framework operates at the network level to detect and mitigate attacks. The architecture involves the following components:

- **Kernel Space Programs**: These programs, written in XDP, are responsible for monitoring incoming traffic, tracking packet rates, and enforcing filtering rules. Key components include:
  - Packet Parser: Parses incoming packets and categorizes them based on Layer 4 protocols.
  - Rate Tracker: Maintains a map of IP addresses and their packet rates.
  - Blacklist Manager: Adds IPs to a blacklist when their packet rates exceed a threshold.

- **User Space**: While the core functionality is in the kernel space, user space may include a statistics program to display information about detected attacks, logs, and system status. This separation ensures efficient resource management.

## Rate Limiting Algorithm
### Static Window Rate Limiting
We plan to implement a static window rate limiting algorithm. This algorithm tracks incoming packets and allows legitimate traffic while limiting excessive traffic from potential attackers.

## Three Implementation Ideas
In the development phase, we are considering three implementation approaches:

### Option 1: Kernel-Only Implementation
1. **Kernel-Only Implementation**: This approach involves writing all logic in the kernel space, including rate limiting, tracking, and blacklisting. The threshold, timer, and limits are customizable through user arguments.

### Option 2: User-Kernel Combination
2. **User-Kernel Combination**: In this approach, the kernel handles packet tracking, rate limiting, and blacklisting. The user space is responsible for periodically refreshing the rate tracking map and handling statistics and user interaction.

### Option 3: Computationally Heavy Algorithm
3. **Computationally Heavy Algorithm**: For more complex rate limiting algorithms, we may implement the logic in user space. Kernel space will handle basic packet tracking, and user space will perform the heavy computations, updating the tracking map as needed.

## References
- [Learning eBPF and XDP Repository](https://example.com/learning-ebpf-xdp): This repository provided valuable insights into the technologies used in this project.

## Project Status
This project is currently in the development phase. We are actively working on building the framework and welcome contributions from the open-source community.

<!-- ## Contribution
If you'd like to contribute to the project, please follow these steps:
- Fork the repository.
- Create a new branch for your feature or bug fix.
- Make your changes and submit a pull request. -->

## License
This project is licensed under the [MIT License](LICENSE).

## Contact
If you have any questions, suggestions, or would like to collaborate, please feel free to contact us at [MeherRushi-Email](sudharushi0@gmail.com).

## Acknowledgments
We'd like to thank the open-source community for their support and contributions to this project.

