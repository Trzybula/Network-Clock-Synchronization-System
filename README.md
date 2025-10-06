## Network Clock Synchronization System

This project implements a peer-to-peer network clock synchronization system. 
The system consists of equal nodes that communicate with each other to synchronize their clocks while accounting for network packet travel times. 
Each node maintains its own natural clock (measured in milliseconds since startup) and synchronization level, ranging from 0 (leader) to 255 (unsynchronized).

The system implements three main functionalities: network joining through contact with another node, 
leader election for clock synchronization, and clock synchronization accounting for transmission delays. 
Nodes communicate using UDP over IPv4, exchanging various types of messages including HELLO, SYNC_START, and time requests. 
The synchronization process involves calculating time offsets between nodes to maintain accurate time across the network.
Each node can join the network either by listening for new participants or by sending a HELLO message to an existing node. 
The synchronization process uses a three-message exchange protocol to account for network delays, and nodes periodically send synchronization messages to maintain accurate time across the network. 
The system also includes mechanisms for leader election and providing current time information to other nodes.

The implementation focuses on error handling, proper message validation, and maintaining efficient non-blocking communication between nodes without using multiple threads.
