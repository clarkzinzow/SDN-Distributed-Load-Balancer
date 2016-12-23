# SDN-Distributed-Load-Balancer

A Software Defined Networking application implementing the same functionality as a set of hardware
load balancers.  When clients initiate TCP connections with a specific virtual IP, SDN switches send
the TCP SYN packet to the SDN controller; the SDN application will select a host from a pre-defined
set and install rules in an SDN switch to rewrite the IP and MAC addresses of packets associated
with the connection.  The SDN switch matches the modified packets against the flow rules installed
be the layer-3 routing application detailed
[here](https://github.com/ClarkZinzow/SDN-Layer-3-Routing) and applies the appropriate actions.
