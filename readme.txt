dave
////////////////////////////////////////////////////////////////
Minimal distributed binary store on UDP gossip & proof-of-work.
////////////////////////////////////////////////////////////////


1.  Operation Codes

1.1 GETADDR
1.2 ADDR
1.3 SETDAT
1.4 GETDAT
1.5 DAT


2.  Message Wire Format
Each message is serialized into binary using protobuf. See dave.proto for the protobuf spec.

2.1 How to Transpile Protobuf Spec for Go
#!/bin/bash
protoc --go_out=. dave.proto


3.  Peer Discovery & Liveness
The protocol ensures a cohesive network by combining ping and peer discovery into a single pair of messages (GETADDR & ADDR).
A node responds to a GETADDR with an ADDR, a message with up to NADDR random address:port strings, where each address:port is currently responsive (ping and drop counters are zero).
Each time a GETADDR message is sent, the ping counter (peer.nping) is incremented.
If an ADDR message is received from the address, both ping and drop counters are set to zero.
If the ping counter reaches TOLERANCE, the drop counter is incremented.
If the drop counter reaches DROP*TOLERANCE, the peer is deleted from the peer table.
This 2-stage mechanism ensures that dropped peers are not immediately re-added, because unresponsive addresses are not advertised.


4.  DAT Message Propagation
The network propagates SETDAT and GETDAT messages.
Each node appends the address:port of the message sender to the message address list.
For the SETDAT operation, the message is forwarded to up to FANOUT_SETDAT (2) random addresses, excluding those in the message address list.
For the GETDAT operation, if the receiver DOES NOT have the data, and the message contains less than DISTANCE addresses, the message is forwarded to up to FANOUT_GETDAT (1) random addresses, excluding those in the message address list.
For the GETDAT operation, if the receiver DOES have the data, the receiver sends a DAT message with the data to all addresses in the message address list.




