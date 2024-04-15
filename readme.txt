dave
////////////////////////////////////////////////////////////////
Minimal distributed binary store on UDP gossip & proof-of-work.
////////////////////////////////////////////////////////////////


1.  Operation Codes

1.1 GETPEER
1.2 PEER
1.3 SETDAT
1.4 GETDAT
1.5 DAT


2.  Message Wire Format
A message is serialized into binary using protobuf. See dave.proto for the protobuf spec.

2.1 Transpiling Protobuf Spec for Go
#!/bin/bash
protoc --go_out=. dave.proto


3.  Peer Discovery & Liveness
The protocol ensures a cohesive network by combining ping and peer discovery into a single pair of messages (GETPEER & PEER).
A node replies to a GETPEER message with a PEER message with up to NPEER random address:port strings, where each address:port is a responsive peer (ping and drop counters are zero).
When a GETPEER message is sent, the ping counter (peer.nping) is incremented.
If a PEER message is received from the address, both ping and drop counters are set to zero.
If the ping counter reaches TOLERANCE, the drop counter is incremented.
If the drop counter reaches DROP*TOLERANCE, the peer is deleted from the peer table.
This 2-stage mechanism ensures that dropped peers are not immediately re-added, because unresponsive peers are not advertised.


4.  DAT
DAT is a construct representing a small value, some metadata (time & tag), and the proof of work. The proof-of-work allows the network to prioritise storage of keys backed by more work.
The proof of work also makes it easier to protect the network from protocol deviation.

4.1 Properties:
Val: Data, <=VAL_SIZE bytes
Tag: Arbitrary data, <=32 bytes
Time: Time created, 8 bytes
Nonce: Random, 32 bytes
Prev: Work of previous DAT (if any), 0|32 bytes
Work: SHA256(SHA256(Prev, Val, Tag, Time), Nonce), 0|32 bytes


5.  Message Propagation
The network propagates SETDAT and GETDAT messages.
Each node appends the address:port of the message sender to the message address list.
For the SETDAT operation, the message is forwarded to up to FANOUT_SETDAT (2) random addresses, excluding those in the message address list.
For the GETDAT operation, if the receiver DOES NOT have the data, and the message contains less than DISTANCE addresses, the message is forwarded to up to FANOUT_GETDAT (2) random peers, excluding those in the message address list.
For the GETDAT operation, if the receiver DOES have the data, the receiver sends a DAT message with the data to all addresses in the message address list.

