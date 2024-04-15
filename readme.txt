dave

Distributed binary store based on proof-of-work.

1. Wire format
Each message is serialized into binary.
The message format is defined in the protobuf spec, `dave.proto`.
1.1 Transpile Protobuf Spec
#!/bin/bash
protoc --go_out=. dave.proto

2. GET_ADDR, ADDR
Each node executes a minimal gossip protocol that keeps the network together.
Every PING_PERIOD (1s), each node will range through it's peer list,
and select the one it heard from the least recently, referred to as "quiet".
The node sends a GET_ADDR message to that peer, and increments the NPING counter
of the peer in the peer table. When a node receives the GET_ADDR message, it
responds with ADDR, a message with NADDR random addresses from the peer list,
excluding the remote address. When a node receives any message, the ping counter
is reset. If the ping counter reaches DROP_THRESHOLD, the peer is removed from
the peer list.

3. Keys

4. RW