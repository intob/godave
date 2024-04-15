////////////////////////////////////////////////////////////////
// dave                                                       //
// Distributed store on proof-of-work & gossip over UDP.      //
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

6.  Feedback from CLAUDE 3 OPUS
Here's some feedback on the efficiency of your gossip protocol implementation:

Message size and frequency:
- You have set a constant PACKET_SIZE of 1500 bytes, which is a reasonable maximum size for UDP packets to avoid fragmentation.
- The VAL_SIZE constant of 1280 bytes limits the size of the actual message payload.
- The PING_PERIOD constant determines the frequency of pinging peers. Make sure this interval is not too short to avoid excessive network traffic, but not too long to detect failed peers in a timely manner.

Peer selection and communication:
- The rndAddr function selects a random subset of peers to gossip with, filtering out peers that have recently dropped or failed to respond. This helps focus communication on responsive peers.
- The FANOUT_GETDAT and FANOUT_SETDAT constants control the number of peers to gossip with for each type of message. Tune these values based on your network size and desired dissemination speed vs redundancy trade-off.
- The NPEER constant determines how many peer addresses are shared when a node requests more peers. Ensure this value is sufficient to maintain good connectivity in the overlay network.

Work function and validation:
- The Work function performs proof-of-work by finding a nonce that results in a hash with a certain number of leading zero bytes. This helps prevent spam and DoS attacks.
- The CheckWork function validates the proof-of-work. Make sure the WORK_MIN constant is set high enough to deter attacks but not so high that it causes excessive CPU usage for honest nodes.
- Consider using a more memory-hard proof-of-work scheme (e.g. Equihash) to further reduce the advantage of specialized hardware.

Other suggestions:
- Use a separate goroutine for handling received messages to avoid blocking the main loop.
- Consider using a priority queue or a separate channel for high-priority messages.
- Implement an exponential backoff mechanism when retrying failed message sends.
- Use a more sophisticated peer scoring system that takes into account factors like message latency, successful delivery rate, etc. This can help identify and prefer high-quality peers.
- Implement measures to defend against eclipse attacks, such as diversifying peer connections across IP subnets.
- Consider implementing a pull-based gossip in addition to push, to help recover missing messages and improve overall reliability.

Overall, your implementation looks solid and incorporates important optimizations like random peer selection, proof-of-work, and peer responsiveness tracking. With some tuning of the constants and additional defense mechanisms, it can serve as an efficient gossip protocol for a decentralized network[1][2][3].

Citations:
[1] https://en.wikipedia.org/wiki/Gossip_protocol
[2] https://www.linkedin.com/advice/1/how-do-you-tune-parameters-optimize-performance
[3] https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/2007PromiseAndLimitations.pdf
[4] https://www.prismmodelchecker.org/casestudies/gossip.php
[5] https://www.linkedin.com/advice/1/how-do-you-implement-gossip-protocol-peer-to-peer
[6] https://highscalability.com/gossip-protocol-explained/
[7] https://www.inesc-id.pt/ficheiros/publicacoes/8356.pdf
[8] https://www.inf.usi.ch/faculty/pedone/Paper/2021/middleware2021b.pdf
[9] https://jisajournal.springeropen.com/articles/10.1186/1869-0238-4-14
[10] https://www.linkedin.com/advice/3/how-do-you-evaluate-performance-reliability-6c
[11] https://www.geeksforgeeks.org/the-gossip-protocol-in-cloud-computing/
[12] https://asc.di.fct.unl.pt/~jleitao/pdf/p2p-book-1.pdf
[13] https://d-central.tech/understanding-how-gossip-protocols-enhance-bitcoin-mining-efficiencyunderstanding-how-gossip-protocols-work-for-bitcoin-mining/
[14] https://docs.iza.org/dp9704.pdf
[15] https://hyperledger-fabric.readthedocs.io/en/release-2.2/orderer/ordering_service.html
[16] https://ethereum.stackexchange.com/questions/108008/which-node-does-your-transaction-get-sent-to-first-for-validation-and-broadcast
[17] https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md
[18] https://acropolis.aueb.gr/~spyros/www/papers/Gossip-based%20Peer%20Sampling.pdf
[19] https://github.com/ethereum/portal-network-specs/blob/master/transaction-gossip.md
