# Dave - Distributed Key-Value Store

Dave is a decentralized key-value store built on UDP, designed for efficient data distribution and storage prioritization using proof-of-work.

## Core Features

- Distributed key-value storage over UDP
- Proof-of-work based data prioritization
- Trust-based peer selection
- Configurable sharding for concurrent processing
- Automatic peer discovery and management
- Data backup and recovery

## Architecture

### Network Protocol

- **Maximum Packet Size**: 1424 bytes to avoid fragmentation[1]
- **Transport**: UDP with protobuf serialization
- **Peer Management**: Dynamic peer discovery with trust scoring
- **Data Distribution**: Random push model for anonymity

### Storage System

- **Sharding**: Concurrent processing with configurable shard capacity[2]
- **Data Prioritization**: Mass-based storage prioritization
- **Mass Calculation**: `Mass = Difficulty * (1 / Age_Milliseconds)`
- **Backup**: Automatic data persistence with configurable backup files

## Configuration

```go
type Cfg struct {
    PrivateKey      ed25519.PrivateKey
    UdpListenAddr   *net.UDPAddr
    Edges           []netip.AddrPort
    ShardCap        int
    BackupFilename  string
    Logger          *logger.Logger
}
```

## Protocol Operations

- **PING/PONG**: Peer liveness and discovery
- **PUT**: Store data with proof-of-work
- **GET**: Retrieve stored data

## Trust System

- Trust earned based on valid data contributions
- Maximum trust cap for fair resource distribution
- Trust influences peer selection probability
- No trust gossip to prevent attack vectors

## Data Distribution

- Random push model for sender anonymity
- Recent data prioritization using ring buffer
- Configurable fanout for data propagation
- Edge peers for network bootstrapping

## Pruning and Maintenance

- Periodic pruning of inactive peers
- Mass-based data retention
- Concurrent shard processing
- Automatic backup management

## Security Features

- Ed25519 signatures for data authenticity
- Proof-of-work for spam prevention
- Trust-based peer selection
- Sender anonymity through random push

## Edge Nodes

Edge nodes serve as bootstrap peers with special properties:
- Permanent retention in peer table
- Immunity to normal pruning rules
- Online/offline state tracking

## Performance Considerations

- Concurrent shard processing
- Configurable pruning intervals
- Ring buffer for recent data
- Trust-based resource allocation

Citations:
[1] https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/12516202/cf1409e3-8677-4b3a-8d56-f2701d171abb/paste.txt
[2] https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/12516202/0668448f-2209-4403-b5a5-84399198f0df/paste-2.txt