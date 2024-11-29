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

- **Maximum Packet Size**: 1424 bytes to avoid fragmentation
- **Transport**: UDP with optimised serialization (x4 faster than protobuf)
- **Peer Management**: Dynamic peer discovery with trust scoring
- **Data Distribution**: XOR metric for determinism, random push for anonymity

### Storage System

- **Sharding**: Concurrent processing with configurable shard capacity
- **Data Prioritization**: XOR metric and time-bound storage prioritization
- **Backup**: Automatic data persistence and recovery with configurable backup files

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

## Pruning and Maintenance

- Periodic pruning of inactive peers
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

- Concurrent packet processing
- Concurrent shard processing
- Configurable pruning intervals
- Ring buffer for recent data
- Trust-based resource allocation
- Heap for data prioritisation
- Xor distance implemented in assembly
