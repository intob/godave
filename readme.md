# Dave - Distributed Key-Value Store

Dave is a peer-to-peer key-value store built on UDP, designed for efficient data distribution and resource allocation using XOR metric and proof-of-work.

## Core Features

- Distributed key-value storage over UDP
- XOR metric used to prioritise replicas
- Random storage challenges measure peer reliability
- Sharding for concurrent processing
- Automatic peer discovery
- Data backup and recovery
- Just two dependencies:
    - https://github.com/cespare/xxhash/v2
    - https://github.com/lukechampine/blake3

## Architecture

### Network Protocol

- **Maximum Packet Size**: 1424 bytes to avoid fragmentation
- **Transport**: UDP with optimised serialization (x4 faster than protobuf)
- **Peer Management**: Dynamic peer discovery with trust scoring
- **Data Distribution**: XOR metric for deterministic propagation

### Storage System

- **Sharding**: Concurrent processing with configurable shard capacity
- **Data Prioritization**: XOR metric and time-bound storage prioritization
- **Backup**: Automatic data persistence and recovery with configurable backup files

## Configuration

```go
type DaveCfg struct {
	// A UDP socket. Normally from net.ListenUDP. This interface can be mocked
	// to build simulations.
	Socket pkt.Socket
	// Node private key. The last 32 bytes are the public key. The node ID is
	// derived from the first 8 bytes of the public key.
	PrivateKey    ed25519.PrivateKey
	Edges         []netip.AddrPort // Bootstrap peers.
	ShardCapacity int64            // Capacity of each of 256 shards in bytes.
	// Time-to-live of data. Data older than this will be replaced as needed,
	// if new data has a higher priority. Priority is a function of age and
	// XOR distance.
	TTL            time.Duration
	BackupFilename string // Filename of backup file. Leave blank to disable backup.
	// Set to nil to disable logging, although this is not reccomended. Currently
	// logging is the best way to monitor. In future, the API will be better.
	Logger logger.Logger
}
```

## Protocol Operations

- **PING/PONG**: Peer liveness and discovery
- **PUT**: Store data with proof-of-work
- **GET/GET_ACK**: Retrieve stored data
- **GETMYADDRPORT/GETMYADDRPORT_ACK**: Get own address:port from a remote

## Trust System

- Reliability is measured using random storage challenges
- No gossip about reliability to prevent attack vectors
- Reliability influences peer selection
- Reliability influences re-propagation

## Pruning and Maintenance

- Periodic pruning of inactive peers
- Concurrent shard processing
- Automatic backup management

## Security Features

- Ed25519 signatures for data authenticity
- Proof-of-work for spam prevention
- Trust-based peer selection
- Loopback prevention
- Peer table poisoning (and by extension Eclipse attack) prevention

## Edge Nodes

Edge nodes serve as bootstrap peers, and are permanently retained in the peer table.

## Performance Considerations

- Concurrent packet processing
- Concurrent shard processing
- Configurable pruning intervals
- Priority heap for data prioritisation, O(log n) inserts
