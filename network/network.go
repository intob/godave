package network

import "time"

const (
	// Max packet size, 1500 MTU is typical, prevents packet fragmentation
	MAX_MSG_LEN = 1424
	// Number of peers selected when sending dats.
	FANOUT = 5
	// Inverse of probability that a peer is selected regardless of trust.
	PROBE = 12
	// Maximum number of peer descriptors in a PONG message.
	NPEER_LIMIT = 5
	// Minimum amount of acceptable work in number of leading zero bits.
	MIN_WORK = 8
	// Period between pinging peers.
	PING = 1 * time.Second
	// Time until new peers are activated.
	ACTIVATE_AFTER = 5 * PING
	// Time until protocol-deviating peers are deactivated.
	DEACTIVATE_AFTER = 3 * PING
	// Time until protocol-deviating peers are dropped.
	DROP_AFTER = 12 * PING
	// Period between getting my addrport from an edge.
	GETMYADDRPORT_EVERY = 10 * time.Minute
	// Time-to-live of data. Data older than this will be replaced as needed,
	// if new data has a higher priority. Priority is a function of age and
	// XOR distance.
	TTL = 365 * 24 * time.Hour
	// Period between evaluating replicas of each entry.
	REPLICATE_EVERY = 10 * time.Minute
)
