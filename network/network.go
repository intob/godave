package network

import "time"

const (
	// Max packet size, 1500 MTU is typical, prevents packet fragmentation
	MAX_MSG_LEN = 1424

	FANOUT              = 3                // Number of peers selected when sending dats.
	PROBE               = 12               // Inverse of probability that a peer is selected regardless of trust.
	NPEER_LIMIT         = 5                // Maximum number of peer descriptors in a PONG message.
	MIN_WORK            = 16               // Minimum amount of acceptable work in number of leading zero bits.
	PING                = 1 * time.Second  // Period between pinging peers.
	ACTIVATE_AFTER      = 5 * PING         // Time until new peers are activated.
	DEACTIVATE_AFTER    = 3 * PING         // Time until protocol-deviating peers are deactivated.
	DROP_AFTER          = 12 * PING        // Time until protocol-deviating peers are dropped.
	GETMYADDRPORT_EVERY = 10 * time.Minute // Period between getting my addrport from an edge.
	// Time-to-live of data. Data older than this will be replaced as needed,
	// if new data has a higher priority. Priority is a function of age and
	// XOR distance.
	TTL                           = 365 * 24 * time.Hour
	STORAGE_CHALLENGE_PROBABILITY = 0.1 // Probability that a dat will be used as a storage challenge.
	STORAGE_CHALLENGE_EVERY       = 10 * time.Second
	// This doesn't really work on it's own. Maybe measure peer ping time and account for that.
	// This can be broken, though, as peers can add additional time. To fix that, we can
	// reward low ping time in the same "reliability" function.
	STORAGE_CHALLENGE_DEADLINE = 120 * time.Millisecond
)
