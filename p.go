package godave

import (
	"bufio"
	"bytes"
	"container/heap"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	mrand "math/rand"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/cespare/xxhash"
	"github.com/intob/godave/dave"
	cuckoo "github.com/panmari/cuckoofilter"
	"google.golang.org/protobuf/proto"
	"lukechampine.com/blake3"
)

const (
	BUF        = 1424   // Max packet size, 1500 MTU is typical, avoids packet fragmentation.
	FANOUT     = 3      // Number of peers randomly selected when selecting more than one.
	PROBE      = 8      // Inverse of probability that an untrusted peer is randomly selected.
	GETNPEER   = 2      // Limit of peer descriptors in a PEER message.
	MINWORK    = 8      // Minimum amount of acceptable work in number of leading zero bits.
	TRUSTEXP   = .375   // Exponent to apply to trust score to flatten distribution of peer selection.
	FILTERLOAD = .95    // Maximum load factor of seed filter.
	DELAY      = 28657  // Epochs until new peers may be randomly selected.
	PING       = 14197  // Epochs until silent peers are pinged with a GETPEER message.
	DROP       = 131071 // Epochs until silent peers are dropped from the peer table.
	SEED       = 3      // Epochs between sending one dat to one peer.
	SET        = 17     // Epochs between each round of sending a new dat from the app.
	GET        = 257    // Epochs between each round of getting a new dat for the app.
	PRUNE      = 26227  // Epochs between pruning the dat store.
)

var zeroTable = [256]uint8{ // Lookup table for the number of leading zero bits in a byte
	8, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

type Dave struct {
	Recv       <-chan *dave.M
	Send       chan<- *dave.M
	epoch      time.Duration
	kill, done chan struct{}
}

type Cfg struct {
	LstnAddr      *net.UDPAddr     // Listening address:port
	Edges         []netip.AddrPort // Bootstrap peers
	Epoch         time.Duration    // Base cycle, lower runs faster, using more bandwidth
	ShardCap      uint             // Shard capacity
	SeedFilterCap uint             // Cuckoo filter capacity
	Log           chan<- []byte    // Log messages
	BackupFname   string           // Dat and peer table backup filename
}

type Dat struct {
	V, S, W []byte // Val, Salt, Work
	Ti      time.Time
}

type peer struct {
	pd                   *dave.Pd // Peer descriptor
	fp                   uint64   // Fingerprint
	added, seen, peermsg time.Time
	edge                 bool
	trust                float64
}

type pkt struct {
	msg *dave.M
	ip  netip.AddrPort
}

type pair struct {
	DatID uint64
	Dat   Dat
}

type datheap []*pair

func (h datheap) Len() int { return len(h) }
func (h datheap) Less(i, j int) bool {
	return Mass(h[i].Dat.W, h[i].Dat.Ti) < Mass(h[j].Dat.W, h[j].Dat.Ti)
}
func (h datheap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *datheap) Push(x interface{}) { *h = append(*h, x.(*pair)) }
func (h *datheap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
func (h *datheap) Peek() *pair { return (*h)[0] }

func NewDave(cfg *Cfg) (*Dave, error) {
	if cfg.Epoch == 0 {
		return nil, errors.New("Cfg.Epoch must not be zero. Try 20us")
	}
	if cfg.ShardCap == 0 {
		return nil, errors.New("Cfg.ShardCap must not be zero. Depends on your system's available memory. 10K should be ok")
	}
	if cfg.SeedFilterCap == 0 {
		return nil, errors.New("Cfg.SeedFilterCap must not be zero. 100K should be ok")
	}
	lg(cfg.Log, "/init cfg: %+v\n", *cfg)
	c, err := net.ListenUDP("udp", cfg.LstnAddr)
	if err != nil {
		return nil, err
	}
	bootstrap := make(map[uint64]*peer)
	h := xxhash.New()
	for _, e := range cfg.Edges {
		bootstrap[pdfp(h, pdfrom(e))] = &peer{pd: pdfrom(e), fp: pdfp(h, pdfrom(e)), added: time.Now(), seen: time.Now(), edge: true}
	}
	pktout := make(chan *pkt, 1)
	go writePackets(c, pktout, cfg.Log)
	backup := make(chan *dave.M, 1)
	kill := make(chan struct{}, 1)
	done := make(chan struct{}, 1) // buffer allows writeBackup routine to end when backup disabled
	go writeBackup(backup, kill, done, cfg)
	var dats map[uint8]map[uint64]Dat
	if cfg.BackupFname != "" {
		dats, err = readBackup(h, cfg)
		if err != nil {
			lg(cfg.Log, "/backup failed to read backup file: %s\n", err)
		}
	}
	if dats == nil {
		dats = make(map[uint8]map[uint64]Dat)
		lg(cfg.Log, "/init created empty map\n")
	}
	send := make(chan *dave.M)
	recv := make(chan *dave.M, 1)
	go d(dats, bootstrap, lstn(c, cfg), pktout, backup, send, recv, cfg)
	return &Dave{Recv: recv, Send: send, epoch: cfg.Epoch, kill: kill, done: done}, nil
}

func (d *Dave) Kill() <-chan struct{} {
	d.kill <- struct{}{}
	return d.done
}
func (d *Dave) Get(work []byte, timeout time.Duration) <-chan *Dat {
	c := make(chan *Dat, 1)
	go func() {
		getmsg := &dave.M{Op: dave.Op_GET, W: work}
		d.Send <- getmsg
		defer close(c)
		tick := time.NewTicker(GET * d.epoch)
		timeout := time.NewTimer(timeout)
		for {
			select {
			case <-timeout.C:
				return
			case m := <-d.Recv:
				if m.Op == dave.Op_DAT && bytes.Equal(m.W, work) {
					c <- &Dat{m.V, m.S, m.W, Btt(m.T)}
					return
				}
			case <-tick.C:
				d.Send <- getmsg
			}
		}
	}()
	return c
}
func (d *Dave) Set(dat Dat, rounds int) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		m := &dave.M{Op: dave.Op_DAT, V: dat.V, S: dat.S, W: dat.W, T: Ttb(dat.Ti)}
		d.Send <- m
		defer close(done)
		var r int
		tick := time.NewTicker(SET * d.epoch)
		for range tick.C {
			d.Send <- m
			r++
			if r == rounds {
				done <- struct{}{}
				return
			}
		}
	}()
	return done
}

func Work(val, tim []byte, d uint8) (work, salt []byte) {
	salt = make([]byte, 32)
	h := blake3.New(32, nil)
	h.Write(val)
	h.Write(tim)
	load := h.Sum(nil)
	for {
		crand.Read(salt)
		h.Reset()
		h.Write(salt)
		h.Write(load)
		work = h.Sum(nil)
		if nzerobit(work) >= d {
			return work, salt
		}
	}
}

func Check(val, tim, salt, work []byte) int {
	if len(tim) != 8 || Btt(tim).After(time.Now()) {
		return -3
	}
	return check(blake3.New(32, nil), val, tim, salt, work)
}

func Mass(work []byte, t time.Time) float64 {
	return float64(nzerobit(work)) * (1 / float64(time.Since(t).Milliseconds()))
}

func Ttb(t time.Time) []byte {
	milli := t.UnixNano() / 1000000
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, uint64(milli))
	return bytes
}

func Btt(b []byte) time.Time {
	return time.Unix(0, int64(binary.LittleEndian.Uint64(b))*1000000)
}

func d(dats map[uint8]map[uint64]Dat, peers map[uint64]*peer, pktin <-chan *pkt, pktout chan<- *pkt, backup chan<- *dave.M, appsend <-chan *dave.M, apprecv chan<- *dave.M, cfg *Cfg) {
	var nepoch, npeer, ndat, seedCount, seedMax int
	var seedShardi uint8
	var seedShard map[uint64]*Dat
	var legend *peer
	etick := time.NewTicker(cfg.Epoch)
	xxh := xxhash.New()
	filter := cuckoo.NewFilter(cfg.SeedFilterCap)
	for {
		select {
		case <-etick.C:
			nepoch++
			if nepoch%PRUNE == 0 { // MEMORY MANAGEMENT
				ndat, dats = pruneDats(dats, int(cfg.ShardCap))
				legend, peers = prunePeers(peers)
				npeer = len(peers)
				lg(cfg.Log, "/mem got %d peers, %d dats across %d shards\n", npeer, ndat, len(dats))
			} else if npeer > 0 {
				if ndat > 0 && nepoch%SEED == 0 { // SEND RANDOM DAT TO RANDOM PEER
					if seedCount == seedMax { // BUILD NEXT SEED SHARD
						for found := false; !found; {
							seedShardi = (seedShardi + 1) % 255
							var shard map[uint64]Dat
							shard, found = dats[uint8(seedShardi)]
							if found {
								seedShard = make(map[uint64]*Dat, len(shard))
								for k, d := range shard {
									seedShard[k] = &d
								}
								seedMax = len(shard)
								seedCount = 0
								lg(cfg.Log, "/seed built new shard %d\n", seedShardi)
							}
						}
					}
					if filter.LoadFactor() > FILTERLOAD {
						filter.Reset()
						lg(cfg.Log, "/seed filter reset\n")
					}
					for _, rp := range rndpeers(peers, legend, 0, 1, func(p *peer, l *peer) bool { return share(p, cfg.Epoch) && trust(p, l) }) {
						for k, d := range seedShard {
							if filter.Insert(concatWorkIp(d.W, rp.pd.Ip)) {
								pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: d.V, T: Ttb(d.Ti), S: d.S, W: d.W}, addrfrom(rp.pd)}
								delete(seedShard, k)
								break
							}
						}
					}
					seedCount++
				} else if nepoch%PING == 0 { // PING AND DROP
					for pid, p := range peers {
						if !p.edge && time.Since(p.seen) > DROP*cfg.Epoch { // DROP UNRESPONSIVE PEER
							delete(peers, pid)
							lg(cfg.Log, "/peer/ping/delete %s\n", addrfrom(p.pd))
						} else { // SEND PING
							addr := addrfrom(p.pd)
							pktout <- &pkt{&dave.M{Op: dave.Op_GETPEER}, addr}
							lg(cfg.Log, "/peer/ping/getpeer_msg sent to %s\n", addr)
						}
					}
				}
			}
		case pk := <-pktin: // HANDLE INCOMING PACKET
			pkpd := pdfrom(pk.ip)
			pkpfp := pdfp(xxh, pkpd)
			p, ok := peers[pkpfp]
			if ok {
				p.seen = time.Now()
			} else {
				p = &peer{pd: pkpd, fp: pkpfp, added: time.Now()}
				peers[pkpfp] = p
				lg(cfg.Log, "/peer/add %s %x\n", pk.ip, pkpfp)
			}
			switch pk.msg.Op {
			case dave.Op_PEER: // STORE PEERS
				if time.Since(p.peermsg) >= PING*cfg.Epoch {
					p.peermsg = time.Now()
					for _, mpd := range pk.msg.Pds {
						mpdfp := pdfp(xxh, mpd)
						_, ok := peers[mpdfp]
						if !ok {
							peers[mpdfp] = &peer{pd: mpd, fp: mpdfp, added: time.Now(), seen: time.Now()}
							lg(cfg.Log, "/peer/add_from_gossip %s from %s\n", addrfrom(mpd), pk.ip)
						}
					}
				} else {
					lg(cfg.Log, "/peer/unexpected dropped msg from %s %s\n", pk.ip, time.Since(p.peermsg))
				}
			case dave.Op_GETPEER: // GIVE PEERS
				rpeers := rndpeers(peers, legend, p.fp, GETNPEER, func(p *peer, l *peer) bool { return share(p, cfg.Epoch) })
				pds := make([]*dave.Pd, len(rpeers))
				for i, rp := range rpeers {
					pds[i] = rp.pd
				}
				pktout <- &pkt{&dave.M{Op: dave.Op_PEER, Pds: pds}, pk.ip}
				lg(cfg.Log, "/peer/reply_to_getpeer %s %x\n", pk.ip, p.fp)
			case dave.Op_DAT: // STORE AND INSERT INTO FILTER
				dat := &Dat{pk.msg.V, pk.msg.S, pk.msg.W, Btt(pk.msg.T)}
				novel, shardid, err := put(dats, dat, xxh)
				if err != nil {
					lg(cfg.Log, "/store error: %s\n", err)
				}
				filter.Insert(concatWorkIp(pk.msg.W, pkpd.Ip))
				if novel {
					p.trust += Mass(pk.msg.W, Btt(pk.msg.T))
					if cfg.BackupFname != "" {
						backup <- pk.msg
					}
					lg(cfg.Log, "/store %x %d %s %f\n", pk.msg.W, shardid, pk.ip, p.trust)
				}
			case dave.Op_GET: // REPLY WITH DAT
				shardi, dati := workid(xxh, pk.msg.W)
				shard, ok := dats[shardi]
				if ok { // GOT SHARD
					dat, ok := shard[dati]
					if ok { // GOT DAT
						pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: dat.V, T: Ttb(dat.Ti), S: dat.S, W: dat.W}, pk.ip}
						lg(cfg.Log, "/dat/reply_to_get %s %x\n", pk.ip, dat.W)
					}
				}
			}
		case m := <-appsend: // SEND PACKET FOR APP
			if cfg.BackupFname != "" && m.Op == dave.Op_DAT {
				backup <- m
			}
			sendForApp(m, dats, xxh, peers, legend, pktout, apprecv, cfg.Log)
		}
	}
}

func concatWorkIp(work []byte, ip []byte) []byte {
	buf := make([]byte, 32+16)
	copy(buf, work)
	copy(buf[32:], ip)
	return buf
}

func writePackets(c *net.UDPConn, pkts <-chan *pkt, log chan<- []byte) {
	for pkt := range pkts {
		bin, err := proto.Marshal(pkt.msg)
		if err != nil {
			panic(err)
		}
		_, err = c.WriteToUDPAddrPort(bin, pkt.ip)
		if err != nil {
			lg(log, "/dispatch error: %s\n", err)
		}
	}
}

func pruneDats(dats map[uint8]map[uint64]Dat, cap int) (int, map[uint8]map[uint64]Dat) {
	newdats := make(map[uint8]map[uint64]Dat)
	var ndat int
	for shardid, shard := range dats {
		dh := &datheap{}
		heap.Init(dh)
		for datid, dat := range shard {
			if dh.Len() < cap {
				heap.Push(dh, &pair{datid, dat})
			} else if Mass(dat.W, dat.Ti) > Mass(dh.Peek().Dat.W, dh.Peek().Dat.Ti) {
				heap.Pop(dh)
				heap.Push(dh, &pair{datid, dat})
			}
		}
		newdats[shardid] = make(map[uint64]Dat, dh.Len())
		for dh.Len() > 0 {
			pair := heap.Pop(dh).(*pair)
			newdats[shardid][pair.DatID] = pair.Dat
			ndat++
		}
	}
	return ndat, newdats
}

func prunePeers(peers map[uint64]*peer) (*peer, map[uint64]*peer) {
	newpeers := make(map[uint64]*peer)
	var legend *peer
	for k, p := range peers {
		newpeers[k] = p
		if legend == nil || p.trust > legend.trust {
			legend = p
		}
	}
	return legend, newpeers
}

func writeBackup(backup <-chan *dave.M, kill <-chan struct{}, done chan<- struct{}, cfg *Cfg) {
	if cfg.BackupFname == "" {
		done <- struct{}{}
		lg(cfg.Log, "/backup disabled\n")
		return
	}
	f, err := os.OpenFile(cfg.BackupFname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(fmt.Sprintf("/backup failed to open file: %s\n", err))
	}
	buf := bufio.NewWriter(f)
	for {
		select {
		case <-kill:
			flushErr := buf.Flush()
			closeErr := f.Close()
			done <- struct{}{}
			lg(cfg.Log, "/backup buffer flushed, file closed, errors if any: %v %v\n", flushErr, closeErr)
			return
		case m := <-backup:
			b, _ := proto.Marshal(m)
			lenb := make([]byte, 2)
			binary.LittleEndian.PutUint16(lenb, uint16(len(b)))
			buf.Write(lenb)
			buf.Write(b)
		}
	}
}

func readBackup(h hash.Hash64, cfg *Cfg) (map[uint8]map[uint64]Dat, error) {
	dats := make(map[uint8]map[uint64]Dat)
	workHash := blake3.New(32, nil)
	f, err := os.Open(cfg.BackupFname)
	if err != nil {
		return nil, fmt.Errorf("err opening file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("err reading file info: %w", err)
	}
	size := info.Size()
	var pos int64
	var ndat uint
	defer lg(cfg.Log, "/backup read %d dats from file\n", ndat)
	lb := make([]byte, 2)
	for pos < size {
		n, err := f.Read(lb)
		pos += int64(n)
		if err != nil {
			return dats, fmt.Errorf("err reading len prefix: %w", err)
		}
		datbuf := make([]byte, binary.LittleEndian.Uint16(lb))
		n, err = f.Read(datbuf)
		pos += int64(n)
		if err != nil {
			lg(cfg.Log, "/backup read err reading length-prefixed msg: %s\n", err)
			continue
		}
		m := &dave.M{}
		err = proto.Unmarshal(datbuf, m)
		if err != nil {
			lg(cfg.Log, "/backup unmarshal err unmarshalling proto msg: %s\n", err)
			continue
		}
		if m.Op != dave.Op_DAT {
			lg(cfg.Log, "/backup not a dat\n")
			continue
		}
		if check(workHash, m.V, m.T, m.S, m.W) < MINWORK {
			lg(cfg.Log, "/backup work check  failed\n")
			continue
		}
		shardi, dati := workid(h, m.W)
		if _, ok := dats[shardi]; !ok {
			dats[shardi] = make(map[uint64]Dat)
		}
		dats[shardi][dati] = Dat{V: m.V, Ti: Btt(m.T), S: m.S, W: m.W}
		ndat++
	}
	return dats, nil
}

func sendForApp(m *dave.M, dats map[uint8]map[uint64]Dat, h hash.Hash64, peers map[uint64]*peer, legend *peer, pktout chan<- *pkt, apprecv chan<- *dave.M, log chan<- []byte) {
	if m != nil {
		switch m.Op {
		case dave.Op_DAT:
			put(dats, &Dat{m.V, m.S, m.W, Btt(m.T)}, h)
			go func(rps []*peer) {
				for _, rp := range rps {
					pktout <- &pkt{m, addrfrom(rp.pd)}
					lg(log, "/send_for_app dat sent %x to %x\n", m.W, rp.fp)
				}
			}(rndpeers(peers, legend, 0, FANOUT, func(p *peer, l *peer) bool { return true }))
		case dave.Op_GET:
			shardi, dati := workid(h, m.W)
			var found bool
			shard, ok := dats[shardi]
			if ok {
				dat, ok := shard[dati]
				if ok {
					found = true
					apprecv <- &dave.M{Op: dave.Op_DAT, V: dat.V, T: Ttb(dat.Ti), S: dat.S, W: dat.W}
					lg(log, "/send_for_app get found locally %x\n", dat.W)
				}
			}
			if !found {
				go func(rps []*peer) {
					for _, rp := range rps {
						pktout <- &pkt{&dave.M{Op: dave.Op_GET, W: m.W}, addrfrom(rp.pd)}
						lg(log, "/send_for_app get sent %x %x\n", rp.fp, m.W)
					}
				}(rndpeers(peers, legend, 0, FANOUT, func(p *peer, l *peer) bool { return true }))
			}
		default:
			panic(fmt.Sprintf("unsupported operation: send %s", m.Op))
		}
	}
}

func put(dats map[uint8]map[uint64]Dat, d *Dat, h hash.Hash64) (bool, uint8, error) {
	shardid, datid := workid(h, d.W)
	shard, ok := dats[shardid]
	if !ok {
		dats[shardid] = make(map[uint64]Dat)
		dats[shardid][datid] = *d
		return true, shardid, nil
	} else {
		_, ok := shard[datid]
		if !ok {
			shard[datid] = *d
			return true, shardid, nil
		}
		return false, shardid, nil
	}
}

func lstn(c *net.UDPConn, cfg *Cfg) <-chan *pkt {
	pkts := make(chan *pkt, 1)
	go func() {
		bpool := sync.Pool{New: func() any { return make([]byte, BUF) }}
		mpool := sync.Pool{New: func() any { return &dave.M{} }}
		ch := blake3.New(32, nil)
		defer c.Close()
		for {
			p := rdpkt(c, ch, &bpool, &mpool, cfg)
			if p != nil {
				pkts <- p
			}
		}
	}()
	return pkts
}

func rdpkt(c *net.UDPConn, ch *blake3.Hasher, bpool, mpool *sync.Pool, cfg *Cfg) *pkt {
	buf := bpool.Get().([]byte)
	defer bpool.Put(buf) //lint:ignore SA6002 slice is already a reference
	n, raddr, err := c.ReadFromUDPAddrPort(buf)
	if err != nil {
		panic(err)
	}
	m := mpool.Get().(*dave.M)
	defer mpool.Put(m)
	err = proto.Unmarshal(buf[:n], m)
	if err != nil {
		lg(cfg.Log, "/rdpkt failed to unmarshal\n")
		return nil
	}
	if m.Op == dave.Op_PEER && len(m.Pds) > GETNPEER {
		lg(cfg.Log, "/rdpkt packet exceeds pd limit\n")
		return nil

	} else if m.Op == dave.Op_DAT {
		work := check(ch, m.V, m.T, m.S, m.W)
		if work < MINWORK {
			lg(cfg.Log, "/rdpkt failed work check: %d from %s\n", work, raddr)
			return nil
		}
	}
	cpy := &dave.M{Op: m.Op, Pds: make([]*dave.Pd, len(m.Pds)), V: m.V, T: m.T, S: m.S, W: m.W}
	for i, pd := range m.Pds {
		cpy.Pds[i] = &dave.Pd{Ip: pd.Ip, Port: pd.Port}
	}
	return &pkt{cpy, raddr}
}

func rndpeers(prs map[uint64]*peer, legend *peer, excludePeerFp uint64, lim int, match func(p, legend *peer) bool) []*peer {
	candidates := make([]*peer, 0, len(prs))
	for fp, peer := range prs {
		if fp != excludePeerFp && match(peer, legend) {
			candidates = append(candidates, peer)
		}
	}
	if len(candidates) <= lim {
		return candidates
	}
	ans := make([]*peer, lim)
	for i := 0; i < lim; i++ {
		r := i + mrand.Intn(len(candidates)-i)
		ans[i] = candidates[r]
	}
	return ans
}

func share(k *peer, epoch time.Duration) bool {
	return time.Since(k.added) > DELAY*epoch
}

func trust(p *peer, legend *peer) bool {
	return p.edge || mrand.Intn(PROBE) == 1 || mrand.Float64() < math.Pow(p.trust/legend.trust, TRUSTEXP)
}

func addrfrom(pd *dave.Pd) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom16([16]byte(pd.Ip)), uint16(pd.Port))
}

func pdfrom(addrport netip.AddrPort) *dave.Pd {
	ip := addrport.Addr().As16()
	return &dave.Pd{Ip: ip[:], Port: uint32(addrport.Port())}
}

func pdfp(h hash.Hash64, pd *dave.Pd) uint64 {
	port := make([]byte, 2)
	binary.LittleEndian.PutUint16(port, uint16(pd.Port))
	h.Reset()
	h.Write(port)
	h.Write(pd.Ip)
	return h.Sum64()
}

func workid(h hash.Hash64, work []byte) (uint8, uint64) {
	h.Reset()
	h.Write(work)
	return nzerobit(work), h.Sum64()
}

func check(h *blake3.Hasher, val, tim, salt, work []byte) int {
	if len(tim) != 8 || Btt(tim).After(time.Now()) {
		return -2
	}
	h.Reset()
	h.Write(val)
	h.Write(tim)
	load := h.Sum(nil)
	h.Reset()
	h.Write(salt)
	h.Write(load)
	if !bytes.Equal(h.Sum(nil), work) {
		return -1
	}
	return int(nzerobit(work))
}

func nzerobit(key []byte) uint8 {
	var count uint8
	for _, b := range key {
		count += zeroTable[b]
		if b != 0 {
			return count
		}
	}
	return count
}

func lg(ch chan<- []byte, msg string, args ...any) {
	select {
	case ch <- []byte(fmt.Sprintf(msg, args...)):
	default:
	}
}
