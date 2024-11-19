package godave

import (
	"bufio"
	"bytes"
	"container/heap"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	xxhash "github.com/cespare/xxhash/v2"
	"github.com/intob/godave/dave"
	"github.com/intob/godave/ringbuffer"
	"google.golang.org/protobuf/proto"
	"lukechampine.com/blake3"
)

const (
	EPOCH        = 500 * time.Microsecond
	BUF          = 1424             // Max packet size, 1500 MTU is typical, avoids packet fragmentation.
	FANOUT       = 5                // Number of peers randomly selected when selecting more than one.
	PROBE        = 8                // Inverse of probability that an untrusted peer is randomly selected.
	GETNPEER     = 2                // Limit of peer descriptors in a PEER message.
	MINWORK      = 8                // Minimum amount of acceptable work in number of leading zero bits.
	MAXWORK      = 64               // Maximum ammount of work in number of leading zero bits. To limit number of ring buffers.
	MAXTRUST     = 25               // Maximum trust score, ensuring fair trust distribution from feedback.
	APP          = 100              // Epochs between each round of sending a message for the app.
	PING         = 8 * time.Second  // Time until peers are pinged with a GETPEER message.
	DROP         = 16 * time.Second // Time until silent peers are dropped from the peer table.
	SHARE_DELAY  = 20 * time.Second // Time until new peers are shared. Must be greater than DROP.
	PRUNE        = time.Minute      // Period between pruning dats & peers.
	RINGSIZE     = 1000             // Number of dats to store in ring buffer.
	LOGLVL_ERROR = LogLvl(0)        // Base log level, for errors & status.
	LOGLVL_DEBUG = LogLvl(1)        // Debugging log level.
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

type LogLvl int

type Dave struct {
	recv       <-chan *Dat
	send       chan<- *dave.M
	kill, done chan struct{}
	npeer      *atomic.Int32
}

type Cfg struct {
	UdpListenAddr *net.UDPAddr     // Listening address:port
	Edges         []netip.AddrPort // Bootstrap peers
	ShardCap      int              // Shard capacity
	Log           chan<- string    // Log message output
	LogLvl        LogLvl           // Log level
	BackupFname   string           // Dat table backup filename
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
	id  uint64
	dat Dat
}

type datheap []*pair

func (h datheap) Len() int { return len(h) }
func (h datheap) Less(i, j int) bool {
	return Mass(h[i].dat.W, h[i].dat.Ti) < Mass(h[j].dat.W, h[j].dat.Ti)
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
	tstart := time.Now()
	lg(cfg, LOGLVL_ERROR, "/init cfg: %+v", *cfg)
	bootstrap := make(map[uint64]*peer)
	for _, e := range cfg.Edges {
		bootstrap[pdfp(pdfrom(e))] = &peer{pd: pdfrom(e), fp: pdfp(pdfrom(e)), added: time.Now(), edge: true}
	}
	udpc, err := net.ListenUDP("udp", cfg.UdpListenAddr)
	if err != nil {
		return nil, err
	}
	dats := make([]map[uint64]Dat, MAXWORK-MINWORK)
	for i := range dats {
		dats[i] = make(map[uint64]Dat)
	}
	var ndat uint32
	if cfg.BackupFname != "" {
		ndat, dats, err = readBackup(cfg.BackupFname)
		if err != nil {
			lg(cfg, LOGLVL_ERROR, "/init failed to read backup file: %s", err)
		}
		lg(cfg, LOGLVL_ERROR, "/init read %d dats from file", ndat)
		ndat, dats = pruneDats(dats, cfg.ShardCap)
		err = writeFreshBackup(dats, cfg.BackupFname)
		if err != nil {
			panic(err)
		}
	}
	if dats == nil {
		dats = make([]map[uint64]Dat, MAXWORK-MINWORK)
		lg(cfg, LOGLVL_ERROR, "/init created empty map")
	}
	lg(cfg, LOGLVL_ERROR, "/init pruned %d dats across %d shards, init took %s", ndat, len(dats), time.Since(tstart))
	backup := make(chan *dave.M, 100)
	kill := make(chan struct{}, 1)
	done := make(chan struct{}, 1) // buffer allows writeBackup routine to end when backup disabled
	go writeBackup(backup, kill, done, cfg)
	pktout := make(chan *pkt, 100)
	go writePackets(udpc, pktout, cfg)
	send := make(chan *dave.M)
	recv := make(chan *Dat, 100)
	npeer := &atomic.Int32{}
	go d(dats, bootstrap, ndat, npeer, lstn(udpc, cfg), pktout, backup, send, recv, cfg)
	return &Dave{recv: recv, send: send, kill: kill, done: done, npeer: npeer}, nil
}

func (d *Dave) Kill() <-chan struct{} {
	d.kill <- struct{}{}
	return d.done
}

func (d *Dave) Get(work []byte, npeer int32, timeout time.Duration) <-chan *Dat {
	c := make(chan *Dat, 1)
	go func() {
		for d.npeer.Load() < npeer {
			time.Sleep(APP * EPOCH)
		}
		d.send <- &dave.M{Op: dave.Op_GET, W: work}
		defer close(c)
		tick := time.NewTicker(APP * EPOCH)
		timeout := time.NewTimer(timeout)
		for {
			select {
			case <-timeout.C:
				return
			case dat := <-d.recv:
				if bytes.Equal(dat.W, work) {
					c <- dat
					return
				}
			case <-tick.C:
				d.send <- &dave.M{Op: dave.Op_GET, W: work}
			}
		}
	}()
	return c
}

func (d *Dave) Set(dat *Dat, rounds, npeer int32) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		for d.npeer.Load() < npeer {
			time.Sleep(APP * EPOCH)
		}
		m := &dave.M{Op: dave.Op_DAT, V: dat.V, S: dat.S, W: dat.W, T: Ttb(dat.Ti)}
		d.send <- m
		defer close(done)
		var r int32
		tick := time.NewTicker(APP * EPOCH)
		for range tick.C {
			d.send <- m
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
	salt = make([]byte, 8)
	h := blake3.New(32, nil)
	h.Write(val)
	h.Write(tim)
	load := h.Sum(nil)
	counter := uint64(0)
	for {
		*(*uint64)(unsafe.Pointer(&salt[0])) = counter
		h.Reset()
		h.Write(salt)
		h.Write(load)
		work = h.Sum(nil)
		if nzerobit(work) >= d {
			return work, salt
		}
		counter++
	}
}

func Check(val, tim, salt, work []byte) int {
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

func d(dats []map[uint64]Dat, peers map[uint64]*peer, ndat uint32, npeer *atomic.Int32, pktin <-chan *pkt, pktout chan<- *pkt, backup chan<- *dave.M, appsend <-chan *dave.M, apprecv chan<- *Dat, cfg *Cfg) {
	npeer.Store(int32(len(peers)))
	var peerList []*peer // sorted by trust score, updated during prune
	var trustSum float64
	epochTick := time.NewTicker(EPOCH)
	pruneTick := time.NewTicker(PRUNE)
	pingTick := time.NewTicker(PING)
	statTick := time.NewTicker(5 * time.Second)
	ring := ringbuffer.NewRingBuffer[*Dat](RINGSIZE)
	var cshard uint8
	for {
		select {
		case pk := <-pktin: // HANDLE INCOMING PACKET
			pkpd := pdfrom(pk.ip)
			pkfp := pdfp(pkpd)
			_, ok := peers[pkfp]
			if ok {
				peers[pkfp].seen = time.Now()
			} else {
				peers[pkfp] = &peer{pd: pkpd, fp: pkfp, added: time.Now(), seen: time.Now()}
				trustSum, peerList, peers = prunePeers(peers)
				npeer.Add(1)
				lg(cfg, LOGLVL_ERROR, "/peer/add %s %x", pk.ip, pkfp)
			}
			switch pk.msg.Op {
			case dave.Op_PEER: // STORE PEERS
				if time.Since(peers[pkfp].peermsg) >= PING-10*time.Millisecond {
					peers[pkfp].peermsg = time.Now()
					for _, mpd := range pk.msg.Pds {
						mpdfp := pdfp(mpd)
						_, ok := peers[mpdfp]
						if !ok {
							peers[mpdfp] = &peer{pd: mpd, fp: mpdfp, added: time.Now(), seen: time.Now()}
							npeer.Add(1)
							lg(cfg, LOGLVL_ERROR, "/peer/add_from_gossip %s from %s", addrfrom(mpd), pk.ip)
						}
					}
					trustSum, peerList, peers = prunePeers(peers)
				} else {
					lg(cfg, LOGLVL_ERROR, "/peer/unexpected dropped msg from %s", pk.ip)
				}
			case dave.Op_GETPEER: // GIVE PEERS
				rps := rndpeers(peerList, trustSum, GETNPEER, pkfp, SHARE_DELAY)
				pds := make([]*dave.Pd, len(rps))
				for i, p := range rps {
					pds[i] = p.pd
				}
				pktout <- &pkt{&dave.M{Op: dave.Op_PEER, Pds: pds}, pk.ip}
				lg(cfg, LOGLVL_DEBUG, "/peer/reply_to_getpeer %s", pk.ip)
			case dave.Op_DAT: // STORE DAT
				dat := &Dat{pk.msg.V, pk.msg.S, pk.msg.W, Btt(pk.msg.T)}
				select {
				case apprecv <- dat:
				default:
				}
				novel, err := put(dats, dat)
				if err != nil {
					lg(cfg, LOGLVL_ERROR, "/store error: %s", err)
				}
				if novel {
					ndat++
					trust := peers[pkfp].trust
					if trust < MAXTRUST {
						trust += Mass(pk.msg.W, Btt(pk.msg.T))
						if trust > MAXTRUST {
							trust = MAXTRUST
						}
					}
					if cfg.BackupFname != "" {
						backup <- pk.msg
					}
					ring.Write(dat)
					lg(cfg, LOGLVL_DEBUG, "/store %x %s %f", pk.msg.W, pk.ip, trust)
				}
			case dave.Op_GET: // REPLY WITH DAT
				shardKey, datKey := keys(pk.msg.W)
				dat, ok := dats[shardKey][datKey]
				if ok { // GOT DAT
					pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: dat.V, T: Ttb(dat.Ti), S: dat.S, W: dat.W}, pk.ip}
					lg(cfg, LOGLVL_DEBUG, "/dat/reply_to_get %s %x", pk.ip, dat.W)
				}
			}
		case <-epochTick.C: // SEED
			rp := rndpeer(peerList, trustSum)
			if ndat > 0 && rp != nil {
				raddr := addrfrom(rp.pd)
				d := rnddat(dats[cshard])
				if d != nil {
					pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: d.V, T: Ttb(d.Ti), S: d.S, W: d.W}, raddr}
				}
				d, ok := ring.Read()
				if ok {
					pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: d.V, T: Ttb(d.Ti), S: d.S, W: d.W}, raddr}
				} else {
					lg(cfg, LOGLVL_DEBUG, "/push nothing in ring buffer")
				}
				for {
					cshard = (cshard + 1) % uint8(MAXWORK-MINWORK)
					if len(dats[cshard]) > 0 {
						break
					}
				}
			}
		case <-pingTick.C: // PING & DROP PEERS
			var dropped bool
			for pid, p := range peers {
				if !p.edge && time.Since(p.seen) > DROP {
					delete(peers, pid)
					npeer.Add(-1)
					dropped = true
					lg(cfg, LOGLVL_ERROR, "/peer/ping/drop %s, not seen for %s", addrfrom(p.pd), time.Since(p.seen))
				} else if time.Since(p.peermsg) > PING { // SEND PING
					addr := addrfrom(p.pd)
					pktout <- &pkt{&dave.M{Op: dave.Op_GETPEER}, addr}
					lg(cfg, LOGLVL_DEBUG, "/peer/ping/getpeer_msg sent to %s", addr)
				}
			}
			if dropped {
				trustSum, peerList, peers = prunePeers(peers)
			}
		case <-pruneTick.C: // PRUNE DATS & PEERS
			tstart := time.Now()
			ndat, dats = pruneDats(dats, cfg.ShardCap)
			trustSum, peerList, peers = prunePeers(peers)
			lg(cfg, LOGLVL_ERROR, "/prune got %d peers, %d dats across %d shards, took %s", len(peerList), ndat, len(dats), time.Since(tstart))
		case m := <-appsend: // SEND PACKET FOR APP
			sendForApp(m, dats, peerList, trustSum, pktout, apprecv, cfg)
			if cfg.BackupFname != "" && m.Op == dave.Op_DAT {
				backup <- m
			}
		case <-statTick.C:
			lg(cfg, LOGLVL_ERROR, "/stat got %d peers, %d dats", npeer.Load(), ndat)
		}
	}
}

func writePackets(c *net.UDPConn, pkts <-chan *pkt, cfg *Cfg) {
	for pkt := range pkts {
		bin, err := proto.Marshal(pkt.msg)
		if err != nil {
			lg(cfg, LOGLVL_ERROR, "/dispatch error: %s", err)
			continue
		}
		_, err = c.WriteToUDPAddrPort(bin, pkt.ip)
		if err != nil {
			lg(cfg, LOGLVL_ERROR, "/dispatch error: %s", err)
		}
	}
}

func pruneDats(dats []map[uint64]Dat, cap int) (uint32, []map[uint64]Dat) {
	newdats := make([]map[uint64]Dat, MAXWORK-MINWORK)
	var ndat uint32
	var wg sync.WaitGroup
	var mu sync.Mutex
	jobs := make(chan int, len(dats))
	for w := 0; w < runtime.NumCPU(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for shardid := range jobs {
				dh := &datheap{}
				heap.Init(dh)
				for datid, dat := range dats[shardid] {
					if dh.Len() < cap {
						heap.Push(dh, &pair{datid, dat})
					} else if dat.Ti.After(dh.Peek().dat.Ti) {
						heap.Pop(dh)
						heap.Push(dh, &pair{datid, dat})
					}
				}
				shardMap := make(map[uint64]Dat, dh.Len())
				var localCount uint32
				for dh.Len() > 0 {
					pair := heap.Pop(dh).(*pair)
					shardMap[pair.id] = pair.dat
					localCount++
				}
				newdats[shardid] = shardMap
				mu.Lock()
				ndat += localCount
				mu.Unlock()
			}
		}()
	}
	for shardid := range dats {
		jobs <- shardid
	}
	close(jobs)
	wg.Wait()
	return ndat, newdats
}

func prunePeers(peers map[uint64]*peer) (float64, []*peer, map[uint64]*peer) {
	newpeers := make(map[uint64]*peer, len(peers))
	list := make([]*peer, 0, len(peers))
	var trustSum float64
	for k, p := range peers {
		newpeers[k] = p
		list = append(list, p)
		trustSum += p.trust
	}
	sort.Slice(list, func(i, j int) bool { return list[i].trust > list[j].trust })
	return trustSum, list, newpeers
}

func writeBackup(backup <-chan *dave.M, kill <-chan struct{}, done chan<- struct{}, cfg *Cfg) {
	if cfg.BackupFname == "" {
		done <- struct{}{}
		lg(cfg, LOGLVL_ERROR, "/backup disabled")
		return
	}
	f, err := os.OpenFile(cfg.BackupFname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(fmt.Sprintf("/backup failed to open file: %s", err))
	}
	buf := bufio.NewWriter(f)
	for {
		select {
		case <-kill:
			flushErr := buf.Flush()
			closeErr := f.Close()
			done <- struct{}{}
			lg(cfg, LOGLVL_ERROR, "/backup buffer flushed, file closed, errors if any: %v %v", flushErr, closeErr)
			return
		case m := <-backup:
			b, err := proto.Marshal(m)
			if err != nil {
				lg(cfg, LOGLVL_ERROR, "/backup failed to marshal: %s", err)
				continue
			}
			lenb := make([]byte, 2)
			binary.LittleEndian.PutUint16(lenb, uint16(len(b)))
			buf.Write(lenb)
			buf.Write(b)
		}
	}
}

func writeFreshBackup(dats []map[uint64]Dat, fname string) error {
	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := bufio.NewWriter(f)
	for _, shard := range dats {
		for _, d := range shard {
			b, err := proto.Marshal(&dave.M{Op: dave.Op_DAT, V: d.V, T: Ttb(d.Ti), S: d.S, W: d.W})
			if err != nil {
				return err
			}
			lenb := make([]byte, 2)
			binary.LittleEndian.PutUint16(lenb, uint16(len(b)))
			buf.Write(lenb)
			buf.Write(b)
		}
	}
	return buf.Flush()
}

func readBackup(fname string) (uint32, []map[uint64]Dat, error) {
	dats := make([]map[uint64]Dat, MAXWORK-MINWORK)
	for i := range dats {
		dats[i] = make(map[uint64]Dat)
	}
	workHash := blake3.New(32, nil)
	f, err := os.Open(fname)
	if err != nil {
		return 0, nil, fmt.Errorf("err opening file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, nil, fmt.Errorf("err reading file info: %w", err)
	}
	size := info.Size()
	var pos int64
	var ndat uint32
	lb := make([]byte, 2)
	for pos < size {
		n, err := f.Read(lb)
		pos += int64(n)
		if err != nil {
			return ndat, dats, fmt.Errorf("err reading length prefix: %w", err)
		}
		datbuf := make([]byte, binary.LittleEndian.Uint16(lb))
		n, err = f.Read(datbuf)
		pos += int64(n)
		if err != nil {
			return ndat, dats, fmt.Errorf("err reading length-prefixed msg: %w", err)
		}
		m := &dave.M{}
		err = proto.Unmarshal(datbuf, m)
		if err != nil {
			return ndat, dats, fmt.Errorf("err unmarshalling proto msg: %w", err)
		}
		if check(workHash, m.V, m.T, m.S, m.W) < MINWORK {
			continue
		}
		shardKey, datKey := keys(m.W)
		dats[shardKey][datKey] = Dat{V: m.V, Ti: Btt(m.T), S: m.S, W: m.W}
		ndat++
	}
	return ndat, dats, nil
}

func sendForApp(m *dave.M, dats []map[uint64]Dat, peerList []*peer, trustSum float64, pktout chan<- *pkt, apprecv chan<- *Dat, cfg *Cfg) {
	if m == nil {
		return
	}
	switch m.Op {
	case dave.Op_DAT:
		lg(cfg, LOGLVL_DEBUG, "/send_for_app sending dat %x, trustSum %f", m.W, trustSum)
		put(dats, &Dat{m.V, m.S, m.W, Btt(m.T)})
		for _, p := range rndpeers(peerList, trustSum, FANOUT, 0, 0) {
			addr := addrfrom(p.pd)
			pktout <- &pkt{m, addr}
			lg(cfg, LOGLVL_DEBUG, "/send_for_app dat sent to %s", addr)
		}
	case dave.Op_GET:
		shardKey, datKey := keys(m.W)
		var found bool
		dat, ok := dats[shardKey][datKey]
		if ok {
			found = true
			apprecv <- &dat
			lg(cfg, LOGLVL_DEBUG, "/send_for_app get found locally %x", dat.W)
		}
		if !found {
			for _, p := range rndpeers(peerList, trustSum, FANOUT, 0, 0) {
				addr := addrfrom(p.pd)
				pktout <- &pkt{&dave.M{Op: dave.Op_GET, W: m.W}, addr}
				lg(cfg, LOGLVL_DEBUG, "/send_for_app get sent to %s", addr)
			}
		}
	default:
		lg(cfg, LOGLVL_ERROR, "/send_for_app unsupported operation: %s", m.Op)
	}
}

func put(dats []map[uint64]Dat, d *Dat) (bool, error) {
	shardKey, datKey := keys(d.W)
	_, ok := dats[shardKey][datKey]
	if !ok {
		dats[shardKey][datKey] = *d
		return true, nil
	}
	return false, nil
}

func lstn(c *net.UDPConn, cfg *Cfg) <-chan *pkt {
	pkts := make(chan *pkt, 100)
	go func() {
		bpool := sync.Pool{New: func() any { return make([]byte, BUF) }}
		ch := blake3.New(32, nil)
		for {
			p := rdpkt(c, ch, &bpool, cfg)
			if p != nil {
				pkts <- p
			}
		}
	}()
	return pkts
}

func rdpkt(c *net.UDPConn, ch *blake3.Hasher, bpool *sync.Pool, cfg *Cfg) *pkt {
	buf := bpool.Get().([]byte)
	defer bpool.Put(buf) //lint:ignore SA6002 slice is already a reference
	n, raddr, err := c.ReadFromUDPAddrPort(buf)
	if err != nil {
		lg(cfg, LOGLVL_ERROR, "/rdpkt failed to read from socket")
		return nil
	}
	m := &dave.M{}
	err = proto.Unmarshal(buf[:n], m)
	if err != nil {
		lg(cfg, LOGLVL_ERROR, "/rdpkt failed to unmarshal")
		return nil
	}
	if m.Op == dave.Op_DAT {
		work := check(ch, m.V, m.T, m.S, m.W)
		if work < MINWORK {
			lg(cfg, LOGLVL_ERROR, "/rdpkt failed work check: %d from %s", work, raddr)
			return nil
		}
	} else if m.Op == dave.Op_PEER && len(m.Pds) > GETNPEER {
		lg(cfg, LOGLVL_ERROR, "/rdpkt packet exceeds pd limit")
		return nil
	}
	return &pkt{m, raddr}
}

func rndpeer(list []*peer, trustSum float64) *peer {
	if len(list) == 0 {
		return nil
	}
	if mrand.Intn(PROBE) == 0 {
		return list[mrand.Intn(len(list))]
	}
	r := mrand.Float64() * trustSum
	for _, p := range list {
		r -= p.trust
		if r <= 0 {
			return p
		}
	}
	return nil
}

func rndpeers(list []*peer, trustSum float64, limit int, excludeFp uint64, knownFor time.Duration) []*peer {
	if len(list) == 0 {
		return nil
	}
	peers := make([]*peer, 0, limit)
	r := mrand.Float64() * trustSum
	for _, p := range list {
		r -= p.trust
		if p.fp == excludeFp || time.Since(p.added) < knownFor {
			continue
		}
		if trustSum == 0 || r <= 0 || mrand.Intn(PROBE) == 0 {
			peers = append(peers, p)
			if len(peers) == limit {
				return peers
			}
		}
	}
	return peers
}

func rnddat(shard map[uint64]Dat) *Dat {
	if len(shard) == 0 {
		return nil
	}
	datPos := mrand.Intn(len(shard))
	var cDatPos int
	for _, dat := range shard {
		if cDatPos != datPos {
			cDatPos++
			continue
		}
		return &dat
	}
	return nil
}

func addrfrom(pd *dave.Pd) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom16([16]byte(pd.Ip)), uint16(pd.Port))
}

func pdfrom(addrport netip.AddrPort) *dave.Pd {
	ip := addrport.Addr().As16()
	return &dave.Pd{Ip: ip[:], Port: uint32(addrport.Port())}
}

func pdfp(pd *dave.Pd) uint64 {
	port := make([]byte, 2)
	binary.LittleEndian.PutUint16(port, uint16(pd.Port))
	h := xxhash.New()
	h.Write(port)
	h.Write(pd.Ip)
	return h.Sum64()
}

func keys(work []byte) (uint8, uint64) {
	return min(MAXWORK, nzerobit(work)) - MINWORK, xxhash.Sum64(work)
}

func check(h *blake3.Hasher, val, tim, salt, work []byte) int {
	if len(tim) != 8 || Btt(tim).After(time.Now().Add(time.Second)) { // 1s grace period incase clocks are not accurate
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

func lg(cfg *Cfg, lvl LogLvl, msg string, args ...any) {
	if lvl <= cfg.LogLvl {
		select {
		case cfg.Log <- fmt.Sprintf(msg, args...):
		default:
		}
	}
}
