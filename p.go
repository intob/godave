package godave

import (
	"bufio"
	"bytes"
	"container/heap"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
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
	EPOCH          = time.Millisecond
	BUF            = 1424             // Max packet size, 1500 MTU is typical, avoids packet fragmentation.
	FANOUT         = 5                // Number of peers randomly selected when selecting more than one.
	ROUNDS         = 5                // Number of rounds to repeat sending new dats.
	PROBE          = 8                // Inverse of probability that an untrusted peer is randomly selected.
	NPEER_LIMIT    = 2                // Maximum number of peer descriptors in a PEER message.
	MINWORK        = 16               // Minimum amount of acceptable work in number of leading zero bits.
	MAXTRUST       = 25               // Maximum trust score, ensuring fair trust distribution from feedback.
	APP            = 25               // Epochs between each round of sending a message for the app.
	PING           = 8 * time.Second  // Time until peers are pinged with a GETPEER message.
	DROP           = 16 * time.Second // Time until silent peers are dropped from the peer table.
	SHARE_DELAY    = 20 * time.Second // Time until new peers are shared. Must be greater than DROP.
	PRUNE          = time.Minute      // Period between pruning dats & peers.
	RINGSIZE       = 1000             // Number of dats to store in ring buffer.
	LOGLEVEL_ERROR = LogLevel(0)      // Base log level, for errors & status.
	LOGLEVEL_DEBUG = LogLevel(1)      // Debugging log level.
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

type LogLevel int

type Dave struct {
	recv       <-chan *Dat
	send       chan<- *dave.M
	kill, done chan struct{}
	npeer      *atomic.Int32
	appRecv    <-chan *Dat
}

type Cfg struct {
	UdpListenAddr *net.UDPAddr     // Listening address:port
	Edges         []netip.AddrPort // Bootstrap peers
	ShardCap      int              // Shard capacity
	BackupFname   string           // Dat table backup filename
	LogLevel      LogLevel         // Log level
	Log           chan<- string    // Log message output
}

type Dat struct {
	Key, Val, Salt, Work, Sig []byte
	Time                      time.Time
	PubKey                    ed25519.PublicKey
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
	return Mass(h[i].dat.Work, h[i].dat.Time) < Mass(h[j].dat.Work, h[j].dat.Time)
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
	lg(cfg, LOGLEVEL_ERROR, "/init cfg: %+v", *cfg)
	bootstrap := make(map[uint64]*peer)
	for _, e := range cfg.Edges {
		bootstrap[pdfp(pdfrom(e))] = &peer{pd: pdfrom(e), fp: pdfp(pdfrom(e)), added: time.Now(), edge: true}
	}
	udpc, err := net.ListenUDP("udp", cfg.UdpListenAddr)
	if err != nil {
		return nil, err
	}
	dats := make([]map[uint64]Dat, 256)
	for i := range dats {
		dats[i] = make(map[uint64]Dat)
	}
	var ndat uint32
	if cfg.BackupFname != "" {
		ndat, dats, err = readBackup(cfg.BackupFname)
		if err != nil {
			lg(cfg, LOGLEVEL_ERROR, "/init failed to read backup file: %s", err)
		}
		lg(cfg, LOGLEVEL_ERROR, "/init read %d dats from file", ndat)
		ndat, dats = pruneDats(dats, cfg.ShardCap)
		err = writeFreshBackup(dats, cfg.BackupFname)
		if err != nil {
			return nil, fmt.Errorf("failed to write fresh backup: %s", err)
		}
	}
	if dats == nil {
		dats = make([]map[uint64]Dat, 256)
		lg(cfg, LOGLEVEL_ERROR, "/init created empty map")
	}
	lg(cfg, LOGLEVEL_ERROR, "/init pruned %d dats across %d shards, init took %s", ndat, len(dats), time.Since(tstart))
	backup := make(chan *dave.M, 100)
	kill := make(chan struct{}, 1)
	done := make(chan struct{}, 1) // buffer allows writeBackup routine to end when backup disabled
	go writeBackup(backup, kill, done, cfg)
	pktout := make(chan *pkt, 100)
	go writePackets(udpc, pktout, cfg)
	send := make(chan *dave.M)
	recv := make(chan *Dat, 100)
	appRecv := make(chan *Dat, 100)
	npeer := &atomic.Int32{}
	go d(dats, bootstrap, ndat, npeer, lstn(udpc, cfg), pktout, backup, send, recv, appRecv, cfg)
	return &Dave{recv: recv, send: send, kill: kill, done: done, npeer: npeer}, nil
}

func (d *Dave) Kill() <-chan struct{} {
	d.kill <- struct{}{}
	return d.done
}

func (d *Dave) Recv() <-chan *Dat {
	return d.appRecv
}

func (d *Dave) PeerCount() int32 {
	return d.npeer.Load()
}

func (d *Dave) Get(pubKey ed25519.PublicKey, datKey []byte, timeout time.Duration) <-chan *Dat {
	c := make(chan *Dat, 1)
	go func() {
		d.send <- &dave.M{Op: dave.Op_GET, DatKey: datKey, PubKey: pubKey}
		defer close(c)
		tick := time.NewTicker(APP * EPOCH)
		timeout := time.NewTimer(timeout)
		for {
			select {
			case <-timeout.C:
				return
			case dat := <-d.recv:
				if bytes.Equal(dat.Key, datKey) {
					c <- dat
					return
				}
			case <-tick.C:
				d.send <- &dave.M{Op: dave.Op_GET, DatKey: datKey, PubKey: pubKey}
			}
		}
	}()
	return c
}

func (d *Dave) Set(dat *Dat) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		m := &dave.M{Op: dave.Op_PUT, DatKey: dat.Key, Val: dat.Val, Salt: dat.Salt, Work: dat.Work, Time: Ttb(dat.Time), PubKey: dat.PubKey, Sig: dat.Sig}
		d.send <- m
		defer close(done)
		var r int32
		tick := time.NewTicker(APP * EPOCH)
		for range tick.C {
			d.send <- m
			r++
			if r == ROUNDS {
				done <- struct{}{}
				return
			}
		}
	}()
	return done
}

// DoWork computes a proof-of-work, either on a single core or on all cores,
// depending on the difficulty level. For lower difficulty levels (< 12),
// the single-core implementation performs best.
func DoWork(key, val, tim []byte, d uint8) (work []byte, salt []byte) {
	if d >= 12 {
		return doWorkAllCores(key, val, tim, d)
	} else {
		return doWorkSingleCore(key, val, tim, d)
	}
}

// doWork computes a proof-of-work on a single core.
// For low difficulty settings (< 12), this outperforms the multi-core implementation.
func doWorkSingleCore(key, val, tim []byte, d uint8) (work, salt []byte) {
	salt = make([]byte, 8)
	h := blake3.New(32, nil)
	h.Write(key)
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

// doWorkAllCores computes a proof-of-work using all cores.
// For higher difficulty settings (>= 12), this outperforms the single-core implementation.
func doWorkAllCores(key, val, tim []byte, d uint8) (work, salt []byte) {
	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	type Result struct{ work, salt []byte }
	resultChan := make(chan Result)
	quit := make(chan struct{})
	h := blake3.New(32, nil)
	h.Write(key)
	h.Write(val)
	h.Write(tim)
	load := h.Sum(nil)
	for i := 0; i < numCPU; i++ {
		go func(offset uint64) {
			salt := make([]byte, 8)
			h := blake3.New(32, nil)
			counter := offset
			for {
				select {
				case <-quit:
					return
				default:
					*(*uint64)(unsafe.Pointer(&salt[0])) = counter
					h.Reset()
					h.Write(salt)
					h.Write(load)
					work := h.Sum(nil)

					if nzerobit(work) >= d {
						select {
						case resultChan <- Result{work: work, salt: salt}:
						case <-quit:
						}
						return
					}
					counter += uint64(numCPU)
				}
			}
		}(uint64(i))
	}
	result := <-resultChan
	close(quit)
	return result.work, result.salt
}

func Check(key, val, tim, salt, work []byte) (uint8, error) {
	return check(blake3.New(32, nil), key, val, tim, salt, work)
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

func d(dats []map[uint64]Dat, peers map[uint64]*peer, ndat uint32, npeer *atomic.Int32, pktin <-chan *pkt, pktout chan<- *pkt, backup chan<- *dave.M, send <-chan *dave.M, recv, appRecv chan<- *Dat, cfg *Cfg) {
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
				lg(cfg, LOGLEVEL_ERROR, "/peer/add %s %x", pk.ip, pkfp)
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
							lg(cfg, LOGLEVEL_ERROR, "/peer/add_from_gossip %s from %s", addrfrom(mpd), pk.ip)
						}
					}
					trustSum, peerList, peers = prunePeers(peers)
				} else {
					lg(cfg, LOGLEVEL_ERROR, "/peer/unexpected dropped msg from %s", pk.ip)
				}
			case dave.Op_GETPEER: // GIVE PEERS
				rps := rndpeers(peerList, trustSum, NPEER_LIMIT, pkfp, SHARE_DELAY)
				pds := make([]*dave.Pd, len(rps))
				for i, p := range rps {
					pds[i] = p.pd
				}
				pktout <- &pkt{&dave.M{Op: dave.Op_PEER, Pds: pds}, pk.ip}
				lg(cfg, LOGLEVEL_DEBUG, "/peer/reply_to_getpeer %s", pk.ip)
			case dave.Op_PUT: // STORE DAT
				dat := &Dat{pk.msg.DatKey, pk.msg.Val, pk.msg.Salt, pk.msg.Work, pk.msg.Sig, Btt(pk.msg.Time), pk.msg.PubKey}
				novel, err := put(dats, dat)
				if err != nil {
					lg(cfg, LOGLEVEL_DEBUG, "/store error: %s", err)
					continue
				}
				select {
				case recv <- dat:
				default:
				}
				select {
				case appRecv <- dat:
				default:
				}
				if novel {
					ndat++
				}
				trust := peers[pkfp].trust
				if trust < MAXTRUST {
					trust += Mass(pk.msg.Work, Btt(pk.msg.Time))
					if trust > MAXTRUST {
						trust = MAXTRUST
					}
				}
				if cfg.BackupFname != "" {
					backup <- pk.msg
				}
				ring.Write(dat)
				lg(cfg, LOGLEVEL_DEBUG, "/store %x %s %f", pk.msg.Work, pk.ip, trust)

			case dave.Op_GET: // REPLY WITH DAT
				shard, mapKey := keys(pk.msg.PubKey, pk.msg.DatKey)
				dat, ok := dats[shard][mapKey]
				if ok { // GOT DAT
					pktout <- &pkt{&dave.M{Op: dave.Op_PUT, DatKey: dat.Key, Val: dat.Val, Time: Ttb(dat.Time), Salt: dat.Salt, Work: dat.Work, PubKey: dat.PubKey, Sig: dat.Sig}, pk.ip}
					lg(cfg, LOGLEVEL_DEBUG, "/dat/reply_to_get %s %x", pk.ip, dat.Work)
				}
			}
		case <-epochTick.C: // SEED
			rp := rndpeer(peerList, trustSum)
			if ndat > 0 && rp != nil {
				raddr := addrfrom(rp.pd)
				dat := rnddat(dats[cshard])
				if dat != nil {
					pktout <- &pkt{&dave.M{Op: dave.Op_PUT, DatKey: dat.Key, Val: dat.Val, Time: Ttb(dat.Time), Salt: dat.Salt, Work: dat.Work, PubKey: dat.PubKey, Sig: dat.Sig}, raddr}
				}
				dat, ok := ring.Read()
				if ok {
					pktout <- &pkt{&dave.M{Op: dave.Op_PUT, DatKey: dat.Key, Val: dat.Val, Time: Ttb(dat.Time), Salt: dat.Salt, Work: dat.Work, PubKey: dat.PubKey, Sig: dat.Sig}, raddr}
				} else {
					lg(cfg, LOGLEVEL_DEBUG, "/push nothing in ring buffer")
				}
				for {
					cshard++
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
					lg(cfg, LOGLEVEL_ERROR, "/peer/ping/drop %s, not seen for %s", addrfrom(p.pd), time.Since(p.seen))
				} else if time.Since(p.peermsg) > PING { // SEND PING
					addr := addrfrom(p.pd)
					pktout <- &pkt{&dave.M{Op: dave.Op_GETPEER}, addr}
					lg(cfg, LOGLEVEL_DEBUG, "/peer/ping/getpeer_msg sent to %s", addr)
				}
			}
			if dropped {
				trustSum, peerList, peers = prunePeers(peers)
			}
		case <-pruneTick.C: // PRUNE DATS & PEERS
			tstart := time.Now()
			ndat, dats = pruneDats(dats, cfg.ShardCap)
			trustSum, peerList, peers = prunePeers(peers)
			lg(cfg, LOGLEVEL_ERROR, "/prune got %d peers, %d dats across %d shards, took %s", len(peerList), ndat, len(dats), time.Since(tstart))
		case m := <-send: // SEND PACKET FOR APP
			sendForApp(m, dats, peerList, trustSum, pktout, recv, cfg)
			if cfg.BackupFname != "" && m.Op == dave.Op_PUT {
				backup <- m
			}
		case <-statTick.C:
			lg(cfg, LOGLEVEL_ERROR, "/stat got %d peers, %d dats", npeer.Load(), ndat)
		}
	}
}

func writePackets(c *net.UDPConn, pkts <-chan *pkt, cfg *Cfg) {
	for pkt := range pkts {
		bin, err := proto.Marshal(pkt.msg)
		if err != nil {
			lg(cfg, LOGLEVEL_ERROR, "/dispatch error: %s", err)
			continue
		}
		_, err = c.WriteToUDPAddrPort(bin, pkt.ip)
		if err != nil {
			lg(cfg, LOGLEVEL_ERROR, "/dispatch error: %s", err)
		}
	}
}

func pruneDats(dats []map[uint64]Dat, cap int) (uint32, []map[uint64]Dat) {
	newdats := make([]map[uint64]Dat, len(dats))
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
					} else if Mass(dat.Work, dat.Time) > Mass(dh.Peek().dat.Work, dh.Peek().dat.Time) {
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
		lg(cfg, LOGLEVEL_ERROR, "/backup disabled")
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
			lg(cfg, LOGLEVEL_ERROR, "/backup buffer flushed, file closed, errors if any: %v %v", flushErr, closeErr)
			return
		case m := <-backup:
			b, err := proto.Marshal(m)
			if err != nil {
				lg(cfg, LOGLEVEL_ERROR, "/backup failed to marshal: %s", err)
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
			b, err := proto.Marshal(&dave.M{Op: dave.Op_PUT, DatKey: d.Key, Val: d.Val, Time: Ttb(d.Time), Salt: d.Salt, Work: d.Work, PubKey: d.PubKey, Sig: d.Sig})
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
	dats := make([]map[uint64]Dat, 256)
	for i := range dats {
		dats[i] = make(map[uint64]Dat)
	}
	hasher := blake3.New(32, nil)
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
		work, err := check(hasher, m.DatKey, m.Val, m.Time, m.Salt, m.Work)
		if err != nil {
			continue
		}
		if work < MINWORK {
			continue
		}
		shard, mapKey := keys(m.PubKey, m.DatKey)
		dats[shard][mapKey] = Dat{m.DatKey, m.Val, m.Salt, m.Work, m.Sig, Btt(m.Time), m.PubKey}
		ndat++
	}
	return ndat, dats, nil
}

func sendForApp(m *dave.M, dats []map[uint64]Dat, peerList []*peer, trustSum float64, pktout chan<- *pkt, recv chan<- *Dat, cfg *Cfg) {
	if m == nil {
		return
	}
	switch m.Op {
	case dave.Op_PUT:
		put(dats, &Dat{m.DatKey, m.Val, m.Salt, m.Work, m.Sig, Btt(m.Time), m.PubKey})
		for _, p := range rndpeers(peerList, trustSum, FANOUT, 0, 0) {
			addr := addrfrom(p.pd)
			pktout <- &pkt{m, addr}
			lg(cfg, LOGLEVEL_DEBUG, "/send_for_app dat sent to %s", addr)
		}
	case dave.Op_GET:
		shard, mapKey := keys(m.PubKey, m.DatKey)
		var found bool
		dat, ok := dats[shard][mapKey]
		if ok {
			found = true
			recv <- &dat
			lg(cfg, LOGLEVEL_DEBUG, "/send_for_app get found locally %s", dat.Key)
		}
		if !found {
			for _, p := range rndpeers(peerList, trustSum, FANOUT, 0, 0) {
				addr := addrfrom(p.pd)
				pktout <- &pkt{m, addr}
				lg(cfg, LOGLEVEL_DEBUG, "/send_for_app get sent to %s", addr)
			}
		}
	default:
		lg(cfg, LOGLEVEL_ERROR, "/send_for_app unsupported operation: %s", m.Op)
	}
}

func put(dats []map[uint64]Dat, d *Dat) (bool, error) {
	shard, mapKey := keys(d.PubKey, d.Key)
	current, ok := dats[shard][mapKey]
	if !ok {
		dats[shard][mapKey] = *d
		return true, nil
	}
	if !current.PubKey.Equal(d.PubKey) {
		return false, errors.New("pub keys don't match, rejected")
	}
	if current.Time.After(d.Time) {
		return false, errors.New("current is newer")
	}
	if current.Time == d.Time && bytes.Equal(current.Val, d.Val) {
		return false, errors.New("already stored")
	}
	dats[shard][mapKey] = *d
	return false, nil
}

func lstn(c *net.UDPConn, cfg *Cfg) <-chan *pkt {
	pkts := make(chan *pkt, 100)
	go func() {
		bpool := sync.Pool{New: func() any { return make([]byte, BUF) }}
		h := blake3.New(32, nil)
		for {
			p, err := rdpkt(c, h, &bpool)
			if err != nil {
				lg(cfg, LOGLEVEL_ERROR, "/rdpkt %s", err)
				continue
			}
			pkts <- p
		}
	}()
	return pkts
}

func rdpkt(c *net.UDPConn, h *blake3.Hasher, bpool *sync.Pool) (*pkt, error) {
	buf := bpool.Get().([]byte)
	defer bpool.Put(buf) //lint:ignore SA6002 slice is already a reference
	n, raddr, err := c.ReadFromUDPAddrPort(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read from socket: %s", err)
	}
	m := &dave.M{}
	err = proto.Unmarshal(buf[:n], m)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %s", err)
	}
	if m.Op == dave.Op_PUT {
		work, err := check(h, m.DatKey, m.Val, m.Time, m.Salt, m.Work)
		if err != nil {
			return nil, fmt.Errorf("failed work check: %s", err)
		}
		if work < MINWORK {
			return nil, fmt.Errorf("work is insufficient: %d from %s", work, raddr)
		}
		pubKey, err := unmarshalEd25519(m.PubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal pub key: %s", err)
		}
		if !ed25519.Verify(pubKey, m.Work, m.Sig) {
			return nil, fmt.Errorf("invalid signature")
		}
	} else if m.Op == dave.Op_PEER && len(m.Pds) > NPEER_LIMIT {
		return nil, errors.New("packet exceeds pd limit")
	}
	return &pkt{m, raddr}, nil
}

func unmarshalEd25519(publicKeyBytes []byte) (ed25519.PublicKey, error) {
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519: public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(publicKeyBytes), nil
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

func keys(pubKey, datKey []byte) (uint8, uint64) {
	h := xxhash.New()
	h.Write(pubKey)
	h.Write(datKey)
	sum64 := h.Sum64()
	return uint8(sum64 >> 56), sum64
}

func check(h *blake3.Hasher, key, val, tim, salt, work []byte) (uint8, error) {
	if len(key) > 32 {
		return 0, errors.New("key must be of size 32B or less")
	}
	if len(tim) != 8 || Btt(tim).After(time.Now()) {
		return 0, errors.New("time is invalid")
	}
	h.Reset()
	h.Write(key)
	h.Write(val)
	h.Write(tim)
	load := h.Sum(nil)
	h.Reset()
	h.Write(salt)
	h.Write(load)
	if !bytes.Equal(h.Sum(nil), work) {
		return 0, errors.New("hash is invalid")
	}
	return nzerobit(work), nil
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

func lg(cfg *Cfg, lvl LogLevel, msg string, args ...any) {
	if lvl <= cfg.LogLevel {
		select {
		case cfg.Log <- fmt.Sprintf(msg, args...):
		default:
		}
	}
}
