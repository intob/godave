package godave

import (
	"bufio"
	"bytes"
	"container/heap"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash"
	"github.com/intob/godave/dave"
	"google.golang.org/protobuf/proto"
	"lukechampine.com/blake3"
)

const (
	BUF      = 1424   // Max packet size, 1500 MTU is typical, avoids packet fragmentation.
	FANOUT   = 3      // Number of peers randomly selected when selecting more than one.
	PROBE    = 8      // Inverse of probability that an untrusted peer is randomly selected.
	GETNPEER = 2      // Limit of peer descriptors in a PEER message.
	MINWORK  = 4      // Minimum amount of acceptable work in number of leading zero bits.
	APP      = 17     // Epochs between each round of sending a message for the app.
	DROP     = 131071 // Epochs until silent peers are dropped from the peer table, and new peers are shared.
	PING     = 28657  // Epochs until silent peers are pinged with a GETPEER message.
	PRUNE    = 65537  // Epochs between pruning dats & peers.
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
	recv       <-chan *Dat
	send       chan<- *dave.M
	epoch      time.Duration
	kill, done chan struct{}
	npeer      *atomic.Int32
}

type Cfg struct {
	ListenAddr   *net.UDPAddr     // Listening address:port
	Edges        []netip.AddrPort // Bootstrap peers
	Epoch        time.Duration    // Base cycle, lower runs faster, using more bandwidth
	ShardCap     uint32           // Shard capacity
	MaxSeedTries uint32           // Max number of attempts at selecting a dat not in the filter.
	Log          chan<- string    // Log messages
	BackupFname  string           // Dat and peer table backup filename
	Test         bool             // Allow multiple ports per IP
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
	lg(cfg.Log, "/init cfg: %+v", *cfg)
	bootstrap := make(map[uint64]*peer)
	for _, e := range cfg.Edges {
		bootstrap[pdfp(pdfrom(e))] = &peer{pd: pdfrom(e), fp: pdfp(pdfrom(e)), added: time.Now(), edge: true}
	}
	c, err := net.ListenUDP("udp", cfg.ListenAddr)
	if err != nil {
		return nil, err
	}
	var dats map[uint8]map[uint64]Dat
	if cfg.BackupFname != "" {
		var ndat uint
		ndat, dats, err = readBackup(cfg.BackupFname)
		if err != nil {
			lg(cfg.Log, "/backup failed to read backup file: %s", err)
			if ndat > 0 {
				err = writeFreshBackup(dats, cfg.BackupFname)
				if err != nil {
					panic(err)
				}
				lg(cfg.Log, "/backup file was corrupted, created fresh backup with %d dats", ndat)
			}
		}
		lg(cfg.Log, "/backup read %d dats from file", ndat)
	}
	if dats == nil {
		dats = make(map[uint8]map[uint64]Dat)
		lg(cfg.Log, "/init created empty map")
	}
	backup := make(chan *dave.M, 100)
	kill := make(chan struct{}, 1)
	done := make(chan struct{}, 1) // buffer allows writeBackup routine to end when backup disabled
	go writeBackup(backup, kill, done, cfg)
	pktout := make(chan *pkt, 1)
	go writePackets(c, pktout, cfg.Log)
	send := make(chan *dave.M)
	recv := make(chan *Dat, 100)
	npeer := &atomic.Int32{}
	go d(dats, bootstrap, npeer, lstn(c, cfg), pktout, backup, send, recv, cfg)
	return &Dave{recv: recv, send: send, epoch: cfg.Epoch, kill: kill, done: done, npeer: npeer}, nil
}

func (d *Dave) Kill() <-chan struct{} {
	d.kill <- struct{}{}
	return d.done
}
func (d *Dave) Get(work []byte, npeer int32, timeout time.Duration) <-chan *Dat {
	c := make(chan *Dat, 1)
	go func() {
		for d.npeer.Load() < npeer {
			time.Sleep(APP * d.epoch)
		}
		d.send <- &dave.M{Op: dave.Op_GET, W: work}
		defer close(c)
		tick := time.NewTicker(APP * d.epoch)
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
			time.Sleep(APP * d.epoch)
		}
		m := &dave.M{Op: dave.Op_DAT, V: dat.V, S: dat.S, W: dat.W, T: Ttb(dat.Ti)}
		d.send <- m
		defer close(done)
		var r int32
		tick := time.NewTicker(APP * d.epoch)
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

func d(dats map[uint8]map[uint64]Dat, peers map[uint64]*peer, npeer *atomic.Int32, pktin <-chan *pkt, pktout chan<- *pkt, backup chan<- *dave.M, appsend <-chan *dave.M, apprecv chan<- *Dat, cfg *Cfg) {
	npeer.Store(int32(len(peers)))
	var nepoch, ndat uint32
	var peerList []*peer // sorted by trust score, updated during prune
	var trustSum float64
	trustSum, peerList, peers = prunePeers(peers)
	epochTick := time.NewTicker(cfg.Epoch)
	for {
		select {
		case pk := <-pktin: // HANDLE INCOMING PACKET
			pkpd := pdfrom(pk.ip)
			pkfp := pdfp(pkpd)
			p, ok := peers[pkfp]
			if ok {
				p.seen = time.Now()
			} else {
				p = &peer{pd: pkpd, fp: pkfp, added: time.Now(), seen: time.Now()}
				peers[pkfp] = p
				npeer.Add(1)
				lg(cfg.Log, "/peer/add %s %x", pk.ip, pkfp)
			}
			switch pk.msg.Op {
			case dave.Op_PEER: // STORE PEERS
				if time.Since(p.peermsg) >= PING*cfg.Epoch {
					p.peermsg = time.Now()
					for _, mpd := range pk.msg.Pds {
						mpdfp := pdfp(mpd)
						_, ok := peers[mpdfp]
						if !ok {
							peers[mpdfp] = &peer{pd: mpd, fp: mpdfp, added: time.Now(), seen: time.Now()}
							npeer.Add(1)
							lg(cfg.Log, "/peer/add_from_gossip %s from %s", addrfrom(mpd), pk.ip)
						}
					}
				} else {
					lg(cfg.Log, "/peer/unexpected dropped msg from %s %s", pk.ip, time.Since(p.peermsg))
				}
			case dave.Op_GETPEER: // GIVE PEERS
				pktout <- &pkt{&dave.M{Op: dave.Op_PEER, Pds: rndpds(peerList, trustSum, GETNPEER, pkfp, cfg.Epoch)}, pk.ip}
				lg(cfg.Log, "/peer/reply_to_getpeer %s", pk.ip)
			case dave.Op_DAT: // STORE DAT
				dat := &Dat{pk.msg.V, pk.msg.S, pk.msg.W, Btt(pk.msg.T)}
				select {
				case apprecv <- dat:
				default:
				}
				novel, shardid, err := put(dats, dat)
				if err != nil {
					lg(cfg.Log, "/store error: %s", err)
				}
				//filter.Insert(seedKey(pk.msg.W, p, cfg.Test))
				if novel {
					p.trust += Mass(pk.msg.W, Btt(pk.msg.T))
					if cfg.BackupFname != "" {
						backup <- pk.msg
					}
					lg(cfg.Log, "/store %x %d %s %f", pk.msg.W, shardid, pk.ip, p.trust)
				}
			case dave.Op_GET: // REPLY WITH DAT
				shardKey, datKey := keys(pk.msg.W)
				shard, ok := dats[shardKey]
				if ok { // GOT SHARD
					dat, ok := shard[datKey]
					if ok { // GOT DAT
						pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: dat.V, T: Ttb(dat.Ti), S: dat.S, W: dat.W}, pk.ip}
						lg(cfg.Log, "/dat/reply_to_get %s %x", pk.ip, dat.W)
					}
				}
			}
		case <-epochTick.C:
			nepoch++
			if ndat > 0 { // SEED DAT
				rp := rndpeer(peerList, trustSum)
				if rp != nil {
					d := rnddat(dats)
					if d != nil {
						pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: d.V, T: Ttb(d.Ti), S: d.S, W: d.W}, addrfrom(rp.pd)}
					}
				}
			}
			if nepoch%PING == 0 { // PING & DROP PEERS
				var dropped bool
				for pid, p := range peers {
					if !p.edge && time.Since(p.seen) > DROP*cfg.Epoch {
						delete(peers, pid)
						npeer.Add(-1)
						dropped = true
						lg(cfg.Log, "/peer/ping/delete %s", addrfrom(p.pd))
					} else { // SEND PING
						addr := addrfrom(p.pd)
						pktout <- &pkt{&dave.M{Op: dave.Op_GETPEER}, addr}
						lg(cfg.Log, "/peer/ping/getpeer_msg sent to %s", addr)
					}
				}
				if dropped {
					trustSum, peerList, peers = prunePeers(peers)
				}
			} else if nepoch%PRUNE == 0 {
				ndat, dats = pruneDats(dats, int(cfg.ShardCap))
				trustSum, peerList, peers = prunePeers(peers)
				lg(cfg.Log, "/mem got %d peers, %d dats across %d shards", len(peerList), ndat, len(dats))
			}
		case m := <-appsend: // SEND PACKET FOR APP
			if cfg.BackupFname != "" && m.Op == dave.Op_DAT {
				backup <- m
			}
			sendForApp(m, dats, peerList, trustSum, pktout, apprecv, cfg)
		}
	}
}

func writePackets(c *net.UDPConn, pkts <-chan *pkt, log chan<- string) {
	for pkt := range pkts {
		bin, err := proto.Marshal(pkt.msg)
		if err != nil {
			panic(err)
		}
		_, err = c.WriteToUDPAddrPort(bin, pkt.ip)
		if err != nil {
			lg(log, "/dispatch error: %s", err)
		}
	}
}

func pruneDats(dats map[uint8]map[uint64]Dat, cap int) (uint32, map[uint8]map[uint64]Dat) {
	newdats := make(map[uint8]map[uint64]Dat)
	var ndat uint32
	for shardid, shard := range dats {
		dh := &datheap{}
		heap.Init(dh)
		for datid, dat := range shard {
			if dh.Len() < cap {
				heap.Push(dh, &pair{datid, dat})
			} else if Mass(dat.W, dat.Ti) > Mass(dh.Peek().dat.W, dh.Peek().dat.Ti) {
				heap.Pop(dh)
				heap.Push(dh, &pair{datid, dat})
			}
		}
		newdats[shardid] = make(map[uint64]Dat, dh.Len())
		for dh.Len() > 0 {
			pair := heap.Pop(dh).(*pair)
			newdats[shardid][pair.id] = pair.dat
			ndat++
		}
	}
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
		lg(cfg.Log, "/backup disabled")
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
			lg(cfg.Log, "/backup buffer flushed, file closed, errors if any: %v %v", flushErr, closeErr)
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

func writeFreshBackup(dats map[uint8]map[uint64]Dat, fname string) error {
	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := bufio.NewWriter(f)
	for _, shard := range dats {
		for _, d := range shard {
			b, _ := proto.Marshal(&dave.M{Op: dave.Op_DAT, V: d.V, T: Ttb(d.Ti), S: d.S, W: d.W})
			lenb := make([]byte, 2)
			binary.LittleEndian.PutUint16(lenb, uint16(len(b)))
			buf.Write(lenb)
			buf.Write(b)
		}
	}
	return buf.Flush()
}

func readBackup(fname string) (uint, map[uint8]map[uint64]Dat, error) {
	dats := make(map[uint8]map[uint64]Dat)
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
	var ndat uint
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
			return ndat, dats, errors.New("work check failed")
		}
		shardKey, datKey := keys(m.W)
		if _, ok := dats[shardKey]; !ok {
			dats[shardKey] = make(map[uint64]Dat)
		}
		dats[shardKey][datKey] = Dat{V: m.V, Ti: Btt(m.T), S: m.S, W: m.W}
		ndat++
	}
	return ndat, dats, nil
}

func sendForApp(m *dave.M, dats map[uint8]map[uint64]Dat, peerList []*peer, trustSum float64, pktout chan<- *pkt, apprecv chan<- *Dat, cfg *Cfg) {
	if m != nil {
		switch m.Op {
		case dave.Op_DAT:
			put(dats, &Dat{m.V, m.S, m.W, Btt(m.T)})
			for _, pd := range rndpds(peerList, trustSum, FANOUT, 0, 0) {
				addr := addrfrom(pd)
				pktout <- &pkt{m, addr}
				lg(cfg.Log, "/send_for_app dat sent to %s", addr)
			}
		case dave.Op_GET:
			shardKey, datKey := keys(m.W)
			var found bool
			shard, ok := dats[shardKey]
			if ok {
				dat, ok := shard[datKey]
				if ok {
					found = true
					apprecv <- &dat
					lg(cfg.Log, "/send_for_app get found locally %x", dat.W)
				}
			}
			if !found {
				for _, pd := range rndpds(peerList, trustSum, FANOUT, 0, 0) {
					addr := addrfrom(pd)
					pktout <- &pkt{&dave.M{Op: dave.Op_GET, W: m.W}, addr}
					lg(cfg.Log, "/send_for_app get sent to %s", addr)
				}
			}
		default:
			panic(fmt.Sprintf("unsupported operation: send %s", m.Op))
		}
	}
}

func put(dats map[uint8]map[uint64]Dat, d *Dat) (bool, uint8, error) {
	shardKey, datKey := keys(d.W)
	shard, ok := dats[shardKey]
	if !ok {
		dats[shardKey] = make(map[uint64]Dat)
		dats[shardKey][datKey] = *d
		return true, shardKey, nil
	} else {
		_, ok := shard[datKey]
		if !ok {
			shard[datKey] = *d
			return true, shardKey, nil
		}
		return false, shardKey, nil
	}
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
		panic(err)
	}
	m := &dave.M{}
	err = proto.Unmarshal(buf[:n], m)
	if err != nil {
		lg(cfg.Log, "/rdpkt failed to unmarshal")
		return nil
	}
	if m.Op == dave.Op_PEER && len(m.Pds) > GETNPEER {
		lg(cfg.Log, "/rdpkt packet exceeds pd limit")
		return nil

	} else if m.Op == dave.Op_DAT {
		work := check(ch, m.V, m.T, m.S, m.W)
		if work < MINWORK {
			lg(cfg.Log, "/rdpkt failed work check: %d from %s", work, raddr)
			return nil
		}
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

func rndpds(list []*peer, trustSum float64, limit int, excludeFp uint64, epoch time.Duration) []*dave.Pd {
	if len(list) == 0 {
		return nil
	}
	r := mrand.Float64() * trustSum
	pds := make([]*dave.Pd, 0, limit)
	for _, p := range list {
		r -= p.trust
		if p.fp == excludeFp || time.Since(p.added) < DROP*epoch {
			continue
		}
		if r <= 0 || mrand.Intn(PROBE) == 0 {
			pds = append(pds, p.pd)
			if len(pds) == limit {
				return pds
			}
		}
	}
	return pds
}

func rnddat(dats map[uint8]map[uint64]Dat) *Dat {
	shardPos := mrand.Intn(len(dats))
	var cShardPos int
	for _, shard := range dats {
		if cShardPos != shardPos {
			cShardPos++
			continue
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
	return nzerobit(work), xxhash.Sum64(work)
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

func lg(ch chan<- string, msg string, args ...any) {
	select {
	case ch <- fmt.Sprintf(msg, args...):
	default:
	}
}
