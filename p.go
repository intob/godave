package godave

import (
	"bufio"
	"bytes"
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
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/intob/godave/dave"
	ckoo "github.com/panmari/cuckoofilter"
	"github.com/twmb/murmur3"
	"google.golang.org/protobuf/proto"
	"lukechampine.com/blake3"
)

const (
	BUF      = 1424   // Max packet size, 1500 MTU is typical, avoids packet fragmentation.
	FANOUT   = 2      // Number of peers randomly selected when selecting more than one.
	PROBE    = 8      // Inverse of probability that an untrusted peer is randomly selected.
	GETNPEER = 2      // Limit of peer descriptors in a PEER message.
	MINWORK  = 8      // Minimum amount of acceptable work in number of leading zero bits.
	TRUSTEXP = .375   // Exponent to apply to trust score to flatten distribution of peer selection.
	DELAY    = 28657  // Epochs until new peers may be randomly selected.
	PING     = 14197  // Epochs until silent peers are pinged with a GETPEER message.
	DROP     = 131071 // Epochs until silent peers are dropped from the peer table.
	SEED     = 3      // Epochs between sending one random dat to one random peer, excluding edges.
	PUSH     = 7      // Epcohs between sending one random mew dat to one random peer, excluding edges.
	PULL     = 9377   // Epochs between pulling a random dat from a random peer. Increases anonymity.
	GET      = 257    // Epochs between repeating GET messages.
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
	Recv  <-chan *dave.M
	Send  chan<- *dave.M
	epoch time.Duration
}

type Cfg struct {
	LstnAddr    *net.UDPAddr     // Listening address:port
	Edges       []netip.AddrPort // Bootstrap peers
	Epoch       time.Duration    // Base cycle, lower runs faster, using more bandwidth
	Prune       int              // Interval between refreshing dat & peer maps
	ShardCap    int              // Cuckoo filter capacity
	FilterCap   uint             // Dat map capacity
	Log         chan<- []byte    // Log messages
	Test        bool             // Allow multiple ports per IP
	BackupFname string           // Dat and peer table backup filename
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

type ringbuffer struct {
	head, cap int
	buf       []Dat
}

func (r *ringbuffer) write(d *Dat) {
	r.buf[r.head] = *d
	r.head = (r.head + 1) % r.cap
}

func (r *ringbuffer) rand() *Dat {
	rdat := r.buf[mrand.Intn(r.cap)]
	if rdat.W != nil {
		return nil
	}
	return &rdat
}

func NewDave(cfg *Cfg) (*Dave, error) {
	if cfg.Epoch == 0 {
		return nil, errors.New("Cfg.Epoch must not be zero. Try 20us")
	}
	if cfg.ShardCap < 1 {
		return nil, errors.New("Cfg.ShardCap must be at least 1. 5K should be ok")
	}
	if cfg.FilterCap < 1 {
		return nil, errors.New("Cfg.FilterCap must not be at least 1. 1K, 10K or 100K is probably good for you ;)")
	}
	if cfg.Prune < 1 {
		return nil, errors.New("Cfg.Prune must be at least 1. 50K or 100K is should be fine")
	}
	lg(cfg.Log, "/init cfg: %+v\n", *cfg)
	c, err := net.ListenUDP("udp", cfg.LstnAddr)
	if err != nil {
		return nil, err
	}
	bootstrap := make(map[uint64]*peer)
	h := murmur3.New64()
	for _, e := range cfg.Edges {
		bootstrap[pdfp(h, pdfrom(e))] = &peer{pd: pdfrom(e), fp: pdfp(h, pdfrom(e)), added: time.Now(), seen: time.Now(), edge: true}
	}
	pktout := make(chan *pkt, 1)
	go writePackets(c, pktout, cfg.Log)
	var dats map[uint8]map[uint64]Dat
	if cfg.BackupFname != "" {
		dats, err = readBackup(h, cfg)
		if err != nil {
			lg(cfg.Log, "/init/read_backup failed to read backup file: %s\n", err)
		}
		lg(cfg.Log, "/init/read_backup read %d dats from file\n", len(dats))
	}
	if dats == nil {
		dats = make(map[uint8]map[uint64]Dat)
		lg(cfg.Log, "/init/new created empty map\n")
	}
	send := make(chan *dave.M)
	recv := make(chan *dave.M, 1)
	go d(pktout, dats, bootstrap, lstn(c, cfg), send, recv, cfg)
	return &Dave{Recv: recv, Send: send, epoch: cfg.Epoch}, nil
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
		tick := time.NewTicker(PUSH * d.epoch)
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

func d(pktout chan<- *pkt, dats map[uint8]map[uint64]Dat, prs map[uint64]*peer, pktin <-chan *pkt, appsend <-chan *dave.M, apprecv chan<- *dave.M, cfg *Cfg) {
	var nepoch, npeer, nedge int
	for _, p := range prs {
		if p.edge {
			nedge++
		}
	}
	etick := time.NewTicker(cfg.Epoch)
	h := murmur3.New64()
	ring := &ringbuffer{cap: cfg.ShardCap, buf: make([]Dat, cfg.ShardCap)}
	lg(cfg.Log, "/d/init/ring cap: %d\n", ring.cap)
	for {
		select {
		case <-etick.C:
			nepoch++
			if nepoch%cfg.Prune == 0 { // MEMORY MANAGEMENT
				memstat := &runtime.MemStats{}
				runtime.ReadMemStats(memstat)
				var ndat int
				ndat, dats, prs = mem(dats, prs, cfg)
				npeer = len(prs)
				lg(cfg.Log, "/d/mem got %d peers, %d dats across %d shards, %.2fGB mem alloc\n", len(prs), ndat, len(dats), float64(memstat.Alloc)/(1<<30))
			}
			if npeer > 0 && nepoch%SEED == 0 { // SEND RANDOM DAT TO RANDOM PEER, EXCLUDING EDGES
				for _, rp := range rndpeers(prs, 0, 1, func(p *peer, l *peer) bool { return !p.edge && available(p, cfg.Epoch) && dotrust(p, l) }) {
					rd := rnddat(dats)
					if rd != nil {
						pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: rd.V, T: Ttb(rd.Ti), S: rd.S, W: rd.W}, addrfrom(rp.pd)}
						lg(cfg.Log, "/d/seed %x %x\n", rp.fp, rd.W)
					}
				}
			}
			if npeer > 0 && nepoch%PUSH == 0 { // SEND RANDOM RECENT DAT TO RANDOM PEER, EXCLUDING EDGES
				rd := ring.rand()
				if rd != nil {
					for _, rp := range rndpeers(prs, 0, 1, func(p *peer, l *peer) bool { return !p.edge && available(p, cfg.Epoch) && dotrust(p, l) }) {
						pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: rd.V, T: Ttb(rd.Ti), S: rd.S, W: rd.W}, addrfrom(rp.pd)}
						lg(cfg.Log, "/d/push %x %x %s\n", rp.fp, rd.W, time.Since(rd.Ti))
					}
				}
			}
			if npeer > 0 && nepoch%PULL == 0 { // PULL RANDOM DAT FROM RANDOM PEER, EXCLUDING EDGES
				rd := rnddat(dats)
				if rd != nil {
					for _, rp := range rndpeers(prs, 0, 1, func(p *peer, l *peer) bool { return !p.edge && available(p, cfg.Epoch) }) {
						pktout <- &pkt{&dave.M{Op: dave.Op_GET, W: rd.W}, addrfrom(rp.pd)}
						lg(cfg.Log, "/d/pull %x %x\n", rp.fp, rd.W)
					}
				}
			}
			if nepoch%PING == 0 { // PING AND DROP
				for pid, p := range prs {
					if !p.edge && time.Since(p.seen) > DROP*cfg.Epoch { // DROP UNRESPONSIVE PEER
						delete(prs, pid)
						lg(cfg.Log, "/d/ping/deleted %s\n", addrfrom(p.pd))
					} else { //if time.Since(p.seen) > cfg.Epoch*PING { // SEND PING
						addr := addrfrom(p.pd)
						pktout <- &pkt{&dave.M{Op: dave.Op_GETPEER}, addr}
						lg(cfg.Log, "/d/ping/getpeer_msg sent to %s\n", addr)
					}
				}
			}
		case m := <-appsend: // SEND PACKET FOR APP
			sendForApp(m, ring, dats, h, prs, pktout, apprecv, cfg)
		case pk := <-pktin: // HANDLE INCOMING PACKET
			pkpd := pdfrom(pk.ip)
			pkpfp := pdfp(h, pkpd)
			p, ok := prs[pkpfp]
			if ok {
				p.seen = time.Now()
			} else {
				p = &peer{pd: pkpd, fp: pkpfp, added: time.Now(), seen: time.Now()}
				prs[pkpfp] = p
				lg(cfg.Log, "/d/h/add_peer %s %x\n", pk.ip.String(), pkpfp)
			}
			m := pk.msg
			select {
			case apprecv <- m:
			default:
			}
			switch m.Op {
			case dave.Op_PEER: // STORE PEERS
				if time.Since(p.peermsg) >= PING*cfg.Epoch {
					p.peermsg = time.Now()
					for _, mpd := range m.Pds {
						mpdfp := pdfp(h, mpd)
						_, ok := prs[mpdfp]
						if !ok {
							prs[mpdfp] = &peer{pd: mpd, fp: mpdfp, added: time.Now(), seen: time.Now()}
							lg(cfg.Log, "/d/h/peer_msg/add_from_gossip %s from %s\n", addrfrom(mpd), pk.ip.String())
						}
					}
				} else {
					lg(cfg.Log, "/d/h/peer_msg/unexpected dropped from %s %s\n", pk.ip.String(), time.Since(p.peermsg))
				}
			case dave.Op_GETPEER: // GIVE PEERS
				rpeers := rndpeers(prs, p.fp, GETNPEER, func(p *peer, l *peer) bool { return available(p, cfg.Epoch) })
				pds := make([]*dave.Pd, len(rpeers))
				for i, rp := range rpeers {
					pds[i] = rp.pd
				}
				pktout <- &pkt{&dave.M{Op: dave.Op_PEER, Pds: pds}, pk.ip}
				lg(cfg.Log, "/d/h/getpeer_msg/reply %s %x\n", pk.ip.String(), p.fp)
			case dave.Op_DAT: // STORE
				dat := &Dat{m.V, m.S, m.W, Btt(m.T)}
				novel, shardid, err := store(ring, dats, dat, h)
				if err != nil {
					lg(cfg.Log, "/d/h/dat_msg/store_error %s\n", err)
				}
				label := "known"
				if novel {
					label = "novel"
					p.trust += Mass(m.W, Btt(m.T))
				}
				lg(cfg.Log, "/d/h/dat_msg/%s %x %d %x %f\n", label, m.W, shardid, p.fp, p.trust)
			case dave.Op_GET: // REPLY WITH DAT
				shardi, dati, err := workid(h, m.W)
				if err == nil {
					shard, ok := dats[shardi]
					if ok { // GOT SHARD
						dat, ok := shard[dati]
						if ok { // GOT DAT
							pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: dat.V, T: Ttb(dat.Ti), S: dat.S, W: dat.W}, pk.ip}
							lg(cfg.Log, "/d/h/get_msg/reply %s %x\n", pk.ip.String(), dat.W)
						}
					}
				}
			}
		}
	}
}

func writePackets(c *net.UDPConn, pkts <-chan *pkt, log chan<- []byte) {
	for pkt := range pkts {
		bin, err := proto.Marshal(pkt.msg)
		if err != nil {
			panic(err)
		}
		_, err = c.WriteToUDPAddrPort(bin, pkt.ip)
		if err != nil {
			lg(log, "/dispatch/error %s\n", err)
		}
	}
}

func mem(dats map[uint8]map[uint64]Dat, prs map[uint64]*peer, cfg *Cfg) (int, map[uint8]map[uint64]Dat, map[uint64]*peer) {
	newdats := make(map[uint8]map[uint64]Dat)
	var ndat int
	for shardid, shard := range dats {
		type hdat struct {
			datid uint64
			dat   Dat
		}
		heaviest := make([]hdat, 0)
		for datid, dat := range shard {
			if len(heaviest) < cfg.ShardCap {
				heaviest = append(heaviest, hdat{datid, dat})
				if len(heaviest) == cfg.ShardCap {
					sort.Slice(heaviest, func(i, j int) bool {
						return Mass(heaviest[i].dat.W, heaviest[i].dat.Ti) < Mass(heaviest[j].dat.W, heaviest[j].dat.Ti)
					})
				}
			} else if Mass(dat.W, dat.Ti) > Mass(heaviest[0].dat.W, heaviest[0].dat.Ti) {
				heaviest[0] = hdat{datid, dat}
				sort.Slice(heaviest, func(i, j int) bool {
					return Mass(heaviest[i].dat.W, heaviest[i].dat.Ti) < Mass(heaviest[j].dat.W, heaviest[j].dat.Ti)
				})
			}
		}
		newdats[shardid] = make(map[uint64]Dat, len(heaviest))
		for _, d := range heaviest {
			newdats[shardid][d.datid] = d.dat
			ndat++
		}
	}
	newpeers := make(map[uint64]*peer)
	for k, p := range prs {
		newpeers[k] = p
	}
	writeBackup(newdats, cfg.BackupFname)
	return ndat, newdats, newpeers
}

func writeBackup(dats map[uint8]map[uint64]Dat, backupFname string) {
	if backupFname == "" {
		return
	}
	backupFile, err := os.Create(backupFname)
	if err != nil {
		panic(fmt.Sprintf("err creating backup file: %s", err))
	}
	defer backupFile.Close()
	buf := bufio.NewWriter(backupFile)
	for _, shard := range dats {
		for _, dat := range shard {
			bin, _ := proto.Marshal(&dave.M{Op: dave.Op_DAT, V: dat.V, T: Ttb(dat.Ti), S: dat.S, W: dat.W})
			lb := make([]byte, 2)
			binary.LittleEndian.PutUint16(lb, uint16(len(bin)))
			buf.Write(lb)
			buf.Write(bin)
		}
	}
	buf.Flush()
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
			lg(cfg.Log, "/read_backup/read err reading length-prefixed msg: %s\n", err)
			continue
		}
		m := &dave.M{}
		err = proto.Unmarshal(datbuf, m)
		if err != nil {
			lg(cfg.Log, "/read_backup/unmarshal err unmarshalling proto msg: %s\n", err)
			continue
		}
		if check(workHash, m.V, m.T, m.S, m.W) < MINWORK {
			lg(cfg.Log, "/read_backup/check_work failed\n")
			continue
		}
		shardi, dati, err := workid(h, m.W)
		if err != nil {
			lg(cfg.Log, "/read_backup/calc_workid err calculating dati or shardi: %s\n", err)
			continue
		}
		if _, ok := dats[shardi]; !ok {
			dats[shardi] = make(map[uint64]Dat)
		}
		dats[shardi][dati] = Dat{V: m.V, Ti: Btt(m.T), S: m.S, W: m.W}
	}
	return dats, nil
}

func sendForApp(m *dave.M, ring *ringbuffer, dats map[uint8]map[uint64]Dat, h hash.Hash64, prs map[uint64]*peer, pktout chan<- *pkt, apprecv chan<- *dave.M, cfg *Cfg) {
	if m != nil {
		switch m.Op {
		case dave.Op_DAT:
			store(ring, dats, &Dat{m.V, m.S, m.W, Btt(m.T)}, h)
			go func(rps []*peer) {
				for _, rp := range rps {
					pktout <- &pkt{m, addrfrom(rp.pd)}
					lg(cfg.Log, "/d/send/dat %x %x\n", rp.fp, m.W)
				}
			}(rndpeers(prs, 0, FANOUT, func(p *peer, l *peer) bool { return available(p, cfg.Epoch) }))
		case dave.Op_GET:
			shardi, dati, err := workid(h, m.W)
			if err == nil {
				var found bool
				shard, ok := dats[shardi]
				if ok {
					dat, ok := shard[dati]
					if ok {
						found = true
						apprecv <- &dave.M{Op: dave.Op_DAT, V: dat.V, T: Ttb(dat.Ti), S: dat.S, W: dat.W}
						lg(cfg.Log, "/d/send/get found locally %x\n", dat.W)
					}
				}
				if !found {
					go func(rps []*peer) {
						for _, rp := range rps {
							pktout <- &pkt{&dave.M{Op: dave.Op_GET, W: m.W}, addrfrom(rp.pd)}
							lg(cfg.Log, "/d/send/get sent %x %x\n", rp.fp, m.W)
						}
					}(rndpeers(prs, 0, FANOUT, func(p *peer, l *peer) bool { return available(p, cfg.Epoch) }))
				}
			}
		default:
			panic(fmt.Sprintf("unsupported operation: send %s", m.Op))
		}
	}
}

func rnddat(dats map[uint8]map[uint64]Dat) *Dat {
	if len(dats) == 0 {
		return nil
	}
	rshardpos := uint8(mrand.Uint32() % (uint32(len(dats)) + 1))
	var cshardpos uint8
	for _, shard := range dats {
		if cshardpos == rshardpos {
			rdati := uint64(len(shard))
			rdatpos := mrand.Uint64() % (rdati + 1)
			var cdatpos uint64
			for _, dat := range shard {
				if cdatpos == rdatpos {
					return &dat
				}
				cdatpos++
			}
		}
		cshardpos++
	}
	return nil
}

func store(ring *ringbuffer, dats map[uint8]map[uint64]Dat, d *Dat, h hash.Hash64) (bool, uint8, error) {
	ring.write(d)
	shardid, datid, err := workid(h, d.W)
	if err != nil {
		return false, shardid, err
	}
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
		fh := murmur3.New64()
		ch := blake3.New(32, nil)
		f := ckoo.NewFilter(cfg.FilterCap)
		rtick := time.NewTicker(cfg.Epoch)
		defer c.Close()
		for {
			select {
			case <-rtick.C:
				f.Reset()
				lg(cfg.Log, "/lstn/filter_reset\n")
			default:
				p := rdpkt(c, fh, f, ch, &bpool, &mpool, cfg)
				if p != nil {
					pkts <- p
				}
			}
		}
	}()
	return pkts
}

func rdpkt(c *net.UDPConn, fh hash.Hash, f *ckoo.Filter, ch *blake3.Hasher, bpool, mpool *sync.Pool, cfg *Cfg) *pkt {
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
		lg(cfg.Log, "/lstn/rdpkt/drop unmarshal err\n")
		return nil
	}
	fh.Reset()
	op := make([]byte, 2)
	binary.LittleEndian.PutUint16(op, uint16(m.Op.Number()))
	fh.Write(op)
	addr := raddr.Addr().As16()
	fh.Write(addr[:])
	if cfg.Test {
		port := make([]byte, 2)
		binary.LittleEndian.PutUint16(port, raddr.Port())
		fh.Write(port)
	}
	sum := fh.Sum(nil)
	if f.Lookup(sum) {
		lg(cfg.Log, "/lstn/rdpkt/drop/filter %s %x\n", m.Op, m.W)
		return nil
	}
	f.Insert(sum)
	if m.Op == dave.Op_PEER && len(m.Pds) > GETNPEER {
		lg(cfg.Log, "/lstn/rdpkt/drop/npeer packet exceeds pd limit\n")
		return nil
	} else if m.Op == dave.Op_DAT && check(ch, m.V, m.T, m.S, m.W) < MINWORK {
		lg(cfg.Log, "/lstn/rdpkt/drop/workcheck failed\n")
		return nil
	}
	lg(cfg.Log, "/lstn/rdpkt/accepted %s %x\n", m.Op, m.W)
	cpy := &dave.M{Op: m.Op, Pds: make([]*dave.Pd, len(m.Pds)), V: m.V, T: m.T, S: m.S, W: m.W}
	for i, pd := range m.Pds {
		cpy.Pds[i] = &dave.Pd{Ip: pd.Ip, Port: pd.Port}
	}
	return &pkt{cpy, raddr}
}

func rndpeers(prs map[uint64]*peer, excludePeerFp uint64, lim int, match func(p, legend *peer) bool) []*peer {
	candidates := make([]*peer, 0, len(prs))
	leg := legend(prs)
	for k, p := range prs {
		if k != excludePeerFp && match(p, leg) {
			candidates = append(candidates, p)
		}
	}
	lencand := len(candidates)
	if lencand <= lim {
		return candidates
	}
	ans := make([]*peer, lim)
	for i := 0; i < lim; i++ {
		r := i + mrand.Intn(lencand-i)
		ans[i] = candidates[r]
	}
	return ans
}

func legend(prs map[uint64]*peer) (legend *peer) {
	for _, p := range prs {
		if legend == nil || p.trust > legend.trust {
			legend = p
		}
	}
	return legend
}

func available(k *peer, epoch time.Duration) bool {
	return k.edge || (time.Since(k.seen) < epoch*PING && time.Since(k.added) > epoch*DELAY)
}

func dotrust(k *peer, legend *peer) bool {
	return mrand.Intn(PROBE) == 1 || mrand.Float64() < math.Pow(k.trust/legend.trust, TRUSTEXP)
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

func workid(h hash.Hash64, work []byte) (uint8, uint64, error) {
	if len(work) != 32 {
		return 0, 0, errors.New("value is not of length 32 bytes")
	}
	h.Reset()
	h.Write(work)
	return nzerobit(work), h.Sum64(), nil
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
