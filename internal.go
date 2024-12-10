// This file contains the methods and tyoes of the main package that are not exposed.
package godave

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"time"

	"github.com/intob/godave/auth"
	"github.com/intob/godave/dat"
	"github.com/intob/godave/logger"
	"github.com/intob/godave/network"
	"github.com/intob/godave/peer"
	"github.com/intob/godave/store"
	"github.com/intob/godave/sub"
	"github.com/intob/godave/tcp"
	"github.com/intob/godave/types"
	"github.com/intob/godave/udp"
	"lukechampine.com/blake3"
)

func (d *Dave) handleMessages() {
	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			hasher := blake3.New(32, nil)
			var myAddrPort netip.AddrPort
			udpPackets := d.udp.In()
			tcpMessages := d.tcp.Messages()
			for {
				select {
				case packet := <-udpPackets:
					d.handleUDPPacket(hasher, myAddrPort, packet)
				case m := <-tcpMessages:
					if m.Op != types.OP_PUT || m.Entry == nil {
						continue
					}
					hasher.Reset()
					err := d.handlePut(hasher, m.Entry)
					if err != nil {
						d.log(logger.ERROR, "failed to handle TCP PUT: %s", err)
					}
				}
			}
		}()
	}
}

func (d *Dave) handleUDPPacket(hasher *blake3.Hasher, myAddrPort netip.AddrPort, packet *udp.RawPacket) {
	msg := &types.Msg{}
	err := msg.Unmarshal(packet.Data)
	if err != nil {
		d.log(logger.ERROR, "failed to unmarshal packet: %s", err)
	}
	switch msg.Op {
	case types.OP_PONG:
		hasher.Reset()
		err := d.handlePong(hasher, msg, packet.AddrPort, myAddrPort)
		if err != nil {
			d.log(logger.ERROR, "failed to handle PONG: %s", err)
		}
	case types.OP_PING:
		hasher.Reset()
		d.handlePing(hasher, msg, packet.AddrPort)
	case types.OP_PUT:
		hasher.Reset()
		err = d.handlePut(hasher, msg.Entry)
		if err != nil {
			d.log(logger.ERROR, "failed to handle PUT: %s", err)
		}
	case types.OP_GET:
		err = d.handleGet(msg.Get, packet.AddrPort)
		if err != nil {
			d.log(logger.DEBUG, "failed to handle GET: %s", err)
		}
	case types.OP_GET_ACK:
		d.subSvc.Publish(sub.RECV_GET_ACK, &udp.Packet{Msg: msg, AddrPort: packet.AddrPort})
	case types.OP_GETMYADDRPORT:
		d.udp.Out() <- &udp.Packet{Msg: &types.Msg{Op: types.OP_GETMYADDRPORT_ACK,
			AddrPorts: []netip.AddrPort{packet.AddrPort}}, AddrPort: packet.AddrPort}
	case types.OP_GETMYADDRPORT_ACK:
		// Only accept from edge peers
		if d.peers.IsEdge(packet.AddrPort) && len(msg.AddrPorts) == 1 {
			myAddrPort = msg.AddrPorts[0]
			d.udp.MyAddrPortChan() <- myAddrPort
		} else {
			d.log(logger.ERROR, "rejected MYADDRPORT_ACK from %s", packet.AddrPort)
		}
	}
}

func (d *Dave) managePeerDiscovery() {
	pingTick := time.NewTicker(network.PING)
	getMyAddrPortTick := time.NewTicker(network.GETMYADDRPORT_EVERY)
	if len(d.peers.Edges()) == 0 {
		getMyAddrPortTick.Stop()
	} else { // also send now
		err := d.sendGetMyAddrPort()
		if err != nil {
			d.log(logger.ERROR, "failed to send GETMYADDRPORT: no edge is online")
		}
	}
	for {
		select {
		case <-pingTick.C:
			for _, peer := range d.peers.ListAll() {
				challenge, err := d.peers.CreateAuthChallenge(peer.AddrPort)
				if err != nil {
					d.log(logger.ERROR, "failed to create challenge: %s", err)
					continue
				}
				d.udp.Out() <- &udp.Packet{Msg: &types.Msg{Op: types.OP_PING,
					AuthChallenge: challenge, Status: &types.Status{
						UsedSpace: d.UsedSpace(), Capacity: d.Capacity()},
				}, AddrPort: peer.AddrPort}
			}
		case <-getMyAddrPortTick.C:
			err := d.sendGetMyAddrPort()
			if err != nil {
				d.log(logger.ERROR, "failed to send GETMYADDRPORT: no edge is online")
			}
		}
	}
}

func (d *Dave) manageReplicas() {
	refresh := time.NewTicker(network.REPLICATE_EVERY)
	for range refresh.C {
		d.replaceReplicas()
	}
}

func (d *Dave) replaceReplicas() {
	active := append(d.peers.ListActive(nil), peer.PeerCopy{ID: d.myID})
	refreshActive := time.NewTicker(network.DEACTIVATE_AFTER)
	entries := d.store.ListAll()
	writers := make(map[uint64]*tcp.ConnWriter)
	mbuf := make([]byte, network.MAX_MSG_LEN+2)
	for {
		select {
		case <-refreshActive.C:
			active = append(d.peers.ListActive(nil), peer.PeerCopy{ID: d.myID})
		case e, ok := <-entries:
			if !ok {
				d.log(logger.ERROR, "finished replacing replicas")
				return
			}
			sorted := peer.SortPeersByDistance(peer.IDFromPublicKey(e.Dat.PubKey), active)
			oldReplicas := e.Replicas
			var leader uint64
			var replicaChanged bool
			for j, r := range e.Replicas {
				if r > leader {
					leader = r
				}
				if j < len(sorted) && e.Replicas[j] != sorted[j].Peer.ID {
					e.Replicas[j] = sorted[j].Peer.ID
					replicaChanged = true
				}
			}
			if !replicaChanged {
				continue
			}
			d.store.Write(&e)
			if leader != d.myID {
				continue
			}
			msg := &types.Msg{Op: types.OP_PUT, Entry: &e}
			n, err := msg.Marshal(mbuf[2:])
			binary.LittleEndian.PutUint16(mbuf, uint16(n))
			if err != nil {
				d.log(logger.ERROR, "failed to marshal message: %s", err)
				continue
			}
			for i, r := range e.Replicas {
				var found bool
				for _, r2 := range oldReplicas {
					if r == r2 {
						found = true
						break
					}
				}
				if found {
					continue
				}
				target := sorted[i].Peer
				writer, ok := writers[target.ID]
				if !ok {
					var err error
					writers[target.ID], err = tcp.Dial(target.AddrPort)
					if err != nil {
						d.log(logger.ERROR, "failed to dial TCP: %s", err)
					}
					writer = writers[target.ID]
				}
				_, err := writer.Writer.Write(mbuf[:n+2])
				if err != nil {
					d.log(logger.ERROR, "failed to write to TCP buffer: %s", err)
				}
			}
		}
	}
}

func (d *Dave) handlePing(hasher *blake3.Hasher, msg *types.Msg, raddr netip.AddrPort) {
	d.peers.AddPeer(raddr, false)
	randPeers := d.peers.RandPeers(network.NPEER_LIMIT, &raddr)
	addrPorts := make([]netip.AddrPort, len(randPeers))
	for i, p := range randPeers {
		addrPorts[i] = p.AddrPort
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	hasher.Write(msg.AuthChallenge[:])
	hasher.Write(salt)
	sig := ed25519.Sign(d.privateKey, hasher.Sum(nil))
	d.udp.Out() <- &udp.Packet{Msg: &types.Msg{Op: types.OP_PONG,
		AuthSolution: &auth.AuthSolution{Challenge: msg.AuthChallenge,
			Salt:      auth.Salt(salt),
			PublicKey: d.publicKey,
			Signature: auth.Signature(sig)},
		AddrPorts: addrPorts}, AddrPort: raddr}
	err := d.peers.SetPeerUsedSpaceAndCapacity(raddr, msg.Status.UsedSpace, msg.Status.Capacity)
	if err != nil {
		d.log(logger.ERROR, "failed to set peer used space & capacity: %s", err)
	}
}

func (d *Dave) handlePong(h *blake3.Hasher, msg *types.Msg, raddr, myAddr netip.AddrPort) error {
	challenge, storedPubKey, err := d.peers.CurrentAuthChallengeAndPubKey(raddr)
	if err != nil {
		return err
	}
	if msg.AuthSolution.Challenge != challenge {
		return errors.New("challenge is incorrect")
	}
	if len(msg.AuthSolution.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("pub key is invalid: %s", err)
	}
	if storedPubKey != nil && !storedPubKey.Equal(msg.AuthSolution.PublicKey) {
		return fmt.Errorf("msg pub key does not match stored pub key")
	}
	h.Write(challenge[:])
	h.Write(msg.AuthSolution.Salt[:])
	hash := h.Sum(nil)
	if !ed25519.Verify(msg.AuthSolution.PublicKey, hash, msg.AuthSolution.Signature[:]) {
		return fmt.Errorf("signature is invalid")
	}
	if storedPubKey == nil {
		d.peers.SetPublicKeyAndID(raddr, msg.AuthSolution.PublicKey)
	}
	if len(msg.AddrPorts) > network.NPEER_LIMIT {
		return fmt.Errorf("message contains more than %d addrports", network.NPEER_LIMIT)
	}
	for _, addrPort := range msg.AddrPorts {
		if addrPort != myAddr {
			d.peers.AddPeer(addrPort, false)
		} else {
			return fmt.Errorf("my own addrport was given")
		}
	}
	d.peers.AuthChallengeSolved(raddr)
	return nil
}

func (d *Dave) handlePut(hasher *blake3.Hasher, entry *store.Entry) error {
	err := entry.Dat.Verify(hasher)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	err = d.store.Write(entry)
	if err != nil {
		return fmt.Errorf("failed to store: %w", err)
	}
	d.log(logger.DEBUG, "stored %s, replicas: %+v", entry.Dat.Key, entry.Replicas)
	return nil
}

func (d *Dave) handleGet(get *types.Get, raddr netip.AddrPort) error {
	entry, err := d.store.Read(get.PublicKey, get.DatKey)
	if err != nil {
		d.udp.Out() <- &udp.Packet{Msg: &types.Msg{Op: types.OP_GET_ACK,
			Entry: &store.Entry{Dat: dat.Dat{PubKey: get.PublicKey, Key: get.DatKey}}},
			AddrPort: raddr}
		return fmt.Errorf("failed to read from store: %s", err)
	}
	d.udp.Out() <- &udp.Packet{Msg: &types.Msg{Op: types.OP_GET_ACK, Entry: &entry}, AddrPort: raddr}
	return nil
}

// TODO: Improve this by not relying on edge nodes. Rather, we can simply collect responses
// from a range of randomly-selected peers. This would relieve edge nodes from the burden of
// responding to these GETMYADDRPORT packets. It also continues to work correctly in the
// event that edge nodes temporarily go offline.
// This distributed IP-lookup is just as important for allowing nodes with dynamic IPs to
// advertise a service to the network, as it is for preventing loopbacks.
func (d *Dave) sendGetMyAddrPort() error {
	for _, p := range d.peers.Edges() {
		if time.Since(p.AuthChallengeSolved) < network.DEACTIVATE_AFTER {
			d.udp.Out() <- &udp.Packet{Msg: &types.Msg{Op: types.OP_GETMYADDRPORT},
				AddrPort: p.AddrPort}
			d.log(logger.DEBUG, "sent GETMYADDRPORT to %s", p.AddrPort)
			return nil
		}
	}
	return errors.New("failed to send MYADDRPORT")
}

func (d *Dave) log(level logger.LogLevel, msg string, args ...any) {
	if d.logger != nil {
		d.logger.Log(level, msg, args...)
	}
}
