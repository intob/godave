package tcp

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/intob/godave/logger"
	"github.com/intob/godave/network"
	"github.com/intob/godave/types"
)

const BUFFER_SIZE = 640 * 1024 // 320KB

type TCPService struct {
	listener   *net.TCPListener
	messagesIn chan *types.Msg
	logger     logger.Logger
}

type ConnWriter struct {
	Conn   net.Conn
	Writer *bufio.Writer
}

func Dial(udpAddrPort netip.AddrPort) (*ConnWriter, error) {
	tcpAddrPort := net.TCPAddrFromAddrPort(udpAddrPort)
	tcpAddrPort.Port = tcpAddrPort.Port + 1
	conn, err := net.Dial("tcp", tcpAddrPort.String())
	if err != nil {
		return nil, err
	}
	return &ConnWriter{
		Writer: bufio.NewWriterSize(conn, BUFFER_SIZE),
		Conn:   conn,
	}, nil
}

// NewTCPService creates a listner that accepts TCP connections. The UDP port is
// incremented by one to get the TCP port.
func NewTCPService(udpAddr *net.UDPAddr, log logger.Logger) (*TCPService, error) {
	laddr := net.TCPAddrFromAddrPort(udpAddr.AddrPort())
	laddr.Port = laddr.Port + 1
	l, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen TCP: %w", err)
	}
	svc := &TCPService{
		listener:   l,
		logger:     log,
		messagesIn: make(chan *types.Msg),
	}
	svc.log(logger.ERROR, "listening TCP on %s", l.Addr().String())
	go svc.acceptConnections()
	return svc, nil
}

func (t *TCPService) Messages() <-chan *types.Msg { return t.messagesIn }

func (t *TCPService) acceptConnections() {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			t.log(logger.ERROR, "error accepting TCP conn: %s", err)
			continue
		}
		go t.handleConnection(conn)
	}
}

func (t *TCPService) handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, BUFFER_SIZE)
	lenBuf := make([]byte, 2)
	msgBuf := make([]byte, network.MAX_MSG_LEN)
	for {
		_, err := io.ReadFull(reader, lenBuf)
		if err != nil {
			t.log(logger.ERROR, "failed to read length prefix from TCP conn: %s", err)
			return
		}
		msgLen := int(binary.LittleEndian.Uint16(lenBuf))
		if msgLen > network.MAX_MSG_LEN {
			t.log(logger.ERROR, "length prefix greater than max: %d, max: %d", msgLen, network.MAX_MSG_LEN)
			return
		}
		_, err = io.ReadFull(reader, msgBuf[:msgLen])
		if err != nil {
			t.log(logger.ERROR, "failed to read message: %s", err)
			return
		}
		m := &types.Msg{}
		err = m.Unmarshal(msgBuf[:msgLen])
		if err != nil {
			t.log(logger.ERROR, "failed to unmarshal message: %s", err)
			return
		}
		t.messagesIn <- m
	}
}

func (t *TCPService) log(level logger.LogLevel, msg string, args ...any) {
	if t.logger != nil {
		t.logger.Log(level, msg, args...)
	}
}
