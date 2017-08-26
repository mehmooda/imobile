package itunes

import "github.com/pkg/errors"
import "net"
import "crypto/tls"
import "crypto/x509"
import "io"
import "github.com/DHowett/go-plist"
import "encoding/binary"

func tls_connect(c net.Conn, cert tls.Certificate) (net.Conn, error) {
	tc := tls.Client(c, &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) != 1 {
				return io.EOF
			}
			//				if bytes.Compare(rawCerts[0], devcert) != 0 {
			//					log.Println("UNMATCHED DEVICE CERTIFICATE")
			//				}
			return nil
		},
	})
	err := tc.Handshake()
	if err != nil {
		errors.Wrap(err, "Unable to Perform TLS Handshake")
	}
	return tc, nil
}

func sendPlist(c net.Conn, send interface{}, recv interface{}) error {
	bytes, err := plist.Marshal(send, 1)
	if err != nil {
		return errors.Wrap(err, "MARSHAL")
	}
	here := make([]byte, 4)
	binary.BigEndian.PutUint32(here, uint32(len(bytes)))
	n, err := c.Write(here)
	if err != nil || n != 4 {
		return errors.Wrap(err, "WRITE")
	}
	n, err = c.Write(bytes)
	if err != nil || n != len(bytes) {
		return errors.Wrap(err, "WRITE")
	}
	n, err = io.ReadFull(c, here)
	if err != nil || n != 4 {
		return errors.Wrap(err, "READ")
	}
	bytes = make([]byte, binary.BigEndian.Uint32(here))
	n, err = io.ReadFull(c, bytes)
	if err != nil || n != int(binary.BigEndian.Uint32(here)) {
		return errors.Wrap(err, "READ")
	}
	_, err = plist.Unmarshal(bytes, recv)
	if err != nil {
		return errors.Wrap(err, "UNMARSHAL")
	}
	return nil
}
