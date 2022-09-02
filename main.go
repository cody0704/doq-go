package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
)

const maxQUICIdleTimeout = 5 * time.Minute

var dnsServer string

func main() {
	flag.StringVar(&dnsServer, "dns", "8.8.8.8:53", "Proxy to a specific DNS server")
	flag.Parse()

	config := generateTLSConfig()

	listener, err := quic.ListenAddr(":853", config, &quic.Config{MaxIdleTimeout: maxQUICIdleTimeout})
	if err != nil {
		log.Panic("Listen:", err)
	}

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Println("Accept:", err)

			continue
		}

		go doqHandler(conn)
	}
}

func doqHandler(conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			// Close the connection to make sure resources are freed.
			err = conn.CloseWithError(0, "")
			if err != nil {
				log.Println("failed to close QUIC connection:", err)
			}

			break
		}

		buf := make([]byte, 65535)
		nr, err := stream.Read(buf)
		if nr < 17 {
			log.Println(err)

			break
		}

		// Skip "tcp segment of a reassembled pdu"
		if nr < 3 {
			break
		}

		if nr > 0 {
			// DoT Data Parser
			var dnsPacket dns.Msg
			if err := dnsPacket.Unpack(buf[2:nr]); err != nil {
				if err := dnsPacket.Unpack(buf[0:nr]); err != nil {
					log.Panic("DNS Payload Parse Failed:Payload", err)
					break
				}
			}

			var domain string
			var qtype uint16

			domain = dnsPacket.Question[0].Name
			qtype = dnsPacket.Question[0].Qtype

			m := new(dns.Msg)

			// logger.Record("[%s][%d] %s DoT Response:QType:%s",
			// 	pidNo, dnsID, srcRemoteInfo, dns.TypeToString[qtype])

			m.SetQuestion(domain, qtype)
			c := new(dns.Client)

			recursion, _, err := c.Exchange(m, "8.8.8.8:53")
			if err != nil {
				log.Println("Forwarding error")
			}

			m = recursion

			m.SetReply(&dnsPacket)
			m.SetEdns0(512, true)

			replay, _ := m.Pack()

			// Calculate the packet size and add the beginning
			replay = append(intToBytes(len(replay)), replay...)

			// Response DNS Packet
			_, err = stream.Write(replay)
			if err != nil {
				log.Println("Response Error")
				break
			}
		}
	}
}

func intToBytes(n int) []byte {
	data := int16(n)
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, data)
	return bytebuf.Bytes()
}

func generateTLSConfig() *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: new(big.Int).Lsh(big.NewInt(1), 128),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates:             []tls.Certificate{tlsCert},
		InsecureSkipVerify:       true,
		PreferServerCipherSuites: true,
		CurvePreferences:         []tls.CurveID{tls.CurveP256, tls.X25519},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}
}
