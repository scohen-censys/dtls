// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"encoding/binary"

	"github.com/scohen-censys/dtls/v2/pkg/protocol"
	"github.com/scohen-censys/dtls/v2/pkg/protocol/extension"
	"github.com/zmap/zcrypto/tls"
)

/*
MessageClientHello is for when a client first connects to a server it is
required to send the client hello as its first message.  The client can also send a
client hello in response to a hello request or on its own
initiative in order to renegotiate the security parameters in an
existing connection.
*/
type MessageClientHello struct {
	Version protocol.Version
	Random  Random
	Cookie  []byte

	SessionID []byte

	CipherSuiteIDs     []uint16
	CompressionMethods []*protocol.CompressionMethod
	Extensions         []extension.Extension
}

const handshakeMessageClientHelloVariableWidthStart = 34

// Type returns the Handshake Type
func (m MessageClientHello) Type() Type {
	return TypeClientHello
}

// Marshal encodes the Handshake
func (m *MessageClientHello) Marshal() ([]byte, error) {
	if len(m.Cookie) > 255 {
		return nil, errCookieTooLong
	}

	out := make([]byte, handshakeMessageClientHelloVariableWidthStart)
	out[0] = m.Version.Major
	out[1] = m.Version.Minor

	rand := m.Random.MarshalFixed()
	copy(out[2:], rand[:])

	out = append(out, byte(len(m.SessionID)))
	out = append(out, m.SessionID...)

	out = append(out, byte(len(m.Cookie)))
	out = append(out, m.Cookie...)
	out = append(out, encodeCipherSuiteIDs(m.CipherSuiteIDs)...)
	out = append(out, protocol.EncodeCompressionMethods(m.CompressionMethods)...)

	extensions, err := extension.Marshal(m.Extensions)
	if err != nil {
		return nil, err
	}

	return append(out, extensions...), nil
}

// Unmarshal populates the message from encoded data
func (m *MessageClientHello) Unmarshal(data []byte) error {
	if len(data) < 2+RandomLength {
		return errBufferTooSmall
	}

	m.Version.Major = data[0]
	m.Version.Minor = data[1]

	var random [RandomLength]byte
	copy(random[:], data[2:])
	m.Random.UnmarshalFixed(random)

	// rest of packet has variable width sections
	currOffset := handshakeMessageClientHelloVariableWidthStart

	currOffset++
	if len(data) <= currOffset {
		return errBufferTooSmall
	}
	n := int(data[currOffset-1])
	if len(data) <= currOffset+n {
		return errBufferTooSmall
	}
	m.SessionID = append([]byte{}, data[currOffset:currOffset+n]...)
	currOffset += len(m.SessionID)

	currOffset++
	if len(data) <= currOffset {
		return errBufferTooSmall
	}
	n = int(data[currOffset-1])
	if len(data) <= currOffset+n {
		return errBufferTooSmall
	}
	m.Cookie = append([]byte{}, data[currOffset:currOffset+n]...)
	currOffset += len(m.Cookie)

	// Cipher Suites
	if len(data) < currOffset {
		return errBufferTooSmall
	}
	cipherSuiteIDs, err := decodeCipherSuiteIDs(data[currOffset:])
	if err != nil {
		return err
	}
	m.CipherSuiteIDs = cipherSuiteIDs
	if len(data) < currOffset+2 {
		return errBufferTooSmall
	}
	currOffset += int(binary.BigEndian.Uint16(data[currOffset:])) + 2

	// Compression Methods
	if len(data) < currOffset {
		return errBufferTooSmall
	}
	compressionMethods, err := protocol.DecodeCompressionMethods(data[currOffset:])
	if err != nil {
		return err
	}
	m.CompressionMethods = compressionMethods
	if len(data) < currOffset {
		return errBufferTooSmall
	}
	currOffset += int(data[currOffset]) + 1

	// Extensions
	extensions, err := extension.Unmarshal(data[currOffset:])
	if err != nil {
		return err
	}
	m.Extensions = extensions
	return nil
}

func (m *MessageClientHello) MakeLog() *tls.ClientHello {
	ret := &tls.ClientHello{}

	ret.Version = tls.TLSVersion((uint16(m.Version.Major) << 8) | uint16(m.Version.Minor))

	ret.Random = make([]byte, RandomLength)
	binary.BigEndian.PutUint32(ret.Random[:4], uint32(m.Random.GMTUnixTime.Unix()))
	copy(ret.Random[4:], m.Random.RandomBytes[:])

	ret.SessionID = make([]byte, len(m.SessionID))
	copy(ret.SessionID, m.SessionID)

	ret.CipherSuites = make([]tls.CipherSuiteID, len(m.CipherSuiteIDs))
	for ix, s := range m.CipherSuiteIDs {
		ret.CipherSuites[ix] = tls.CipherSuiteID(s)
	}

	ret.CompressionMethods = make([]tls.CompressionMethod, len(m.CompressionMethods))
	for ix, m := range m.CompressionMethods {
		ret.CompressionMethods[ix] = tls.CompressionMethod(m.ID)
	}

	for _, anyExt := range m.Extensions {
		switch e := anyExt.(type) {
		case *extension.ALPN:
			ret.AlpnProtocols = make([]string, len(e.ProtocolNameList))
			copy(ret.AlpnProtocols, e.ProtocolNameList)
		case *extension.UseSRTP:
		case *extension.ConnectionID:
			// https://tools.ietf.org/html/rfc9146
		case *extension.RenegotiationInfo:
			ret.SecureRenegotiation = true
		case *extension.ServerName:
			ret.ServerName = e.ServerName
		case *extension.SupportedEllipticCurves:
			ret.SupportedCurves = make([]tls.CurveID, len(e.EllipticCurves))
			for ix, curve := range e.EllipticCurves {
				ret.SupportedCurves[ix] = tls.CurveID(curve)
			}
		case *extension.SupportedPointFormats:
			ret.SupportedPoints = make([]tls.PointFormat, len(e.PointFormats))
			for ix, pointFmt := range e.PointFormats {
				ret.SupportedPoints[ix] = tls.PointFormat(pointFmt)
			}
		case *extension.SupportedSignatureAlgorithms:
			ret.SignatureAndHashes = make([]tls.SignatureAndHash, len(e.SignatureHashAlgorithms))
			for ix, sigAlg := range e.SignatureHashAlgorithms {
				ret.SignatureAndHashes[ix] = tls.SignatureAndHash{
					Signature: uint8(sigAlg.Signature & 0xff),
					Hash:      uint8(sigAlg.Hash & 0xff),
				}
			}
		case *extension.UseExtendedMasterSecret:
			ret.ExtendedMasterSecret = e.Supported
		default:
		}
	}
	return ret
}
