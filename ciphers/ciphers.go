package ciphers

import (
	"fmt"
	"strings"

	"github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
)

type CipherList = []ciphersuite.ID

var FullCipherList = CipherList{
	ciphersuite.TLS_PSK_WITH_AES_128_CCM,
	ciphersuite.TLS_PSK_WITH_AES_128_CCM_8,
	ciphersuite.TLS_PSK_WITH_AES_256_CCM_8,
	ciphersuite.TLS_PSK_WITH_AES_128_GCM_SHA256,
	ciphersuite.TLS_PSK_WITH_AES_128_CBC_SHA256,
	ciphersuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
	ciphersuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
	ciphersuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
	ciphersuite.TLS_AES_128_GCM_SHA256,
	ciphersuite.TLS_AES_256_GCM_SHA384,
	ciphersuite.TLS_CHACHA20_POLY1305_SHA256,
}

var DefaultCipherList = FullCipherList
var DefaultCipherListString = CipherListToString(DefaultCipherList)
var CipherNameToID map[string]ciphersuite.ID

func init() {
	CipherNameToID = make(map[string]ciphersuite.ID)
	for _, id := range FullCipherList {
		CipherNameToID[id.String()] = id
	}
}

func CipherListToString(lst CipherList) string {
	var b strings.Builder
	var firstPrinted bool
	for _, id := range lst {
		if firstPrinted {
			b.WriteByte(':')
		} else {
			firstPrinted = true
		}
		b.WriteString(id.String())
	}
	return b.String()
}

func StringToCipherList(str string) (CipherList, error) {
	if str == "" {
		return nil, nil
	}
	parts := strings.Split(str, ":")
	var res CipherList
	for _, name := range parts {
		if id, ok := CipherNameToID[name]; ok {
			res = append(res, id)
		} else {
			return nil, fmt.Errorf("unknown ciphersuite: %q", name)
		}
	}
	return res, nil
}
