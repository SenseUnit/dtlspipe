package ciphers

import (
	"fmt"
	"strings"

	"github.com/pion/dtls/v3"
)

type CipherList = []dtls.CipherSuiteID

var FullCipherList = CipherList{
	dtls.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
	dtls.TLS_PSK_WITH_AES_128_CCM,
	dtls.TLS_PSK_WITH_AES_128_CCM_8,
	dtls.TLS_PSK_WITH_AES_256_CCM_8,
	dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
	dtls.TLS_PSK_WITH_AES_128_CBC_SHA256,
}

var DefaultCipherList = FullCipherList
var DefaultCipherListString = CipherListToString(DefaultCipherList)
var CipherNameToID map[string]dtls.CipherSuiteID

func init() {
	CipherNameToID = make(map[string]dtls.CipherSuiteID)
	for _, id := range FullCipherList {
		CipherNameToID[dtls.CipherSuiteName(id)] = id
	}
}

func CipherIDToString(id dtls.CipherSuiteID) string {
	return dtls.CipherSuiteName(id)
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
		b.WriteString(dtls.CipherSuiteName(id))
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
