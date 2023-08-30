package ciphers

import (
	"fmt"
	"strings"

	"github.com/pion/dtls/v2"
)

type CipherList = []dtls.CipherSuiteID

var FullList = CipherList{
	dtls.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
	dtls.TLS_PSK_WITH_AES_128_CCM,
	dtls.TLS_PSK_WITH_AES_128_CCM_8,
	dtls.TLS_PSK_WITH_AES_256_CCM_8,
	dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
	dtls.TLS_PSK_WITH_AES_128_CBC_SHA256,
}

var DefaultList = FullList
var DefaultListString = ListToString(DefaultList)
var NameToID map[string]dtls.CipherSuiteID

func init() {
	NameToID = make(map[string]dtls.CipherSuiteID)
	for _, id := range FullList {
		NameToID[dtls.CipherSuiteName(id)] = id
	}
}

func IDToString(id dtls.CipherSuiteID) string {
	return dtls.CipherSuiteName(id)
}

func ListToString(lst CipherList) string {
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

func StringToList(str string) (CipherList, error) {
	if str == "" {
		return nil, nil
	}
	parts := strings.Split(str, ":")
	var res CipherList
	for _, name := range parts {
		if id, ok := NameToID[name]; ok {
			res = append(res, id)
		} else {
			return nil, fmt.Errorf("unknown ciphersuite: %q", name)
		}
	}
	return res, nil
}
