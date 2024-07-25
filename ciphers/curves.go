package ciphers

import (
	"fmt"
	"strings"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
)

type CurveList = []elliptic.Curve

var FullCurveList = CurveList{
	elliptic.X25519,
	elliptic.P256,
	elliptic.P384,
}

var DefaultCurveList = FullCurveList
var DefaultCurveListString = CurveListToString(DefaultCurveList)
var CurveNameToID map[string]elliptic.Curve

func init() {
	CurveNameToID = make(map[string]elliptic.Curve)
	for _, curve := range FullCurveList {
		CurveNameToID[curve.String()] = curve
	}
}

func CurveIDToString(curve elliptic.Curve) string {
	return curve.String()
}

func CurveListToString(lst CurveList) string {
	var b strings.Builder
	var firstPrinted bool
	for _, curve := range lst {
		if firstPrinted {
			b.WriteByte(':')
		} else {
			firstPrinted = true
		}
		b.WriteString(curve.String())
	}
	return b.String()
}

func StringToCurveList(str string) (CurveList, error) {
	if str == "" {
		return CurveList{}, nil
	}
	parts := strings.Split(str, ":")
	var res CurveList
	for _, name := range parts {
		if id, ok := CurveNameToID[name]; ok {
			res = append(res, id)
		} else {
			return nil, fmt.Errorf("unknown curve: %q", name)
		}
	}
	return res, nil
}
