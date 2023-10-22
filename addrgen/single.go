package addrgen

import "math/big"

type SingleAddr string

var _ AddrGen = SingleAddr("")

func (n SingleAddr) Addr() string {
	return string(n)
}

func (n SingleAddr) Power() *big.Int {
	return big.NewInt(1)
}
