package addrgen

import "math/big"

type DomainName string

var _ AddrGetter = DomainName("")

func (n DomainName) Addr() string {
	return string(n)
}

func (n DomainName) Power() *big.Int {
	return big.NewInt(1)
}
