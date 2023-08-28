package keystore

import "bytes"

type StaticKeystore struct {
	psk []byte
}

func NewStaticKeystore(psk []byte) *StaticKeystore {
	return &StaticKeystore{
		psk: bytes.Clone(psk),
	}
}

func (store *StaticKeystore) PSKCallback(hint []byte) ([]byte, error) {
	return bytes.Clone(store.psk), nil
}
