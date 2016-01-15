package txscript

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"sync"
)

type SigCachev2 struct {
	sync.RWMutex
	validSigs  map[wire.ShaHash]SigEntry
	maxEntries uint
}

type SigEntry struct {
	SignatureHash wire.ShaHash
	signature     *btcec.Signature
	publicKey     *btcec.PublicKey
}

func NewSigCachev2(size uint) *SigCachev2 {
	return &SigCachev2{
		validSigs:  make(map[wire.ShaHash]SigEntry, size),
		maxEntries: size,
	}
}

func NewSigEntry(sigHash wire.ShaHash, sig *btcec.Signature, pubKey *btcec.PublicKey) SigEntry {
	return SigEntry{
		SignatureHash: sigHash, signature: sig, publicKey: pubKey,
	}
}

func (sigCache *SigCachev2) Add(sigEntry SigEntry) {
	sigCache.Lock()
	defer sigCache.Unlock()

	sigCache.validSigs[sigEntry.SignatureHash] = sigEntry
}
