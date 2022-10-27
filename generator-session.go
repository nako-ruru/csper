package main

import (
	"math/rand"
)

func NewFetchDirectiveGeneratorSession(randomDirectiveTypes []string, reuseNonce bool) *FetchDirectiveGeneratorSession {
	return &FetchDirectiveGeneratorSession{
		randomDirectiveTypes: randomDirectiveTypes,
		reuseNonce:           reuseNonce,
	}
}

type FetchDirectiveGeneratorSession struct {
	reusableNoncer       *Noncer
	randomDirectiveTypes []string
	reuseNonce           bool
}

func (_this *FetchDirectiveGeneratorSession) Next() Generator {
	key := _this.randomDirectiveTypes[rand.Intn(len(_this.randomDirectiveTypes))]
	if key == "nonce" && _this.reuseNonce {
		return _this.ReusableNoncer()
	}
	return NewGenerator(key)
}

func (_this *FetchDirectiveGeneratorSession) ReusableNoncer() Generator {
	if _this.reusableNoncer == nil {
		_this.reusableNoncer = NewGenerator("nonce").(*Noncer)
	}
	return _this.reusableNoncer
}
