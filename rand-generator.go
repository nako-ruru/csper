package main

import (
	"math/rand"
)

func NewRandRandGenerator(randomDirectiveTypes []string, reuseNonce bool) *RandGenerator {
	return &RandGenerator{
		randomDirectiveTypes: randomDirectiveTypes,
		reuseNonce:           reuseNonce,
	}
}

type RandGenerator struct {
	reusableNoncer       *Noncer
	randomDirectiveTypes []string
	reuseNonce           bool
}

func (_this *RandGenerator) Next() Generator {
	key := _this.randomDirectiveTypes[rand.Intn(len(_this.randomDirectiveTypes))]
	if key == "nonce" && _this.reuseNonce {
		return _this.ReusableNoncer()
	}
	return NewGenerator(key)
}

func (_this *RandGenerator) ReusableNoncer() Generator {
	if _this.reusableNoncer == nil {
		_this.reusableNoncer = NewGenerator("nonce").(*Noncer)
	}
	return _this.reusableNoncer
}
