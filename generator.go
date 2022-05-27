package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"github.com/dlclark/regexp2"
)

type Generator interface {
	Name() string
	Generate(string) string
	AppendToTags() bool
}

func NewGenerator(key string) Generator {
	switch key {
	case "nonce":
		return &Noncer{}
	case "sha256":
		return &Hasher{
			name: key,
			hashFunc: func(bytes []byte) []byte {
				sum256 := sha256.Sum256(bytes)
				return sum256[:]
			},
		}
	case "sha384":
		return &Hasher{
			name: key,
			hashFunc: func(bytes []byte) []byte {
				sum256 := sha512.Sum384(bytes)
				return sum256[:]
			},
		}
	case "sha512":
		return &Hasher{
			name: key,
			hashFunc: func(bytes []byte) []byte {
				sum256 := sha512.Sum512(bytes)
				return sum256[:]
			},
		}
	default:
		return nil
	}
}

type Noncer struct {
	nonce string
}

func (_this *Noncer) Name() string {
	return "nonce"
}

func (_this *Noncer) Generate(string) string {
	if _this.nonce == "" {
		_this.nonce = _this.genNonce()
	}
	return _this.nonce
}

func (_this *Noncer) AppendToTags() bool {
	return true
}

func (_this *Noncer) genNonce() string {
	var b [20]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

type Hasher struct {
	name string
	hashFunc func([]byte)[]byte
	newlineRegex *regexp2.Regexp
}

func (_this *Hasher) Name() string {
	return _this.name
}

func (_this *Hasher) Generate(input string) string {
	if _this.newlineRegex == nil {
		_this.newlineRegex = regexp2.MustCompile("\r\n", regexp2.Singleline)
	}
	//no idea why \r causes result different from browsers
	input, err := _this.newlineRegex.Replace(input, "\n", -1, -1)
	if err != nil {
		panic(err)
	}
	hash := _this.hashFunc([]byte(input))
	b64 := base64.StdEncoding.EncodeToString(hash[:])
	return b64
}

func (_this *Hasher) AppendToTags() bool {
	return false
}