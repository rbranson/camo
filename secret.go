// Package camo provides the Secret type, which is a comparable, immutable
// wrapper around a string or byte slice that is opaque to reflection, making
// it useful for preventing secret data (such as passwords and API keys) from
// accidental serialization and storage or transfer over the wire.
package camo

import (
	"bytes"
	"fmt"
	"hash/maphash"
	"unsafe"
)

// Obscurable is the set of types that can be obscured by the Secret type.
type Obscurable interface {
	string | []byte
}

var hashSeed = maphash.MakeSeed()

// Secret is secret data that cannot be inspected via reflection techniques,
// which is useful for preventing secret data from accidental serialization
// and storage or transfer over the wire.
//
// Just to be clear, this isn't a hard constraint. While it will thwart a
// well-intentioned developer, even if they are using "unsanctioned" reflection
// such as those used by the go-spew package, truly malicious code still has
// access to this memory, and of course could still call the method which
// returns the underlying data.
//
// The zero value of this type is intentionally distinguishable from an empty
// secret, so that empty secrets do not appear as a form of null when
// reflection code inspects the data structure.
//
// Another thing to note about the zero value is that the Reveal and Append
// methods will panic. Other methods such as comparisons will not. This is
// analogous to the behavior of nil.
//
// It is immutable, so it is safe to pass around by value.
//
// It is comparable, so it can be used as a map key.
type Secret[O Obscurable] struct {
	_ unsafe.Pointer

	hash uint64
}

type secret struct {
	// Using an unsafe.Pointer "erases" the type of the underlying data as it
	// is only "known" by the code in this package. While reflection already
	// won't stumble across this field, commonly used packages like go-spew
	// use various hacks to peer into unexported fields, which this will
	// thwart.
	p    unsafe.Pointer
	hash uint64
}

// Obscure returns a Secret that wraps the given content. The content must be a
// string or byte slice. If a byte slice is given it will be copied into a
// newly allocated byte slice owned by the Secret.
func Obscure[O Obscurable](content O) Secret[O] {
	// Make a copy to force immutability. This also means that Secrets with
	// empty content will look like a pointer to a valid object, to avoid
	// being able to distinguish empty secrets in any emitted output.
	str := string(content)
	s := secret{
		p:    unsafe.Pointer(&str),
		hash: maphash.String(hashSeed, str),
	}
	return *(*Secret[O])(unsafe.Pointer(&s))
}

// Valid reports if the Secret is valid.
func (s Secret[O]) Valid() bool {
	ss := s.secret()
	return ss.p != nil
}

func (s Secret[O]) secret() secret {
	return *(*secret)(unsafe.Pointer(&s))
}

func (s Secret[O]) deref() O {
	ss := s.secret()
	return *(*O)(ss.p)
}

// Reveal returns the underlying secret data. If the secret is a byte slice,
// then a copy of the byte slice is returned. If the secret is a string, then
// the string is returned. It panics if the secret is zero.
func (s Secret[O]) Reveal() O {
	ss := s.secret()
	if ss.p == nil {
		panic("illegal use of Reveal on a zero secret")
	}
	switch v := any(s.deref()).(type) {
	case string:
		return O(v)
	case []byte:
		return O(bytes.Clone(v))
	default:
		panic(fmt.Sprintf("illegal type %T", v))
	}
}

// AppendTo appends the secret to the byte slice, and returns the updated
// slice. It panics if the secret is zero.
func (s Secret[O]) AppendTo(dst []byte) []byte {
	ss := s.secret()
	if ss.p == nil {
		panic("illegal use of AppendTo on a zero secret")
	}
	return append(dst, s.deref()...)
}
