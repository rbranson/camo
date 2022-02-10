package camo

import (
	"bytes"
	"unsafe"
)

// Secret is secret data that cannot be inspected via general reflection code,
// which is useful for preventing secret data from accidental serialization
// and storage or transfer over the wire. It is immutable and therefore
// concurrency-safe.
//
// Just to be clear, this isn't a hard constraint. Truly malicious code still
// has access to this memory, and of course could still call the method which
// returns the underlying data.
//
// The zero value of this type is intentionally distinguishable from an empty
// secret, so that empty secrets to not appear as a form of null when
// reflection code inspects the data structure.
type Secret struct {
	// Using an unsafe.Pointer "erases" the type of the underlying data as it
	// is only "known" by the code in this package. To any code using
	// reflection, this will only appear to be an opaque memory address.
	p unsafe.Pointer
}

func Obscure(contents []byte) Secret {
	// Make a copy to force immutability. This also means that Secrets with
	// empty contents will look like a pointer to a valid object, to avoid
	// being able to distinguish empty secrets in any emitted output.
	buf := make([]byte, len(contents))
	copy(buf, contents)
	return Secret{
		p: unsafe.Pointer(&buf),
	}
}

// this will panic if it's null (avoids double checking in most cases)
func (s Secret) deref() []byte {
	return *(*[]byte)(s.p)
}

// Reveal returns a copy of the secret contents, or nil if a zero value
func (s Secret) Reveal() []byte {
	if s.p == nil {
		return nil
	}
	cont := s.deref()
	buf := make([]byte, len(cont))
	copy(buf, cont)
	return buf
}

// RevealCopy copies the secret contents into dst and returns the number
// of bytes written.
func (s Secret) RevealCopy(dst []byte) int {
	if s.p == nil {
		return 0
	}
	cont := s.deref()
	return copy(dst, cont)
}

// Equal reports whether other's contents are equal to this secret, *OR* if
// both of the secrets are zero value.
func (s Secret) Equal(other Secret) bool {
	if s.p == other.p {
		return true // covers both-nils case
	}
	if s.p == nil || other.p == nil {
		return false
	}
	return bytes.Equal(s.deref(), other.deref())
}

// Compare returns an integer comparing the two secrets lexicographically. It
// works identically to bytes.Compare. In the case both secrets are zero values
// it will return 0.
func (a Secret) Compare(b Secret) int {
	switch {
	case a.p == b.p: // covers both-nils case
		return 0
	case a.p == nil:
		return -1
	case b.p == nil:
		return 1
	}
	return bytes.Compare(a.deref(), b.deref())
}
