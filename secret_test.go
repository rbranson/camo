package camo

import (
	"bytes"
	"slices"
	"strconv"
	"testing"
)

func FuzzSecret(f *testing.F) {
	f.Add("", []byte(nil))
	f.Add("1", []byte("1"))
	f.Add("2", []byte("3"))
	f.Add("XXXXXXX", []byte{0})
	f.Fuzz(func(t *testing.T, s string, b []byte) {
		if !Obscure(s).Valid() {
			t.Errorf("unexpected invalid Secret from string")
		}
		if !Obscure(b).Valid() {
			t.Errorf("unexpected invalid Secret from []byte")
		}
	})
}

func TestSecret(t *testing.T) {
	cases := []struct {
		name string
		base Secret[[]byte]
		want []byte
	}{
		{
			name: "nil contents",
			base: Obscure([]byte(nil)),
			want: nil,
		},
		{
			name: "empty contents",
			base: Obscure([]byte{}),
			want: []byte{},
		},
		{
			name: "024",
			base: Obscure([]byte{0, 2, 4}),
			want: []byte{0, 2, 4},
		},
		{
			name: "foo",
			base: Obscure([]byte("foo")),
			want: []byte("foo"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.base.Valid() {
				panic("invalid Secret in test case")
			}
			got := tc.base.Reveal()
			if !bytes.Equal(tc.want, got) {
				t.Errorf("got = %q; want %q", got, tc.want)
			}
		})
	}
}

func TestZeroSecretInvalid(t *testing.T) {
	var zero Secret[[]byte]
	if zero.Valid() {
		t.Errorf("expected zero Secret to be invalid")
	}
}

func TestMapHashDeterminism(t *testing.T) {
	var last Secret[string]
	for i := 0; i < 100; i++ {
		got := Obscure("test")
		if i > 0 && got != last {
			t.Errorf("expected got == last")
		}
		last = got
	}
}

func TestObscureAndRevealPerformCopies(t *testing.T) {
	in := []byte("foo")
	want := slices.Clone(in)
	s := Obscure(in)
	in[0] = 100
	got := s.Reveal()
	if !bytes.Equal(s.Reveal(), got) {
		t.Errorf("secret content should not have been modified by mutation: %q != %q", "foo", got)
	}

	got[0] = 100
	if got := s.Reveal(); !bytes.Equal(got, want) {
		t.Errorf("secret content should not have been modified by mutation: %q != %q", "foo", got)
	}
}

func TestObscureDoesNotRepeatPointers(t *testing.T) {
	// For a given content, Obscure should never repeat a pointers as long as it is held. This
	// is a "probablistic" test of that property.
	cases := [][]byte{
		nil,
		{},
		{1, 2, 3},
	}
	for i, tc := range cases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			secrets := []Secret[[]byte]{}
			for i := 0; i < 1000; i++ {
				// This is only "interesting" if references are held for the lifetime of the run,
				// so don't just like convert these to serialized pointer strings or something
				secrets = append(secrets, Obscure(tc))
			}
			for ai, a := range secrets {
				for bi, b := range secrets {
					if ai != bi && a.secret().p == b.secret().p {
						t.Errorf("Obscure produced the same pointer twice for input %v", tc)
						return
					}
				}
			}
		})
	}
}

func TestPanicOnZeroReveal(t *testing.T) {
	var zero Secret[string]
	_, ok := capturePanic(func() { zero.Reveal() })
	if !ok {
		t.Errorf("expected zero.Reveal() to panic")
	}
}

func TestPanicOnZeroAppend(t *testing.T) {
	var zero Secret[string]
	_, ok := capturePanic(func() { zero.AppendTo(nil) })
	if !ok {
		t.Errorf("expected zero.Reveal() to panic")
	}
}

func TestAppendTo(t *testing.T) {
	got := Obscure("bar").AppendTo([]byte("foo"))
	want := []byte("foobar")
	if !bytes.Equal(got, want) {
		t.Errorf("got = %s; want %s", got, want)
	}
}

// capturePanic executes f and if it panics, it return the value passed to
// panic and true, otherwise it returns a nil value and false.
func capturePanic(f func()) (any, bool) {
	var recovered any
	var ok bool

	func() {
		defer func() {
			if r := recover(); r != nil {
				recovered = r
				ok = true
			}
		}()
		f()
	}()

	return recovered, ok
}
