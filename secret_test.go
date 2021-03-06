package camo

import (
	"reflect"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// value copies the value from in to out and returns true, unless in is nil, in
// which case it does nothing and returns false. Both in and out must be
// pointers of the same type, but just to be clear, this does not copy the
// pointers, it copies the values. out can't be nil, and it must be "settable"
// i.e. it can't point to a const value etc. This will panic on any violation
// of these constraints.
func value(in interface{}, out interface{}) bool {
	if in == nil {
		return false
	}
	if out == nil {
		panic("out can't be nil")
	}

	rin := reflect.ValueOf(in)
	rout := reflect.ValueOf(out)

	// type checks, more specific than necessary to help diagnose common mistakes
	if rin.Type().Kind() != reflect.Ptr {
		panic("in must be a pointer")
	}
	if rout.Type().Kind() != reflect.Ptr {
		panic("out must be a pointer")
	}
	if rout.Type() != rin.Type() {
		panic("out type must be the same as in type")
	}

	// value checks
	if rout.IsNil() {
		panic("out can't be nil")
	}
	if !rout.Elem().CanSet() {
		panic("out's value must be mutable")
	}

	if rin.IsNil() {
		return false
	}
	rout.Elem().Set(rin.Elem())
	return true
}

// ptreq returns true if a and b are equal pointers.
func ptreq(a interface{}, b interface{}) bool {
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}

func TestSecret(t *testing.T) {
	obscure := func(contents []byte) *Secret {
		v := Obscure(contents)
		if v.p == nil {
			t.Fatal("Obscure should never result in a zero value")
		}
		return &v
	}

	sec1 := Obscure([]byte{1, 2, 3})
	sec1copy := sec1

	var zero Secret
	type copyCase struct {
		dst    []byte
		ret    int
		expect []byte
	}
	cases := []struct {
		name        string
		base        Secret
		reveals     []byte
		equalTo     *Secret
		nequalTo    *Secret
		lessThan    *Secret
		greaterThan *Secret
		copy        *copyCase
	}{
		{
			name:     "zero value",
			equalTo:  &zero,
			nequalTo: obscure(nil),
			lessThan: obscure(nil),
		},
		{
			name:        "nil contents",
			base:        Obscure(nil),
			reveals:     []byte{},
			equalTo:     obscure(nil),
			nequalTo:    &zero,
			lessThan:    obscure([]byte{0}),
			greaterThan: &zero,
			copy: &copyCase{
				dst:    make([]byte, 1),
				ret:    0,
				expect: []byte{0},
			},
		},
		{
			name:        "empty contents",
			base:        Obscure([]byte{}),
			reveals:     []byte{},
			equalTo:     obscure([]byte{}),
			nequalTo:    &zero,
			greaterThan: &zero,
			copy: &copyCase{
				dst:    make([]byte, 1),
				ret:    0,
				expect: []byte{0},
			},
		},
		{
			name:    "empty contents eq nil contents",
			base:    Obscure([]byte{}),
			equalTo: obscure(nil),
		},
		{
			name:        "024",
			base:        Obscure([]byte{0, 2, 4}),
			reveals:     []byte{0, 2, 4},
			equalTo:     obscure([]byte{0, 2, 4}),
			nequalTo:    obscure([]byte{0, 2, 5}),
			lessThan:    obscure([]byte{0, 2, 5}),
			greaterThan: obscure([]byte{0, 2, 3}),
			copy: &copyCase{
				dst:    make([]byte, 3),
				ret:    3,
				expect: []byte{0, 2, 4},
			},
		},
		{
			name:    "same internal pointer eq check",
			base:    sec1,
			equalTo: &sec1copy,
		},
		{
			name: "copy to zero buffer",
			base: Obscure([]byte{0, 1, 2, 3, 4}),
			copy: &copyCase{
				dst:    []byte{},
				ret:    0,
				expect: []byte{},
			},
		},
		{
			name: "copy to short buffer",
			base: Obscure([]byte{0, 1, 2, 3, 4}),
			copy: &copyCase{
				dst:    make([]byte, 3),
				ret:    3,
				expect: []byte{0, 1, 2},
			},
		},
		{
			name: "copy to long buffer",
			base: Obscure([]byte{0, 1, 2, 3, 4}),
			copy: &copyCase{
				dst:    make([]byte, 7),
				ret:    5,
				expect: []byte{0, 1, 2, 3, 4, 0, 0},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.reveals != nil {
				reveals := tc.base.Reveal()
				if diff := cmp.Diff(tc.reveals, reveals); diff != "" {
					t.Errorf("Reveal() mismatch:\n%s", diff)
				}
				if rev2 := tc.base.Reveal(); cap(reveals) > 0 && ptreq(reveals, tc.base.Reveal()) {
					// Go spec for slices means that non-zero-capacity slices are essentially immutable
					t.Errorf("Reveal() should never return the same cap>0 slice twice (%p == %p)", reveals, rev2)
				}
			}

			var s Secret
			if ok := value(tc.equalTo, &s); ok {
				if !tc.base.Equal(s) {
					t.Error("Equal does not match against equalTo")
				}
				if x := tc.base.Compare(s); x != 0 {
					t.Errorf("Expected Compare on equalTo to return 0, got %v", x)
				}
			}

			if ok := value(tc.nequalTo, &s); ok {
				if tc.base.Equal(s) {
					t.Error("Equal matches against nequalTo and should not")
				}
				if x := tc.base.Compare(s); x == 0 {
					t.Error("Expected Compare on nequalTo to return non-0, got 0")
				}
			}

			if ok := value(tc.lessThan, &s); ok {
				if x := tc.base.Compare(s); x != -1 {
					t.Errorf("Expected Compare with lessThan to return -1, got %v", x)
				}
			}

			if ok := value(tc.greaterThan, &s); ok {
				if x := tc.base.Compare(s); x != 1 {
					t.Errorf("Expected Compare with greaterThan to return 1, got %v", x)
				}
			}

			if tc.copy != nil {
				copyN := tc.base.RevealCopy(tc.copy.dst)
				if copyN != tc.copy.ret {
					t.Errorf("Expected RevealCopy to return %v, got %v", tc.copy.ret, copyN)
				}
				if diff := cmp.Diff(tc.copy.expect, tc.copy.dst); diff != "" {
					t.Errorf("RevealCopy() mismatch on copyExpect field:\n%s", diff)
				}
			}
		})
	}
}

func TestObscureAndRevealPerformCopies(t *testing.T) {
	cont := []byte{1, 2, 3, 4}
	sec := Obscure(cont)
	cont[0] = 100
	rev := sec.Reveal()
	if diff := cmp.Diff([]byte{1, 2, 3, 4}, rev); diff != "" {
		t.Errorf("secret content should not have been modified by mutation:\n%s", diff)
	}
	rev[0] = 100
	if diff := cmp.Diff([]byte{1, 2, 3, 4}, sec.Reveal()); diff != "" {
		t.Errorf("secret content should not have been modified by mutation:\n%s", diff)
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
			secrets := []Secret{}
			for i := 0; i < 1000; i++ {
				// This is only "interesting" if references are held for the lifetime of the run,
				// so don't just like convert these to serialized pointer strings or something
				secrets = append(secrets, Obscure(tc))
			}
			for ai, a := range secrets {
				for bi, b := range secrets {
					if ai != bi && a.p == b.p {
						t.Errorf("Obscure produced the same pointer twice for input %v", tc)
						return
					}
				}
			}
		})
	}
}

// capturePanic executes f and if it panics, it return the value passed to
// panic and true, otherwise it returns a nil value and false.
func capturePanic(f func()) (interface{}, bool) {
	var recovered interface{}
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

func TestRevealMethodsPanicOnZeroValue(t *testing.T) {
	cases := []struct {
		name       string
		panicValue interface{}
		f          func(s Secret)
	}{
		{
			name:       "Reveal method",
			panicValue: "cannot reveal a zero secret",
			f: func(s Secret) {
				_ = s.Reveal()
			},
		},
		{
			name:       "RevealCopy method",
			panicValue: "cannot reveal a zero secret",
			f: func(s Secret) {
				_ = s.RevealCopy([]byte{})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pv, ok := capturePanic(func() {
				tc.f(Secret{})
			})
			if !ok {
				t.Error("expected function to panic")
				return
			}
			if pv != tc.panicValue {
				t.Errorf("expected panic value of %v, got %v", tc.panicValue, pv)
			}
		})
	}
}
