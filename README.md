# camo

Camo is a Go package that "camouflages" a string or byte slice by making it
opaque to reflection. This _mostly_ protects the data from being exposed by
reflection or by being printed to the console, log files, etc.

For the full documentation, see the
[GoDoc](https://pkg.go.dev/github.com/rbranson/camo).

## Usage

```go
package main

import (
    "fmt"
    "github.com/rbranson/camo"
)

func main() {
    s := camo.Obscure("hello, world!")
    fmt.Println(s) // Output: "camouflaged"
    fmt.Println(s.String()) // Output: "hello, world!"
}
```
