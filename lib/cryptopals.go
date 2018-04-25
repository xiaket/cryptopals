package cryptopals

import "errors"
import "reflect"
import "strconv"
import "strings"

var frequency = map[byte]float64{
	'a': 0.08167,
	'b': 0.01492,
	'e': 0.12702,
	'c': 0.02782,
	'd': 0.04253,
	'f': 0.02228,
	'g': 0.02015,
	'h': 0.06094,
	'i': 0.06966,
	'j': 0.00153,
	'k': 0.00772,
	'l': 0.04025,
	'm': 0.02406,
	'n': 0.06749,
	'o': 0.07507,
	'p': 0.01929,
	'q': 0.00095,
	'r': 0.05987,
	's': 0.06327,
	't': 0.09056,
	'u': 0.02758,
	'v': 0.00978,
	'w': 0.02360,
	'x': 0.00150,
	'y': 0.01974,
	'z': 0.00074,
}

func CalcRating(msg string) float64 {
	rating := 0.0
	for _, ch := range msg {
		if ch < 32 && ch > 0 {
			rating -= 0.1
		} else {
			lowered_character := []byte(strings.ToLower(string(ch)))[0]
			rating += frequency[lowered_character]
		}
	}
	return rating
}

func SafeXORByte(dst []byte, a []byte, b byte) int {
	n := len(a)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b
	}
	return n
}

func SafeXORBytes(dst, a, b []byte) int {
	n := len(a)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i%len(b)]
	}
	return n
}

func msg2bin(msg string) string {
	bin_ := ""
	for _, byte_ := range []byte(msg) {
		converted := strconv.FormatInt(int64(byte_), 2)
		converted = strings.Repeat("0", 8-len(converted)) + converted
		bin_ += converted
	}
	return bin_
}

func HammingDistance(message1, message2 string) int {
	bin1 := msg2bin(message1)
	bin2 := msg2bin(message2)
	counts := 0
	for i, ch := range bin1 {
		if byte(ch) != bin2[i] {
			counts += 1
		}
	}
	return counts
}

var (
	ErrParamsNotAdapted = errors.New("The number of params is not adapted.")
)

type Funcs map[string]reflect.Value

func NewFuncs(size int) Funcs {
	return make(Funcs, size)
}

func (f Funcs) Bind(name string, fn interface{}) (err error) {
	defer func() {
		if e := recover(); e != nil {
			err = errors.New(name + " is not callable.")
		}
	}()
	v := reflect.ValueOf(fn)
	v.Type().NumIn()
	f[name] = v
	return
}

func (f Funcs) Call(name string, params ...interface{}) (result []reflect.Value, err error) {
	if _, ok := f[name]; !ok {
		err = errors.New(name + " does not exist.")
		return
	}
	if len(params) != f[name].Type().NumIn() {
		err = ErrParamsNotAdapted
		return
	}
	in := make([]reflect.Value, len(params))
	for k, param := range params {
		in[k] = reflect.ValueOf(param)
	}
	result = f[name].Call(in)
	return
}
