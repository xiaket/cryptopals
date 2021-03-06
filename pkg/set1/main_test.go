package set1

import (
	"github.com/stretchr/testify/assert"
	"github.com/xiaket/cryptopals/pkg/testutil"
	"strings"
	"testing"
)

func TestProb2(test *testing.T) {
	msg1 := []byte("1c0111001f010100061a024b53535009181c")
	msg2 := []byte("686974207468652062756c6c277320657965")
	const expected = "746865206b696420646f6e277420706c6179"
	encoded := string(prob2(msg1, msg2))
	assert.Equal(test, encoded, expected, "Incorrect xored string: %s, want: %s.", encoded, expected)
}

func TestProb4(test *testing.T) {
	expected := []byte("Now that the party is jumping")
	guess := prob4()
	assert.Equal(test, guess, expected, "Incorrect guess result: %s, want: %s.", guess, expected)
}

func TestProb5(test *testing.T) {
	const message = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
	const key = "ICE"
	const expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20690a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	encoded := prob5(message, key)
	assert.Equal(test, encoded, expected, "Incorrect encoded result: %s, want: %s.", encoded, expected)
}

func TestProb6(test *testing.T) {
	const expected = "Terminator X: Bring the noise"
	const prefix = "I'm back and I'm ringin' the bell"
	const length = 2876
	guess, decoded := prob6()
	assert.Equal(test, guess, expected, "Incorrect key: %s, want: %s.", guess, expected)
	testutil.VerifyPrefixAndLength(decoded, prefix, length, test)
}

func TestProb7(test *testing.T) {
	const prefix = "I'm back and I'm ringin' the bell"
	const length = 2880
	decrypted := prob7([]byte("YELLOW SUBMARINE"), 16)
	testutil.VerifyPrefixAndLength(decrypted, prefix, length, test)
}

func TestProb8(test *testing.T) {
	const prefix = "d880619740a8a19b7840a8"
	found := prob8()
	assert.True(test, strings.HasPrefix(found, prefix), "Incorrect result: prefix %s, want: %s.", found[:len(prefix)], prefix)
}
