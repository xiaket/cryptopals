package solutions

import "strings"
import "testing"

func TestProb2(test *testing.T) {
	const msg1 = "1c0111001f010100061a024b53535009181c"
	const msg2 = "686974207468652062756c6c277320657965"
	const expected = "746865206b696420646f6e277420706c6179"
	encoded := prob2(msg1, msg2)
	if encoded != expected {
		test.Errorf("Incorrect xored string: %s, want: %s.", encoded, expected)
	}
}

func TestProb4(test *testing.T) {
	const expected = "Now that the party is jumping"
	guess := prob4()
	if guess != expected {
		test.Errorf("Incorrect guess result: %s, want: %s.", guess, expected)
	}
}

func TestProb5(test *testing.T) {
	const message = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
	const key = "ICE"
	const expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20690a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	encoded := prob5(message, key)
	if encoded != expected {
		test.Errorf("Incorrect encoded result: %s, want: %s.", encoded, expected)
	}
}

func verifyPrefixAndLength(str string, prefix string, length int, test *testing.T) {
	if !strings.HasPrefix(str, prefix) {
		test.Errorf("Incorrect result: prefix %s, want: %s.", str[:len(prefix)], prefix)
	}
	if len(str) != length {
		test.Errorf("Incorrect result: length %d, want: %d.", len(str), length)
	}
}

func TestProb6(test *testing.T) {
	const expected = "Terminator X: Bring the noise"
	const prefix = "I'm back and I'm ringin' the bell"
	const length = 2876
	guess, decoded := prob6()
	if guess != expected {
		test.Errorf("Incorrect key: %s, want: %s.", guess, expected)
	}
	verifyPrefixAndLength(decoded, prefix, length, test)
}

func TestProb7(test *testing.T) {
	const prefix = "I'm back and I'm ringin' the bell"
	const length = 2880
	decrypted := prob7("YELLOW SUBMARINE", 16)
	verifyPrefixAndLength(decrypted, prefix, length, test)
}

func TestProb8(test *testing.T) {
	const prefix = "d880619740a8a19b7840a8"
	found := prob8()
	if !strings.HasPrefix(found, prefix) {
		test.Errorf("Incorrect result: prefix %s, want: %s.", found[:len(prefix)], prefix)
	}
}
