package solutions

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

func TestProb3(test *testing.T) {
	const message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	const expected = "Cooking MC's like a pound of bacon"
	guess := prob3(message)
	if guess != expected {
		test.Errorf("Incorrect guess result: %s, want: %s.", guess, expected)
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
