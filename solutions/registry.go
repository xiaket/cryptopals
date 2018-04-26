package solutions

import "../lib"

var (
	mapper = map[string]interface{}{
		"1": Prob1,
		"2": Prob2,
		"3": Prob3,
		"4": Prob4,
		"5": Prob5,
		"6": Prob6,
	}
	Registry = cryptopals.NewFuncs(64, mapper)
)
