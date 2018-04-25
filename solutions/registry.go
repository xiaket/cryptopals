package solutions

var Registry = map[int64]func(){
	1: Prob1,
	2: Prob2,
	3: Prob3,
	4: Prob4,
	5: Prob5,
	6: Prob6,
}
