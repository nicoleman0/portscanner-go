package ports

// Top returns the first n commonly-used TCP ports.
func Top(n int) []int {
	if n <= 0 {
		n = 1
	}
	// Seed list: curated common TCP ports (no duplicates).
	seed := []int{
		80, 443, 22, 21, 25, 53, 110, 995, 143, 993,
		587, 465, 3306, 3389, 135, 139, 445, 8080, 8443, 5900,
		23, 8000, 1723, 111, 123, 500, 1433, 1521, 5432, 6379,
		27017, 11211, 389, 636, 554, 1720, 5060, 5061, 88, 1900,
		5353, 1025, 1026, 1027, 1028, 69, 161, 162, 5000, 5001,
		5985, 8081, 8082, 8083, 8444, 9000, 9090, 3128, 1080, 6667,
		7001, 7002, 8181, 8888, 8883, 2181, 2049, 4190, 10000, 25565,
		25575, 5901, 5902, 5903, 9200, 179, 631, 1524, 1434, 19,
		7, 13,
	}

	// Build the final list up to n by appending ascending port numbers
	// skipping duplicates, prioritizing well-known (<1024) first.
	// This avoids hardcoding a massive 1000-element list while ensuring
	// we expand sensibly for larger n.
	seen := make(map[int]struct{}, len(seed))
	list := make([]int, 0, n)
	for _, p := range seed {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			list = append(list, p)
			if len(list) >= n {
				return list
			}
		}
	}
	// Add remaining well-known ports 1-1024
	for p := 1; p <= 1024 && len(list) < n; p++ {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			list = append(list, p)
		}
	}
	// Then add higher ports ascending until we reach n
	for p := 1025; len(list) < n && p <= 65535; p++ {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			list = append(list, p)
		}
	}
	return list
}
