package main

func ContainsAnyFold(str []byte, patterns [][]byte) bool {
	var (
		mask   [4]uint64
		hasPat bool
	)

	for _, pat := range patterns {
		if len(pat) == 0 {
			return true
		}

		c := pat[0]
		if c-'A' < 26 {
			c |= 0x20
		}

		mask[c>>6] |= 1 << (c & 63)

		hasPat = true
	}

	if !hasPat {
		return false
	}

	for i := 0; i < len(str); i++ {
		c := str[i]
		if c-'A' < 26 {
			c |= 0x20
		}

		if mask[c>>6]&(1<<(c&63)) == 0 {
			continue
		}

		rem := str[i:]

		for _, pat := range patterns {
			if len(pat) > len(rem) {
				continue
			}

			p0 := pat[0]
			if p0-'A' < 26 {
				p0 |= 0x20
			}

			if p0 != c {
				continue
			}

			if matchRest(rem, pat) {
				return true
			}
		}
	}

	return false
}

func matchRest(s, pat []byte) bool {
	// BCE
	_ = s[len(pat)-1]
	_ = pat[len(pat)-1]

	for i := 1; i < len(pat); i++ {
		si := s[i]
		pi := pat[i]

		if si == pi {
			continue
		}

		if (si ^ pi) == 0x20 {
			lower := si | 0x20
			if 'a' <= lower && lower <= 'z' {
				continue
			}
		}

		return false
	}

	return true
}
