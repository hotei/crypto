package threefish

type Tweak [2]uint64

const debugThreefish = false

func mix(in0, in1 uint64, rot uint) (out0, out1 uint64) {
	return in0 + in1, in1<<rot | in1>>(64-rot) ^ (in0 + in1)
}

func encrypt512(tweak Tweak, key, state []uint64) {
	const C240 uint64 = 0x1bd11bdaa9fc1a22

	const KeySize = 512
	const Rounds = 72
	const Words = KeySize / 64

	if debugThreefish {
		debugf(":Threefish-%d:  encryption + plaintext feedforward (round-by-round):", KeySize)
		debugf("  Tweak:")
		debugWords(tweak[:])
		debugf("  Key words:")
		debugWords(key)
	}

	var RotationSchedule = [8][4]uint{ // [round][wordpair]
		{46, 36, 19, 37},
		{33, 27, 11, 42},
		{17, 49, 36, 39},
		{44, 9, 54, 56},
		{39, 30, 34, 24},
		{13, 50, 10, 17},
		{25, 29, 39, 43},
		{8, 35, 56, 22},
	}

	if debugThreefish {
		if got, want := len(key), Words; got != want {
			panicf("key size = %v, want %v", got, want)
		}
		if got, want := len(state), Words; got != want {
			panicf("state size = %v, want %v", got, want)
		}
	}

	// Compute the extended tweak
	tweakx := [3]uint64{tweak[0], tweak[1], tweak[0]^tweak[1]}

	// Compute the extended key
	knw := C240
	for _, ki := range key {
		knw ^= ki
	}
	keyx := [9]uint64{}
	keyx[copy(keyx[:], key)] = knw

	// TODO(kevlar): Everything above this line can be precomputed when used in Skein

	// Compute the subkeys
	var subkeys [Rounds/4 + 1][Words]uint64
	for s := range subkeys {
		for i := range subkeys[s] {
			switch i {
			default:
				subkeys[s][i] = keyx[(s+i)%(Words+1)]
			case Words - 3:
				subkeys[s][i] = keyx[(s+i)%(Words+1)] + tweakx[s%3]
			case Words - 2:
				subkeys[s][i] = keyx[(s+i)%(Words+1)] + tweakx[(s+1)%3]
			case Words - 1:
				subkeys[s][i] = keyx[(s+i)%(Words+1)] + uint64(s)
			}
		}
	}

	if debugThreefish {
		debugf("  Tweak schedule:")
		debugWords(tweakx[:])
		debugf("  Key   schedule:")
		debugWords(keyx[:])
		debugf("  Input block (words):")
		debugWords(state)
		debugf("")
	}

	// TODO(kevlar): Everything above this line can be precomputed when used to 3F lots of data

	// Perform the requisite number of rounds
	for round := 0; round < Rounds; round++ {
		// Add in the subkeys
		if round%4 == 0 {
			subkey := subkeys[round/4]
			for i := range state {
				state[i] += subkey[i]
			}
			if debugThreefish {
				rtext := sprintf("key injection #%02d", round/4)
				if round == 0 {
					rtext = "initial key injection"
				}
				debugf(":Threefish-%d:  [state after %s]=", KeySize, rtext)
				debugWords(state)
				debugf("")
			}
		}

		// Mix word pairs
		for i := 0; i < Words; i += 2 {
			state[i], state[i+1] = mix(state[i], state[i+1], RotationSchedule[round%8][i/2])
		}

		if debugThreefish {
			rtext := sprintf("round %2d", round+1)
			debugf(":Threefish-%d:  [state after %s]=", KeySize, rtext)
			debugWords(state)
			debugf("")
		}

		// Shuffle
		state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7] =
			state[2], state[1], state[4], state[7], state[6], state[5], state[0], state[3]
	}

	// Add the final subkeys
	subkey := subkeys[Rounds/4]
	for i := range state {
		state[i] += subkey[i]
	}
}
