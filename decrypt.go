// Breaking the Vigenere Cipher (XOR Variant)

package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"sort"
)

const (
	englishCorpus string = "./corpus.txt"
)

type Frequencies struct {
	freq         map[byte]float32
	ss           float32
	chars        []byte
	invalidChars bool
}

func (f *Frequencies) run(chars []byte) {
	f.invalidChars = false
	f.chars = chars
	f.freq = make(map[byte]float32)
	f.countChars()
	f.sumOfSquares()
}

func (f *Frequencies) sumOfSquares() {
	var total float32 = 0.00
	for _, value := range f.freq {
		total = total + (value * value)
	}
	f.ss = total
}

func (f *Frequencies) countChars() {
	for _, c := range f.chars {
		f.freq[byte(c)] = f.freq[byte(c)] + float32(1)/float32(len(f.chars))
		if !isAllowed(c) {
			f.invalidChars = true
		}
	}
}

func (f *Frequencies) dump() {
	keys := make([]string, 0, len(f.freq))
	for k := range f.freq {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)

	for _, k := range keys {
		fmt.Printf("%s (%#.2x): %v\n", string(byte(k[0])), byte(k[0]), f.freq[byte(k[0])])
	}
}

func isIn(x byte, y []byte) bool {
	for _, b := range y {
		if b == x {
			return true
		}
	}
	return false
}

func allowedChars() []byte {
	var chars []byte
	for i := 32; i < 127; i++ {
		chars = append(chars, byte(i))
	}
	return chars
}

func allChars() []byte {
	var chars []byte
	for i := 0; i < 256; i++ {
		chars = append(chars, byte(i))
	}

	return chars
}

func isAllowed(x byte) bool {
	return isIn(x, allowedChars())
}

func everyOtherN(cText []byte, n int, offset int) []byte {
	var out []byte = nil
	for i, c := range cText {
		if (i-offset)%n == 0 {
			out = append(out, c)
		}
	}
	return out
}

func findN(cText []byte, min int, max int) int {
	freqs := make(map[int]*Frequencies)
	for i := min; i <= max; i++ {
		var tmp Frequencies
		tmp.run(everyOtherN(cText, i, i))
		tmp.countChars()
		freqs[i] = &tmp
	}

	var bestValue float32 = 0.00
	var bestIndex int

	for i, f := range freqs {
		if f.ss > bestValue {
			bestValue = f.ss
			bestIndex = i
		}
	}

	return bestIndex
}

func encrypt(pText []byte, key []byte) []byte {
	var cText []byte
	for i := 0; i < len(pText); i++ {
		cText = append(cText, pText[i]^key[i%len(key)])
	}

	return cText
}

func decrypt(cText []byte, key []byte) []byte {
	var pText []byte
	for i := 0; i < len(cText); i++ {
		c := cText[i] ^ key[i%len(key)]
		if isAllowed(c) {
			pText = append(pText, c)
		}
	}
	return pText
}

func getCorpusFrequencies(filepath string) *Frequencies {
	file, err := os.Open(filepath)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanBytes)

	var bytes []byte

	for scanner.Scan() {
		bytes = append(bytes, scanner.Bytes()[0])
	}

	var f Frequencies
	f.run(bytes)

	return &f
}

func sumOfSquares(f1 *Frequencies, f2 *Frequencies) float32 {
	var total float32
	for _, c := range allChars() {
		f1f := f1.freq[byte(c)]
		f2f := f2.freq[byte(c)]
		total += f1f * f2f
	}
	return total
}

func findKey(cText []byte, min int, max int) []byte {
	english := getCorpusFrequencies(englishCorpus)
	n := findN(cText, min, max)
	var key []byte
	for i := 0; i < n; i++ {
		var bestSS float32
		var bestByte byte
		eon := everyOtherN(cText, n, i)
		for _, b := range allChars() {
			deon := decrypt(eon, []byte{byte(b)})
			var f Frequencies
			f.run(deon)
			if f.invalidChars {
				continue
			}
			ss := sumOfSquares(english, &f)
			if ss > bestSS {
				bestSS = ss
				bestByte = byte(b)
			}

		}
		key = append(key, bestByte)
	}
	return key
}

func hexStringToBytes(s string) []byte {
	// Convert the string given for the programming assignment to bytes
	a, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	return a
}

func getAssignmentCipher(filepath string) []byte {
	file, err := os.Open(filepath)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	scanner.Scan()
	cipher := scanner.Text() // Should be the first and only line of the file

	return hexStringToBytes(cipher)
}

func decodeFile(filename string, min int, max int) {
	cText := getAssignmentCipher(filename)
	key := findKey(cText, min, max)
	fmt.Printf("KEY: %# x | \"%s\"\n", key, string(key))
	fmt.Println(string(decrypt(cText, key)))
}

func main() {
	decodeFile("./test-assignment.txt", 6, 14)
	decodeFile("./assignment.txt", 2, 13)
}
