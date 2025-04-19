package relay

import (
	"testing"
)

func TestSplitBytes(t *testing.T) {
	assert := func(expected [][]byte, actual [][]byte) {
		if len(expected) != len(actual) {
			t.Errorf("Expected %d slices, got %d", len(expected), len(actual))
			return
		}
		for i := range expected {
			if len(expected[i]) != len(actual[i]) {
				t.Errorf("Expected slice %d to have length %d, got %d", i, len(expected[i]), len(actual[i]))
			}
			for j := range expected[i] {
				if expected[i][j] != actual[i][j] {
					t.Errorf("Expected slice %d at index %d to be %d, got %d", i, j, expected[i][j], actual[i][j])
				}
			}
		}
	}

	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	actual, err := splitBytes(data, 0)
	if err == nil {
		t.Errorf("Expected error for chunk size 0, got nil")
	}
	actual, _ = splitBytes(data, 1)
	assert([][]byte{{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}}, actual)
	actual, _ = splitBytes(data, 2)
	assert([][]byte{{0, 1}, {2, 3}, {4, 5}, {6, 7}, {8, 9}}, actual)
	actual, _ = splitBytes(data, 3)
	assert([][]byte{{0, 1, 2}, {3, 4, 5}, {6, 7, 8}, {9}}, actual)
	actual, _ = splitBytes(data, 4)
	assert([][]byte{{0, 1, 2, 3}, {4, 5, 6, 7}, {8, 9}}, actual)
	actual, _ = splitBytes(data, 5)
	assert([][]byte{{0, 1, 2, 3, 4}, {5, 6, 7, 8, 9}}, actual)

	// empty data
	data = []byte{}
	actual, err = splitBytes(data, 0)
	if err == nil {
		t.Errorf("Expected error for chunk size 0, got nil")
	}
	actual, _ = splitBytes(data, 1)
	assert([][]byte{}, actual)
}
