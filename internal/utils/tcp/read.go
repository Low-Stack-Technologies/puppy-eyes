package tcp

import (
	"bufio"
	"strings"
)

func ReadData(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	return strings.TrimSpace(line), err
}
