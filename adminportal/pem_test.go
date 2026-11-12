package adminportal

import "encoding/pem"

func pemDecode(b []byte) ([]byte, []byte) {
	block, rest := pem.Decode(b)
	if block == nil {
		return nil, rest
	}
	return block.Bytes, rest
}
