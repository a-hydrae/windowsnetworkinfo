//go:build windows
// +build windows

package pkg

import (
	"encoding/hex"
	"fmt"
	"regexp"	
	"unicode/utf16"
	"unsafe"
)

func UTF16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}

	length := UnicodeStrLen(p)
	a := make([]uint16, length)

	ptr := unsafe.Pointer(p)

	for i := 0; i < int(length); i++ {
		a[i] = *(*uint16)(ptr)
		ptr = unsafe.Pointer(uintptr(ptr) + 2)
	}

	return string(utf16.Decode(a))
}

func UnicodeStrLen(p *uint16) (length int64) {
	if p == nil {
		return 0
	}

	ptr := unsafe.Pointer(p)

	for i := 0; ; i++ {
		if 0 == *(*uint16)(ptr) {
			length = int64(i)
			break
		}
		ptr = unsafe.Pointer(uintptr(ptr) + 2)
	}
	return
}

func GetMatchesGroupMultiLine(matches [][]string, re *regexp.Regexp) (ret []map[string]string) {
	m := len(matches)
	ret = make([]map[string]string, 0, 3)
	if m > 0 {
		for i := 0; i < m; i++ {
			for j, name := range re.SubexpNames() {
				mEl := map[string]string{}
				if j != 0 && name != "" && matches[i][j] != "" {
					mEl[name] = matches[i][j]
					ret = append(ret, mEl)
				}
			}
		}
	}
	return
}

func IsBufferValid(buff *byte) (ret bool) {
	ret = false
	if buff != nil {
		if *buff != 0x0 {
			ret = true
		}
	}
	return
}

func MacAddressToString(buff []byte) (ret string) {
	if len(buff) > 0 {
		if !IsBufferValid(&buff[0]) {
			return
		}
		for i, b := range buff {
			if b != 0x0 {
				if i == 0 {
					ret = hex.EncodeToString([]byte{b})
				} else {
					ret = fmt.Sprintf("%s:%s", ret, hex.EncodeToString([]byte{b}))
				}
			}
		}
	}
	return
}

func BufferToString(buff []byte) (ret string) {
	if len(buff) > 0 {
		if !IsBufferValid(&buff[0]) {
			return
		}
		for _, b := range buff {
			if b == 0x0 {
				return
			}
			ret = ret + string(b)
		}
	}
	return
}

func Itob(i int) bool {
	if i == 1 {
		return true
	} else {
		return false
	}
}