//go:build windows
// +build windows

package pkg

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const (
	ERROR_BUFFER_OVERFLOW           syscall.Errno = 111
	ERROR_SUCCESS                   syscall.Errno = 0
)

const (
	MAX_ADAPTER_ADDRESS_LENGTH 		= 8
	MAX_ADAPTER_DESCRIPTION_LENGTH 	= 128
	MAX_ADAPTER_NAME_LENGTH 		= 256
	MAX_DOMAIN_NAME_LEN 			= 128
	MAX_HOSTNAME_LEN 				= 128
)

type NicType uint32

const (
	NIC_WIRELESS802_11		=		71
	NIC_ATMNETOWRK			=		28
	NIC_LOOPBACK			=		24
	NIC_PPP					=		23
	NIC_TOKENRING			=		9
	NIC_ETHERNET			=		6
)

const (
	ERROR_INVALID_PARAMETER		=	0x57
	MYSQL_TIME_FORMAT       	= "2006-01-02 15:04:05"
)

type NICSearchFilterGUID string
type NICSearchFilterID int
type NICFilterType NicType

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

func NICTypeConstToString(nType NicType) string {
	switch nType {
	case NIC_WIRELESS802_11:
		return "IEEE 802.11 wireless network interface"
	case NIC_ATMNETOWRK:
		return "ATM network interface"
	case NIC_LOOPBACK:
		return "loopback network interface"
	case  NIC_PPP:
		return "PPP network interface"
	case  NIC_TOKENRING:
		return "Token Ring network interface"
	case  NIC_ETHERNET:
		return "Ethernet network interface"
	default:
		return "Other network interface"
	}
}

func Itob(i int) bool {
	if i == 1 {
		return true
	} else {
		return false
	}
}