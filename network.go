//go:build windows
// +build windows

package windowsnetworkinfo

/*
#include <windows.h>
#include <wlanapi.h>

LPWSTR wlanGetProfileWrap(HANDLE cHandle, const GUID *pInterfaceGuid, LPCWSTR strProfileName) {
	LPWSTR ret = NULL;
	DWORD flags = 0x4;
	DWORD fRet = WlanGetProfile(cHandle, pInterfaceGuid, strProfileName, NULL, &ret, &flags, 0);
	if (fRet == ERROR_SUCCESS) {
		return ret;
	}
	return NULL;
}
*/
// #cgo LDFLAGS: -lwlanapi -Wl,--allow-multiple-definition
// #cgo CFLAGS: -DNDEBUG
import "C"
import (
	"encoding/json"
	"fmt"
	"regexp"
	"syscall"
	"time"
	"unsafe"

	"github.com/a-hydrae/windowsnetworkinfo/pkg"
	"golang.org/x/sys/windows"
)

var (
	iphlpapi				=		syscall.NewLazyDLL("Iphlpapi.dll")
	getAdaptersInfoProc		=		iphlpapi.NewProc("GetAdaptersInfo")
	wlanapi            		= 		syscall.NewLazyDLL("Wlanapi.dll")
	wlanOpenHandleProc 		= 		wlanapi.NewProc("WlanOpenHandle")
	wlanCloseHandleProc   	= 		wlanapi.NewProc("WlanCloseHandle")
	wlanGetProfileListProc 	= 		wlanapi.NewProc("WlanGetProfileList")
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

type wiFiProfile struct {
	ProfileName			string
	Password			string
}

type AdaptersInfo struct {
	Adapters		map[string]AdapterInfo
}

type AdapterInfo struct {
	AdapterName				string
	Description				string	
	MacAddress				string
	Type					string
	CurrentIPAddress		[]string
	IpAddressList			[]string
	GatewayAddressList		[]string
	DhcpServerList			[]string
	PrimaryWinsServer		[]string
	SecondaryWinsServer		[]string
	WiFiProfiles			[]wiFiProfile
	LeaseObtained			string
	LeaseExpires			string
	Index					int32
	ComboIndex				int32
	HaveWins				bool
	DhcpEnabled				bool
}

type vAddress struct {
	String		[16]byte
}

type ipAddressString struct {
	Next		*ipAddressString
	IpAddress	vAddress
	IpMask		vAddress
	Context		int32
}

type ipAdapterInfo struct {
  Next					*ipAdapterInfo
  ComboIndex			int32
  AdapterName			[MAX_ADAPTER_NAME_LENGTH+4]byte
  Description			[MAX_ADAPTER_DESCRIPTION_LENGTH+4]byte
  AddressLength			uint32
  Address				[MAX_ADAPTER_ADDRESS_LENGTH]byte
  Index					int32
  Type					NicType
  DhcpEnabled			uint32
  CurrentIpAddess		*ipAddressString
  IpAddressList			ipAddressString
  GatewayList			ipAddressString
  DhcpServer			ipAddressString
  HaveWins				bool
  PrimaryWinsServer		ipAddressString
  SecondaryWinsServer	ipAddressString
  LeaseObtained			int64
  LeaseExpires			int64
}

type NetworkInfo struct {}

func NewNetworkInfo() *NetworkInfo {return &NetworkInfo{}}

//GetAdaptersInfo returns network interfaces. Can be filtered (logic are in AND) using GUID, ID and NIC typo
func (NI *NetworkInfo) GetAdaptersInfo(filters ...interface{}) (ret AdaptersInfo, err error){
	adapters := map[string]AdapterInfo{}
	buffSize := uint64(0)
	r0, _, _ := getAdaptersInfoProc.Call(uintptr(0), uintptr(unsafe.Pointer(&buffSize)))
	err = syscall.Errno(r0)
	if err == ERROR_BUFFER_OVERFLOW {
		buffer := make([]byte, buffSize)
		r0, _, _ = getAdaptersInfoProc.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&buffSize)))
		err = syscall.Errno(r0)
		if err == ERROR_SUCCESS {
			err = nil
			guidFilters := make([]string, 0)
			idFilters := make([]int, 0)
			nTypes := make([]NICFilterType, 0)
			if filters != nil {
				if len(filters) > 0 {
					for _, f := range filters {
						switch t:=f.(type) {
						case NICSearchFilterGUID:
							guidFilters = append(guidFilters, string(t))

						case NICSearchFilterID:
							idFilters = append(idFilters, int(t))

						case NicType:
							nTypes = append(nTypes, NICFilterType(t))
						}
					}
				}
			}
			wlanHandle := NI.wlanOpenHandle()
			if wlanHandle > 0 {
				defer func() {
					NI.wlanCloseHandle(wlanHandle)
				}()
			}
			for currentAdapterInfo := (*ipAdapterInfo)(unsafe.Pointer(&buffer[0])); currentAdapterInfo != nil; currentAdapterInfo = currentAdapterInfo.Next {
				canAdd := false
				guidFilter := false
				idFilter := false
				typeFilter := false
				if filters == nil {
					canAdd = true
				} else {
					if len(guidFilters) == 0 && len(idFilters) == 0 && len(nTypes) == 0 {
						canAdd = true
					}
				}
				guid := pkg.BufferToString(currentAdapterInfo.AdapterName[:])
				if !canAdd {
					if len(guidFilters) == 0 {
						guidFilter = true
					}
					for _, gf := range guidFilters {
						if guid == string(gf) {
							guidFilter = true
							break
						}
					}
					if len(idFilters) == 0 {
						idFilter = true
					}
					for _, idF := range idFilters {
						if int32(idF) == currentAdapterInfo.Index {
							idFilter = true
							break
						}
					}
					if len(nTypes) == 0 {
						typeFilter = true
					}
					for _, nT := range nTypes {
						if nT == NICFilterType(currentAdapterInfo.Type) {
							typeFilter = true
							break
						}
					}
					if guidFilter && idFilter && typeFilter {
						canAdd = true
					}
				}

				if canAdd {
					aInfo := NI.ipAdapterInfoToAdapterInfo(currentAdapterInfo)					
					if wlanHandle > 0 {			
						var wg windows.GUID	
						if wg, err = windows.GUIDFromString(aInfo.AdapterName); err != nil {									
							return
						}		
						type WlanProfileInfo struct {
							ProfileName [256]uint16
							Flags       uint32
						}
						type WlanProfileInfoList struct {
							NumOfItems  uint32
							Index       uint32
							ProfileInfo [1001]WlanProfileInfo
						}
						wpl := &WlanProfileInfoList{}
						r0, _, _ := wlanGetProfileListProc.Call(wlanHandle, uintptr(unsafe.Pointer(&wg)), 0, uintptr(unsafe.Pointer(&wpl)))
						if r0 == 0 {
							for i := uint32(0); i < wpl.NumOfItems; i++ {
								pInfo := wpl.ProfileInfo[i]
								wifiPro := wiFiProfile{ProfileName: syscall.UTF16ToString(pInfo.ProfileName[:])}
								prfNameUtfPtr, uErr := syscall.UTF16PtrFromString(wifiPro.ProfileName)
								if uErr == nil {						
									wifiPro.Password = NI.wlanGetProfilePassword(wlanHandle, &wg, prfNameUtfPtr)
								}
								aInfo.WiFiProfiles = append(aInfo.WiFiProfiles, wifiPro)
							}
						}
					}
					adapters[guid] = aInfo
				}
			}
		}
	}
	if len(adapters) == 0 {
		err = fmt.Errorf("no interface found")
	}
	ret.Adapters = adapters
	return
}

func (NI *NetworkInfo) wlanOpenHandle() (handle uintptr) {
	handle = 0
	curVer := uint32(0)
	hClient := uintptr(0)
	ret, _, _ := wlanOpenHandleProc.Call(uintptr(2), uintptr(0), uintptr(unsafe.Pointer(&curVer)),
		uintptr(unsafe.Pointer(&hClient)))
	if ret == 0 {
		return hClient
	}
	return
}

func (NI *NetworkInfo) wlanCloseHandle(h uintptr) {
	_, _, _ = wlanCloseHandleProc.Call(h, uintptr(0))
}

func (NI *NetworkInfo) wlanGetProfile(clientHandle uintptr, guidProfileIntf *windows.GUID, profileName *uint16) (ret string) {
	ptrStr := C.wlanGetProfileWrap((C.HANDLE)(clientHandle), (*C.GUID)(unsafe.Pointer(guidProfileIntf)), (*C.WCHAR)(profileName))
	if ptrStr != nil {
		utf16Str := (*uint16)(unsafe.Pointer(ptrStr))
		ret = pkg.UTF16PtrToString(utf16Str)
	}
	return
}

func (NI *NetworkInfo) wlanGetProfilePassword(wlanHandle uintptr, intfGUID *windows.GUID, profileName *uint16) (ret string) {
	profileXML := NI.wlanGetProfile(wlanHandle, intfGUID, profileName)
	re, err := regexp.Compile(`(?:<keyMaterial>)(?P<key>.+)(?:<\/keyMaterial>)`)
	if err == nil {
		matches := re.FindAllStringSubmatch(profileXML, -1)
		if len(matches) > 0 {
			args := pkg.GetMatchesGroupMultiLine(matches, re)
			for _, arg := range args {
				if k, exists := arg["key"]; exists {
					ret = k
					break
				}
			}
		}
	}
	return
}

func (NI *NetworkInfo) ipAdapterInfoToAdapterInfo(ipA *ipAdapterInfo) (ret AdapterInfo) {
	if ipA != nil {
		ret.WiFiProfiles = make([]wiFiProfile, 0)
		ret.AdapterName = pkg.BufferToString(ipA.AdapterName[:])
		ret.Description = pkg.BufferToString(ipA.Description[:])
		ret.CurrentIPAddress = make([]string, 0)
		if ipA.CurrentIpAddess != nil {
			for ciA := ipA.CurrentIpAddess; ciA != nil; ciA = ipA.CurrentIpAddess.Next {
				ip := pkg.BufferToString(ipA.CurrentIpAddess.IpAddress.String[:])
				if ip != "" {
					ret.CurrentIPAddress = append(ret.CurrentIPAddress, ip)
				}
			}
		}
		ma := pkg.MacAddressToString(ipA.Address[:])
		if ma != "" {
			ret.MacAddress = ma
		}
		ret.Type = nicTypeConstToString(ipA.Type)
		ret.IpAddressList = make([]string, 0)
		ret.GatewayAddressList = make([]string, 0)
		ret.DhcpServerList = make([]string, 0)
		ret.PrimaryWinsServer = make([]string, 0)
		ret.SecondaryWinsServer = make([]string, 0)
		
		if pkg.IsBufferValid(&ipA.IpAddressList.IpAddress.String[0]) {
			for iA := &ipA.IpAddressList; iA != nil; iA = (*ipAddressString)(unsafe.Pointer(iA.Next)) {
				ip := pkg.BufferToString(iA.IpAddress.String[:])
				if ip != "" {
					ret.IpAddressList = append(ret.IpAddressList, ip)
				}
			}
		}
	
		if pkg.IsBufferValid(&ipA.GatewayList.IpAddress.String[0]) {
			for iA := &ipA.GatewayList; iA != nil; iA = (*ipAddressString)(unsafe.Pointer(iA.Next)) {
				ip := pkg.BufferToString(iA.IpAddress.String[:])
				if ip != "" {
					ret.GatewayAddressList = append(ret.GatewayAddressList, ip)
				}
			}
		}
	
		if pkg.IsBufferValid(&ipA.DhcpServer.IpAddress.String[0]) {
			for iA := &ipA.DhcpServer; iA != nil; iA = (*ipAddressString)(unsafe.Pointer(iA.Next)) {
				ip := pkg.BufferToString(iA.IpAddress.String[:])
				if ip != "" {
					ret.DhcpServerList = append(ret.DhcpServerList, ip)
				}
			}
		}
	
		if pkg.IsBufferValid(&ipA.PrimaryWinsServer.IpAddress.String[0]) {
			for iA := &ipA.PrimaryWinsServer; iA != nil; iA = (*ipAddressString)(unsafe.Pointer(iA.Next)) {
				ip := pkg.BufferToString(iA.IpAddress.String[:])
				if ip != "" {
					ret.PrimaryWinsServer = append(ret.PrimaryWinsServer, ip)
				}
			}
		}
	
		if pkg.IsBufferValid(&ipA.SecondaryWinsServer.IpAddress.String[0]) {
			for iA := &ipA.SecondaryWinsServer; iA != nil; iA = (*ipAddressString)(unsafe.Pointer(iA.Next)) {
				ip := pkg.BufferToString(iA.IpAddress.String[:])
				if ip != "" {
					ret.SecondaryWinsServer = append(ret.SecondaryWinsServer, ip)
				}
			}
		}
		if ipA.LeaseObtained > 0 {
			ret.LeaseObtained = time.Unix(ipA.LeaseObtained, 0).UTC().Format(MYSQL_TIME_FORMAT)
		}
		if ipA.LeaseExpires > 0 {
			ret.LeaseExpires = time.Unix(ipA.LeaseExpires, 0).UTC().Format(MYSQL_TIME_FORMAT)
		}
		ret.Index = ipA.Index
		ret.ComboIndex = ipA.ComboIndex
		ret.HaveWins = ipA.HaveWins
		ret.DhcpEnabled = pkg.Itob(int(ipA.DhcpEnabled))
	}
	return
}

func (AI AdaptersInfo) ToJSON() (ret []byte, err error) {
	ret, err = json.Marshal(AI.Adapters)
	return
}

func nicTypeConstToString(nType NicType) string {
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