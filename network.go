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
  AdapterName			[pkg.MAX_ADAPTER_NAME_LENGTH+4]byte
  Description			[pkg.MAX_ADAPTER_DESCRIPTION_LENGTH+4]byte
  AddressLength			uint32
  Address				[pkg.MAX_ADAPTER_ADDRESS_LENGTH]byte
  Index					int32
  Type					pkg.NicType
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
	if err == pkg.ERROR_BUFFER_OVERFLOW {
		buffer := make([]byte, buffSize)
		r0, _, _ = getAdaptersInfoProc.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&buffSize)))
		err = syscall.Errno(r0)
		if err == pkg.ERROR_SUCCESS {
			err = nil
			guidFilters := make([]string, 0)
			idFilters := make([]int, 0)
			nTypes := make([]pkg.NICFilterType, 0)
			if filters != nil {
				if len(filters) > 0 {
					for _, f := range filters {
						switch t:=f.(type) {
						case pkg.NICSearchFilterGUID:
							guidFilters = append(guidFilters, string(t))

						case pkg.NICSearchFilterID:
							idFilters = append(idFilters, int(t))

						case pkg.NicType:
							nTypes = append(nTypes, pkg.NICFilterType(t))
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
						if nT == pkg.NICFilterType(currentAdapterInfo.Type) {
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
		ret.Type = pkg.NICTypeConstToString(ipA.Type)
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
			ret.LeaseObtained = time.Unix(ipA.LeaseObtained, 0).UTC().Format(pkg.MYSQL_TIME_FORMAT)
		}
		if ipA.LeaseExpires > 0 {
			ret.LeaseExpires = time.Unix(ipA.LeaseExpires, 0).UTC().Format(pkg.MYSQL_TIME_FORMAT)
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