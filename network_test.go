//go:build windows
// +build windows

package windowsnetworkinfo

import (
	"testing"
)

func TestSpecificUnexistantIntefaceInfo(t *testing.T) {
	//this GUID should not exists, so an error is expected
	ni := NewNetworkInfo()
	_, err := ni.GetAdaptersInfo(NICSearchFilterGUID("{??-3A1C-42FB-9E5C-0C2C440AB463}"))
	if err == nil {
		t.Fatal("This call should exit whith error")
	}
	t.Log(err)

}

func TestAdaptersInfo(t *testing.T) {
	ni := NewNetworkInfo()
	adapters, err := ni.GetAdaptersInfo(nil)
	if err != nil {
		t.Fatal(err)
	}
	var b []byte
	b, err = adapters.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(b))
}

func TestSpecificAdapterInfoFromGUID(t *testing.T) {
	//Gets this specific network interface (GUID) {6ABE2201-1694-4D6A-9B93-5CCD136E68D0} - change it accordingly
	ni := NewNetworkInfo()
	adapters, err := ni.GetAdaptersInfo(NICSearchFilterGUID("{6ABE2201-1694-4D6A-9B93-5CCD136E68D0}"))
	if err != nil {
		t.Fatal(err)
	}
	var b []byte
	b, err = adapters.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(b))
}

func TestSpecificAdapterInfoFromIndex(t *testing.T) {
	//Gets network interface with index 14 - change it accordingly
	ni := NewNetworkInfo()
	adapters, err := ni.GetAdaptersInfo(NICSearchFilterID(14))
	if err != nil {
		t.Fatal(err)
	}
	var b []byte
	b, err = adapters.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(b))
}

func TestWifiAdapters(t *testing.T) {
	//Gets only WiFi interfaces
	ni := NewNetworkInfo()
	adapters, err := ni.GetAdaptersInfo(NicType(NIC_WIRELESS802_11))
	if err != nil {
		t.Fatal(err)
	}
	var b []byte
	b, err = adapters.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(b))
}

func TestMoreFilters(t *testing.T) {
	//Gets only WiFi interfaces + index 14
	ni := NewNetworkInfo()
	adapters, err := ni.GetAdaptersInfo(NicType(NIC_WIRELESS802_11), NICSearchFilterID(14))
	if err != nil {
		t.Fatal(err)
	}
	var b []byte
	b, err = adapters.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(b))
}