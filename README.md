# windowsnetworkinfo
## Retrives Windows system networking cards informations, wifi profiles and passwords.

Tested on Windows 11, should be compatible at least from Windows 7.

#######

See network_test.go for more example.

How to use in your project:

```

import (
    ninfo "github.com/a-hydrae/windowsnetworkinfo"
)
....
ni := ninfo.NewNetworkInfo()
if adaptersInfo, err := ni.GetAdaptersInfo(NicType(NIC_WIRELESS802_11)); err == nil {
    for _, adptr := range adaptersInfo.Adapters {
        fmt.Printf("WiFi Adapter: %s\n", adptr.AdapterName)
        fmt.Printf("IP: %v\n", adptr.IpAddressList)
        fmt.Printf("Profiles: %v\n", adptr.WiFiProfiles)
    }
}

```

OR

```
import (
    ninfo "github.com/a-hydrae/windowsnetworkinfo"
)
...
ni := ninfo.NewNetworkInfo()
if adaptersInfo, err := ni.GetAdaptersInfo(NicType(NIC_WIRELESS802_11)); err == nil {
    fmt.Println(adaptersInfo.ToJSON())
}
```

Don't forget CGO_ENABLED=1