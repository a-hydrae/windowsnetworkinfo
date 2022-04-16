# windowsnetworkinfo
## Retrives Windows system networking cards informations, wifi profiles and passwords.

Tested on Windows 11, should be compatible at least from Windows 7.

#######

See network_test.go for more example.

How to use in your project:

```

import (
    ninfo "github.com/a-hydrae/windowsnetworkinfo"
    . "github.com/a-hydrae/windowsnetworkinfo/pkg"
)
ni := ninfo.NewNetworkInfo()
if adaptersInfo, err := ni.GetAdaptersInfo(NicType(NIC_WIRELESS802_11)); err == nil {
    for _, adptr := range adaptersInfo.Adapters {
        .....
    }
}

```

OR

```
import (
    ninfo "github.com/a-hydrae/windowsnetworkinfo"
    . "github.com/a-hydrae/windowsnetworkinfo/pkg"
)
ni := ninfo.NewNetworkInfo()
if adaptersInfo, err := ni.GetAdaptersInfo(NicType(NIC_WIRELESS802_11)); err == nil {
    fmt.Println(adaptersInfo.ToJSON())
}
```

Don't forget CGO_ENABLED=1