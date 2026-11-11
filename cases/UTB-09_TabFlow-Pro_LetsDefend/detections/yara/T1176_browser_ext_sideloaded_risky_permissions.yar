/*
   Source case: UTB-09 TabFlow Pro (LetsDefend)
   Author:      Kelvin Santos (@kelvinzdk)
   Date:        2026-11-11
   Status:      experimental
*/

rule SUSP_JSON_BrowserExt_Sideloaded_Risky_Permissions
{
    meta:
        description = "Extension manifest without update_url (not installed from a store or managed update server) requesting cookies, nativeMessaging and access to all sites"
        author      = "Kelvin Santos (@kelvinzdk)"
        date        = "2026-11-11"
        reference   = "https://github.com/zdr4k/DFIR-Field-Notes/tree/main/cases/UTB-09_TabFlow-Pro_LetsDefend"
        attack      = "T1176.001, T1539"
        scope       = "Scan manifests: C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Extensions\\*\\*\\manifest.json"
        note        = "Chrome adds update_url to extensions installed from the Web Store. Its absence means the package came from somewhere else. Developer builds of legitimate extensions will also match"

    strings:
        $manifest   = "\"manifest_version\"" ascii
        $update_url = "\"update_url\"" ascii

        $p_cookies  = "\"cookies\"" ascii
        $p_native   = "\"nativeMessaging\"" ascii
        $p_allurls  = "\"<all_urls>\"" ascii

        $p_webreq   = "\"webRequest\"" ascii
        $p_bdata    = "\"browsingData\"" ascii
        $p_history  = "\"history\"" ascii

    condition:
        filesize < 64KB
        and $manifest
        and not $update_url
        and $p_cookies and $p_native and $p_allurls
        and 1 of ($p_webreq, $p_bdata, $p_history)
}
