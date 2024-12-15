rule PysilonStealer : malware {
    meta:
        name        = "PysilonStealer"
        category    = "stealer"
        description = "Pysilon Stealer Rule Match"
        author      = "remiliacn"
        created     = "2024-12-08"
        reliability = 60
    strings:
        $pys1 = ".pysilon"
		$pys2 = "\\PySilon.key"
		$pys3 = "source_prepared"
        $uac_bypass = "resources.uac_bypass"
        $discord_token_grabber = "resources.discord_token_grabber"
    condition:
        ($pys1 or $pys2) or $pys3 or ($uac_bypass and $discord_token_grabber)
}

rule LunaGrabber : malware {
    meta:
        name        = "LunaGrabber"
        category    = "stealer"
        description = "Matches Luna Grabber Rule"
        author      = "remiliacn"
        created     = "2024-12-12"
        reliability = 70
        tlp         = "TLP:amber"

    strings:
        $weird_lines = /(_{8,}..){4,}/
		$decode = "decode"
		$eval = "eval"

    condition:
        all of them
}

rule AmnesiaStealer: malware {
    meta:
        name        = "AmnesiaStealer"
        category    = "stealer"
        description = "Match AmnesiaStealer"
        author      = "remiliacn"
        created     = "2024-12-11"
        reliability = 70
        tlp         = "TLP:red"

    strings:
        $ = "bBuild.exe" wide
		$ = "load PyInstaller"

    condition:
        all of them
}

rule ExelaStealer : malware {
    meta:
        name        = "ExelaStealer"
        category    = "stealer"
        description = "Match ExelaStealer"
        author      = "remiliacn"
        created     = "2024-12-11"
        reliability = 70
        tlp         = "TLP:red"

    strings:
        $ = "Exela Services" wide
		$ = "load PyInstaller"

    condition:
        all of them
}


rule BlankGrabber : malware {
    meta:
        name        = "BlankGrabber"
        category    = "stealer"
        description = "Blank Grabber Match Rule"
        author      = "remiliacn"
        created     = "2024-12-11"
        reliability = 60
        tlp         = "TLP:red"
        sample      = "5f738f6406c2f1944dbdd78001b4fbba317df530efcbdb5a2ac914370c9ea39c"

    strings:
        $ = /b+lank\.aes/
		$ = "load PyInstaller"

    condition:
        all of them
}

rule RayxStealer : malware {
    meta:
        name        = "RayxStealer"
        category    = "library"
        description = "Suspicious use of notoken library"
        author      = "remiliacn"
        created     = "2024-12-09"
        reliability = 80

    strings:
        $ = /notoken\d+\.\w+/i

    condition:
        any of them
}
