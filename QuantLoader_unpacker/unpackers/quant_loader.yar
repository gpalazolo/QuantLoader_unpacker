rule QuantLoader_v14x
{
    meta:
        description = "This rule is for QuantLoader version 1.4x"
        in_the_wild = true
    strings:
        $ql0 = {6F 65 75 68 66 67 6F 38 61 73 64 66}
        $ql1 = {61 6F 69 73 79 64 74 66 67 ?? 61 38 73 75 64 79 69 67 68 66}
        $ql2 = {61 6F 69 73 79 64 67 66 6F 61 69 75 73 64 67 66 69 6F 70 61 73 64}
    condition:
        2 of ($ql*)
}

rule QuantLoader_v15x
{
    meta:
        description = "This rule is for QuantLoader version 1.5x"
        in_the_wild = true
    strings:
        $ql0 = {6A 65 63 65 67 6F 6E 6F 7A 6F 74 75 67 6F 7A 61 74 65 62 61 6B 6F 74 69}
        $ql1 = {63 6F 74 75 77 6F 6B 65 7A 65 68 75 6C 6F 72 6F 76 75 63 75 74 69 62 61 77 75}
        $ql2 = {79 75 6E 69 6D 69 7A 6F 73 69 6C 69 79 65 64 61 6D 69 6A 65 70 65 6E 6F 78 6F 78 6F 63 61 76 65}
        $ql3 = {76 6F 6E 65 77 69 78 6F 6E 75 6C 75 74 69 63 61 7A 6F 79 75 67 61 67 75 67 61 77 6F}
        $ql4 = {66 65 79 65 6B 61 ?? 74 65 63 6F 79 65 68 6F 6B 61 7A 61 70 69 78 61 6E 6F 6D 69 78 6F 68 61}
    condition:
        2 of ($ql*)
}
