rule Vanhelsing_ransomware
{
    meta:
        author="5kidRo0t"
        sha256="83badb448a7575b661deb122871d2340604c4ead3f95ed25bcdf6cdbe58e319c"
        sha512="fb716635e47ec4476dbd306e7a61f834cab477942de8ba842deef22af82655132aa8f00edd489e010731f5f19a5b667a72693495b747e5c3a50da0f7e7ec5012"
    strings:
        $s1="Wow64DisableWow64FsRedirection" nocase
        $s2="vanhelcbxqt4tqie6fuevfng2bsdtxgc7xslo2yo7nitaacdfrlpxnqd.onion" nocase
        $s3="vanhelqmjstkvlhrjwzgjzpq422iku6wlggiz5y5r3rmfdeiaj3ljaid.onion" nocase
        $s4="vanhelsokskrlaacilyfmtuqqa5haikubsjaokw47f3pt3uoivh6cgad.onion" nocase
        $s5="vanheltarnbfjhuvggbncniap56dscnzz5yf6yjmxqivqmb5r2gmllad.onion" nocase
        $s6="vanhelvuuo4k3xsiq626zkqvp6kobc2abry5wowxqysibmqs5yjh4uqd.onion" nocase
        $s7="vanhelwmbf2bwzw7gmseg36qqm4ekc5uuhqbsew4eihzcahyq7sukzad.onion" nocase
        $s8="vanhelxjo52qr2ixcmtjayqqrcodkuh36n7uq7q7xj23ggotyr3y72yd.onion" nocase
        $s9="ca11d09d4d234ab8c9a9260c0905a421"
        $s10="VanHelsingLocker"
        $s11="9fa06f2f771a6559d473fd9ba303bb83e3a3c63c1dba4e3060ddc1cbf2613e20"
    condition:
        6 of them
}
