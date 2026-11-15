import "hash"

rule WARDENStealer_malware
{
    meta:
        author = "5kidRo0t"
        description = "Exact malware sample identification"
        filename = "6f4ccc1718eddb12fab554f0c19e908f0486fd734bb02c706534ad92860d5df2.exe"
        malware_name = "WARDENStealer"
        md5 = "5fff315917c102d44430d45cdb48c926"
        sha256 = "6f4ccc1718eddb12fab554f0c19e908f0486fd734bb02c706534ad92860d5df2"
        sha512 = "d57b40096589e3045490fae3f631dc8029602d25ef2b90a8a4fa8dec803943bbd9e3979a168eadd551f52b3d07121d9f35368127b96c254c7339bbef4b262db0"

    condition:
        filesize == 720384 and
        hash.sha256(0, filesize) == "6f4ccc1718eddb12fab554f0c19e908f0486fd734bb02c706534ad92860d5df2"
}
