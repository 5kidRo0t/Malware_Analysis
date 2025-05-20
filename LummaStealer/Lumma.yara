import "pe"

rule Lumma_malware_imphash
{
	meta:
		author="5kidRo0t"
		reference = "https://www.hybrid-analysis.com/search?query=imphash%3A%22bf95d1fc1d10de18b32654b123ad5e1f%22"
		sha256_lumma_1="dcb7ce8cf51da4997489814f1ea6a877b97b4d0fcd28d6c89d8f9f363ab17abd"
		sha512_lumma_1="d26208ff6e9dc65612f0e7ca7d5b3ecf8ee56a5f8c31a30679a79c5f72ee7b6a355257c65ab01c931e4c7597cff717a657c3bb76dd15c4a4e2ef12eeeaefb836"
		sha256_lumma_2="b58ea28950ba3c0b5b67cf3b62a60c4ba8a2ada384540ccd0d90c5d9a77ec230"
		sha512_lumma_2="c124878e6a1add26bdd6571af86b48881a5808344a622fe02f272b60c38a8c8beea13de7175fcaada58d9e7922d8c3fbec607440b60f3fb5dbb38c7607baa3b8"
	condition:
		pe.imphash() == "bf95d1fc1d10de18b32654b123ad5e1f"
}
