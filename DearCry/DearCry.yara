import "pe"
rule DearCry_malware
{
	meta:
		author = "5kidRo0t"
		description = "Detecta esta muestra específica (o binarios casi idénticos) de DearCry que incluyen OpenSSL EC + scrypt + Camellia + tabla Base64 con imphash f8b8e20e844ccd50a8eb73c2fca3626d"
		date = "2025-10-30"
		tags = "ransomware, libcrypto, openssl, ec, camellia, scrypt"

	strings:
		$ec1="pkey_ec_keygen" ascii
		$ec2="EC_POINT_oct2point" ascii
		$ec3="o2i_ECPublicKey" ascii
		$nist256="nistp256_pre_comp_new" ascii
		$scrypt="scrypt" ascii
		$cam256="camellia256" ascii
		$cam192="camellia192" ascii
		$cam128="camellia128" ascii
		$base64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii

	condition:
		uint16(0) == 0x5A4D and 
		(
			(1 of ($ec1, $ec2, $ec3, $nist256)) and
			$scrypt and
			(1 of ($cam256, $cam192, $cam128)) and
			$base64
		) and (pe.imphash() == "f8b8e20e844ccd50a8eb73c2fca3626d")
}
