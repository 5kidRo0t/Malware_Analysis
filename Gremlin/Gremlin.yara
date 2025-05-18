rule Gremlin_malware
{
	meta:
		author="5kidRo0t"
		sha256="d1ea7576611623c6a4ad1990ffed562e8981a3aa209717065eddc5be37a76132"
		sha512="61ac46af46f94ebd6927079cbc23e59ba393ab2e29ba090da647413cc4b433d5e85aacb30e53e94c15c900b95c5a5ca43190deb7db047a53a58990de999f297f"
	strings:
		$s1="GetTelegramSessions"
		$s2="GetCookiesFromBrowser"
		$s3="7c11697d-caad-4bae-8b2a-0e331680a53b" nocase
		$s4="CefSharp.BrowsersSubprocess" nocase
		$s5="BCryptSetAlgorithmProperty" nocase
		$s6="GetEncryptionKey"
		$s7="CyberGhost" nocase
		$s8="PK11SDR_Decrypt"
		$s9="TelegramBot" nocase
		$s10="SQLDataTypeSize"
		$s11="bcrypt" nocase
		$s12="NordVPN" nocase
		$s13="OpenVPN" nocase
		$s14="VPN" nocase
		$s15="DecryptTokenMethodB" nocase
		$s16="7D78CB380BF5EFB7B851409CA6A875F77DECF09D19B9149DA17A3EBF674BC0F9" nocase
		$s17="obtainedTokens" nocase
		$s18="PublicKeyToken=b77a5c561934e089" nocase
		$s19="b77a5c561934e089" nocase
		$s20="passwordWriter" nocase
		$s21="GetCreditCards" nocase
		$s22="bitcoin" nocase
		$s23="bitcoincore" nocase
		$s24="BIOS" nocase
		$s25="GetBIOScaption" nocase
		$s26="monero" nocase
		$hex1={ 42 53 4A 42 }
		$hex2={ 52 75 6E 42 72 6F 77 73 65 72 76 }
		$hex3={ 47 65 74 43 72 65 64 69 74 43 61 72 64 73 }
		$hex4={ 47 65 74 50 61 73 73 77 6F 72 64 73 }
		$hex5={ 47 65 74 43 6F 6F 6B 69 65 73 }
		$hex6={ 6F 62 74 61 69 6E 65 64 54 6F 6B 65 6E 73 }
		$hex7={ 42 43 52 59 50 54 }
		$hex8={ 56 50 4E }
		$hex9={ 53 74 61 72 74 56 50 4E }
		$hex10={ 54 47 64 6F 77 6E 6C 6F 61 64 }
		$hex11={ 42 69 74 63 6F 69 6E 43 6F 72 65 }
		$hex12={ 42 49 4F 53 }
		$hex13={ 47 65 74 42 49 4F 53 63 61 70 74 69 6F 6E }
		$hex14={ 43 72 79 70 74 6F 67 72 61 70 68 69 63 }
		$hex15={ 43 72 79 70 74 6F 67 72 61 70 68 69 63 45 78 63 65 70 74 69 6F 6E }
		$hex16={ 47 65 74 48 44 44 53 65 72 69 61 6C 4E 6F }
		$hex17={ 6D 6F 6E 65 72 6F }
		$hex18={ 42 43 72 79 70 74 4F 70 65 6E }
		$hex19={ 53 74 65 61 6D 47 65 74 }
		$hex20={ 41 74 6F 6D 69 63 57 61 6C 6C 65 74 }
		$hex21={ 54 65 6C 65 67 72 61 6D 42 6F 74 }
	condition:
		15 of ($s*) and 10 of ($hex*)
}
