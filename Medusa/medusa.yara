rule Medusa_malware
{
	meta:
		author="5kidRo0t"
		sha256="f1c361bb3b649918bc5b3ad3fc5cbd1bbd7c585fbe2557410e267d161d3bb998"
		sha512="54c1c34cba89a0471a0dfb4e0437abd36bd4223483f3c7771cf5a6fa0bc81c937a9374a181c11898fe38d2c42d204dc5dc4574111ffa707c7dcec7d0ca9f423d"
	strings:
		$s1="jMuUb0zP5+jFqFmgSzxjDNVYab6FeiGO7NRJ0xik16HDlKyfOT1D548E6iamwxS1jD9P8A3ebBPKVWSE1xBhnoxa5wQ1"
		$s2="kW6t8ReCnHh5LKAh"
		$s3="csi9t/s4L1O9J0X3Qr5lIBVnXm4TmNYaJKs8vR0WhKf9RseqVH1Kde4kuvMA24dLf8ssf03PFZHOnl8ji00wYsZ85pEIPDnJmapxqJ0206vC6utgfz5tiEzuwi7cOcIEfmO2yjZB7OIlywiwSb5cn2HRfzu9PsktkdCnPs3Hsza"
		$s4="YOUR COMPANY NETWORK HAS BEEN PENETRATED"
		$s5="qd7pcafncosqfqu3ha6fcx4h6sr7tzwagzpcdcnytiw3b6varaeqv5yd.onion"
		$s6="ithelp01@decorous.cyou"
		$s7="Dinkumware"
	condition:
		5 of them
}
