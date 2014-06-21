<?php

include '../Chacha20.php';
include '../Poly1305.php';
include '../Chacha20Poly1305.php';

// testVectors from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#page-11
$testVectors = array(
	'4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007',
	'86d09974840bded2a5ca',
	'cd7cf67be39c794a',
	'87e229d4500845a079c0',
	'e3e446f7ede9a19b62a4677dabf4e3d24b876bb284753896e1d6',
);

function fromHex($hex) {
	$hex = preg_replace('/[^0-9a-f]/', '', $hex);
	return SplFixedArray::fromArray(unpack("C*", pack("H*", $hex)), false);
}

function printDiff($a, $b) {
	printf("want:\n");
		for ($i = 0; $i < count($a); $i++) printf("%02x,", $a[$i]); printf("\n");
	printf("got :\n");
		for ($i = 0; $i < count($b); $i++) printf("%02x,", $b[$i]); printf("\n");
	printf("diff:\n");
		for ($i = 0; $i < count($a); $i++) {
			if ($a[$i] ^ $b[$i]) {
				printf("%02x,", $a[$i] ^ $b[$i]);
			} else {
				printf("  ,");
			}
		}
	printf("\n\n");
}


function bytesEqual($a, $b) {
	$dif = 0;
	if (count($a) !== count($b)) return 0;
	for ($i = 0; $i < count($a); $i++) {
		$dif |= ($a[$i] ^ $b[$i]);
	}
	$dif = ($dif - 1) >> 31;
	return ($dif & 1);
}

$key      = fromHex($testVectors[0]);
$input    = fromHex($testVectors[1]);
$nonce    = fromHex($testVectors[2]);
$ad       = fromHex($testVectors[3]);
$expected = fromHex($testVectors[4]);

$aead = new Chacha20Poly1305($key);

$ciphertext = $aead->encrypt($nonce, $input, $ad);

if ( ! bytesEqual($expected, $ciphertext)) {
	echo "encryption error:\n";
	printDiff($expected, $ciphertext);
} else {
	echo "encryption OK\n";
}

$plaintext = $aead->decrypt($nonce, $ciphertext, $ad);

if ( ! bytesEqual($input, $plaintext)) {
	echo "decryption error:\n";
	printDiff($input, $plaintext);
} else {
	echo "decryption OK\n";
}
