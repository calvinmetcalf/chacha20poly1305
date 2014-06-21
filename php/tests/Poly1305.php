<?php

include '../Poly1305.php';

// testVectors from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#page-11
$testVectors = array(
	array(
		'0000000000000000000000000000000000000000000000000000000000000000',
		'746869732069732033322d62797465206b657920666f7220506f6c7931333035',
		'49ec78090e481ec6c26b33b91ccc0307',
	),
	array(
		'48656c6c6f20776f726c6421',
		'746869732069732033322d62797465206b657920666f7220506f6c7931333035',
		'a6f745008f81c916a20dcc74eef2b2f0',
	),
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

for ($i = 0; $i < count($testVectors); $i++) {
	$input    = fromHex($testVectors[$i][0]);
	$key      = fromHex($testVectors[$i][1]);
	$expected = fromHex($testVectors[$i][2]);

	$mac = Poly1305::auth($key, $input);

	if ( ! Poly1305::verify($expected, $mac)) {
		echo "error: ".$i."\n";
		printDiff($expected, $mac);
	} else {
		echo $i." OK\n";
	}
}
