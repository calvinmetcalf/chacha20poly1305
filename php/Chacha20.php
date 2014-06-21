<?php

class Chacha20 {

	protected $input;

	function __construct() {
		$this->input = new SplFixedArray(16);
	}

	function load32($x, $i) {
		return $x[$i] | ($x[$i+1]<<8) | ($x[$i+2]<<16) | ($x[$i+3]<<24);
	}

	function store32($x, $i, $u) {
		$x[$i]   = $u & 0xff; $u >>= 8;
		$x[$i+1] = $u & 0xff; $u >>= 8;
		$x[$i+2] = $u & 0xff; $u >>= 8;
		$x[$i+3] = $u & 0xff;
	}

	function plus($a, $b) {
		return ($a + $b) & 0xffffffff;
	}

	function rotl32($v, $c) {
		return (($v << $c) & 0xffffffff) | ($v >> (32 - $c));
	}

	function round($x, $a, $b, $c, $d) {
		$x[$a] = $this->plus($x[$a], $x[$b]); $x[$d] = $this->rotl32($x[$d] ^ $x[$a], 16);
		$x[$c] = $this->plus($x[$c], $x[$d]); $x[$b] = $this->rotl32($x[$b] ^ $x[$c], 12);
		$x[$a] = $this->plus($x[$a], $x[$b]); $x[$d] = $this->rotl32($x[$d] ^ $x[$a],  8);
		$x[$c] = $this->plus($x[$c], $x[$d]); $x[$b] = $this->rotl32($x[$b] ^ $x[$c],  7);
	}

	function keysetup($key) {
		$this->input[0] = 1634760805;
		$this->input[1] =  857760878;
		$this->input[2] = 2036477234;
		$this->input[3] = 1797285236;
		for ($i = 0; $i < 8; $i++) {
			$this->input[$i+4] = $this->load32($key, $i*4);
		}
	}

	function ivsetup($iv) {
		$this->input[12] = 0;
		$this->input[13] = 0;
		$this->input[14] = $this->load32($iv, 0);
		$this->input[15] = $this->load32($iv, 4);
	}

	function encrypt($dst, $src, $len) {
		$x = new SplFixedArray(16);
		$buf = new SplFixedArray(64);
		$i = 0; $dpos = 0; $spos = 0;

		while ($len > 0) {
			for ($i = 16; $i--;) $x[$i] = $this->input[$i];
			for ($i = 20; $i > 0; $i -= 2) {
				$this->round($x, 0, 4, 8,12);
				$this->round($x, 1, 5, 9,13);
				$this->round($x, 2, 6,10,14);
				$this->round($x, 3, 7,11,15);
				$this->round($x, 0, 5,10,15);
				$this->round($x, 1, 6,11,12);
				$this->round($x, 2, 7, 8,13);
				$this->round($x, 3, 4, 9,14);
			}

			for ($i = 16; $i--;) $x[$i] += $this->input[$i];
			for ($i = 16; $i--;) $this->store32($buf, 4*$i, $x[$i]);

			$this->input[12] = $this->plus($this->input[12], 1);
			if (!$this->input[12]) {
				$this->input[13] = $this->plus($this->input[13], 1);
			}
			if ($len <= 64) {
				for ($i = $len; $i--;) {
					$dst[$i+$dpos] = $src[$i+$spos] ^ $buf[$i];
				}
				return;
			}
			for ($i = 64; $i--;) {
				$dst[$i+$dpos] = $src[$i+$spos] ^ $buf[$i];
			}
			$len -= 64;
			$spos += 64;
			$dpos += 64;
		}
	}

	function decrypt($dst, $src, $len) {
		$this->encrypt($dst, $src, $len);
	}

	function keystream($dst, $len) {
		for ($i = $len; $i--;) $dst[$i] = 0;
		$this->encrypt($dst, $dst, $len);
	}
}
