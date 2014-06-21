<?php

class Poly1305 {

	protected $ctx;

	public function __construct($key = null) {
		$this->ctx    = new SplFixedArray(6);
		$this->ctx[0] = new SplFixedArray(5);  // r
		$this->ctx[1] = new SplFixedArray(5);  // h
		$this->ctx[2] = new SplFixedArray(4);  // pad
		$this->ctx[3] = 0;                     // leftover
		$this->ctx[4] = new SplFixedArray(16); // buffer
		$this->ctx[5] = 0;                     // final

		if ($key !== null) $this->init($key);
	}

	protected function load($x, $i = 0) {
		return $x[$i] | ($x[1+$i]<<8) | ($x[2+$i]<<16) | ($x[3+$i]<<24);
	}

	protected function store($x, $i = 0, $u) {
		$x[$i]   = $u & 0xff; $u >>= 8;
		$x[1+$i] = $u & 0xff; $u >>= 8;
		$x[2+$i] = $u & 0xff; $u >>= 8;
		$x[3+$i] = $u & 0xff;
	}

	public function init($key) {
		// r
		$this->ctx[0][0] = ($this->load($key, 0)     ) & 0x3ffffff;
		$this->ctx[0][1] = ($this->load($key, 3) >> 2) & 0x3ffff03;
		$this->ctx[0][2] = ($this->load($key, 6) >> 4) & 0x3ffc0ff;
		$this->ctx[0][3] = ($this->load($key, 9) >> 6) & 0x3f03fff;
		$this->ctx[0][4] = ($this->load($key,12) >> 8) & 0x00fffff;

		// h
		$this->ctx[1][0] = 0;
		$this->ctx[1][1] = 0;
		$this->ctx[1][2] = 0;
		$this->ctx[1][3] = 0;
		$this->ctx[1][4] = 0;

		// pad
		$this->ctx[2][0] = $this->load($key, 16);
		$this->ctx[2][1] = $this->load($key, 20);
		$this->ctx[2][2] = $this->load($key, 24);
		$this->ctx[2][3] = $this->load($key, 28);

		// leftover
		$this->ctx[3] = 0;

		// final
		$this->ctx[5] = 0;
	}

	protected function blocks($data, $offset = 0, $length) {
		$hibit = $this->ctx[5] ? 0 : (1 << 24);

		// r
		$r0 = $this->ctx[0][0];
		$r1 = $this->ctx[0][1];
		$r2 = $this->ctx[0][2];
		$r3 = $this->ctx[0][3];
		$r4 = $this->ctx[0][4];

		$s1 = $r1 * 5;
		$s2 = $r2 * 5;
		$s3 = $r3 * 5;
		$s4 = $r4 * 5;

		// h
		$h0 = $this->ctx[1][0];
		$h1 = $this->ctx[1][1];
		$h2 = $this->ctx[1][2];
		$h3 = $this->ctx[1][3];
		$h4 = $this->ctx[1][4];

		while ($length >= 16) {
			$h0 += ($this->load($data,   $offset)     ) & 0x3ffffff;
			$h1 += ($this->load($data, 3+$offset) >> 2) & 0x3ffffff;
			$h2 += ($this->load($data, 6+$offset) >> 4) & 0x3ffffff;
			$h3 += ($this->load($data, 9+$offset) >> 6) & 0x3ffffff;
			$h4 += ($this->load($data,12+$offset) >> 8) | $hibit;

			$d0 = ($h0 * $r0) + ($h1 * $s4) + ($h2 * $s3) + ($h3 * $s2) + ($h4 * $s1);
			$d1 = ($h0 * $r1) + ($h1 * $r0) + ($h2 * $s4) + ($h3 * $s3) + ($h4 * $s2);
			$d2 = ($h0 * $r2) + ($h1 * $r1) + ($h2 * $r0) + ($h3 * $s4) + ($h4 * $s3);
			$d3 = ($h0 * $r3) + ($h1 * $r2) + ($h2 * $r1) + ($h3 * $r0) + ($h4 * $s4);
			$d4 = ($h0 * $r4) + ($h1 * $r3) + ($h2 * $r2) + ($h3 * $r1) + ($h4 * $r0);

			                $c = ($d0 >> 26); $h0 = $d0 & 0x3ffffff;
			$d1 += $c;      $c = ($d1 >> 26); $h1 = $d1 & 0x3ffffff;
			$d2 += $c;      $c = ($d2 >> 26); $h2 = $d2 & 0x3ffffff;
			$d3 += $c;      $c = ($d3 >> 26); $h3 = $d3 & 0x3ffffff;
			$d4 += $c;      $c = ($d4 >> 26); $h4 = $d4 & 0x3ffffff;
			$h0 += $c * 5;  $c = ($h0 >> 26); $h0 = $h0 & 0x3ffffff;
			$h1 += $c;

			$offset += 16;
			$length -= 16;
		}

		// h
		$this->ctx[1][0] = $h0;
		$this->ctx[1][1] = $h1;
		$this->ctx[1][2] = $h2;
		$this->ctx[1][3] = $h3;
		$this->ctx[1][4] = $h4;
	}

	public function update($data) {
		$length = count($data);
		$offset = 0;

		/* handle leftover */
		if ($this->ctx[3]) {
			$want = (16 - $this->ctx[3]);
			if ($want > $length) {
				$want = $length;
			}
			for ($i = 0; $i < $want;++$i) {
				// buffer
				$this->ctx[4][$this->ctx[3] + $i] = $data[$i+$offset];
			}
			$length  -= $want;
			$offset += $want;
			
			$this->ctx[3] += $want;
			if ($this->ctx[3] < 16) {
				return;
			}
			$this->blocks($this->ctx[4], 0, 16);
			$this->ctx[3] = 0;
		}

		/* process full blocks */
		if ($length >= 16) {
			$want = ($length & ~(16 - 1));
			$this->blocks($data, $offset, $want);
			$offset += $want;
			$length -= $want;
		}

		/* store leftover */
		if ($length) {
			for ($i = 0; $i < $length; ++$i) {
				$this->ctx[4][$this->ctx[3] + $i] = $data[$i+$offset];
			}
			$this->ctx[3] += $length;
		}
	}

	public function finish() {
		$out = new SplFixedArray(16);

		if ($this->ctx[3]) {
			$i = $this->ctx[3];
			$this->ctx[4][$i++] = 1;
			for ($j = $i; $j < 16; ++$j) {
				$this->ctx[4][$j] = 0;
			}
			$this->ctx[5] = 1;
			$this->blocks($this->ctx[4], 0, 16);
		}

		$h0 = $this->ctx[1][0];
		$h1 = $this->ctx[1][1];
		$h2 = $this->ctx[1][2];
		$h3 = $this->ctx[1][3];
		$h4 = $this->ctx[1][4];

		               $c = $h1 >> 26; $h1 = $h1 & 0x3ffffff;
		$h2 +=     $c; $c = $h2 >> 26; $h2 = $h2 & 0x3ffffff;
		$h3 +=     $c; $c = $h3 >> 26; $h3 = $h3 & 0x3ffffff;
		$h4 +=     $c; $c = $h4 >> 26; $h4 = $h4 & 0x3ffffff;
		$h0 += $c * 5; $c = $h0 >> 26; $h0 = $h0 & 0x3ffffff;
		$h1 +=     $c;

		$g0 = $h0 + 5;  $c = $g0 >> 26; $g0 &= 0x3ffffff;
		$g1 = $h1 + $c; $c = $g1 >> 26; $g1 &= 0x3ffffff;
		$g2 = $h2 + $c; $c = $g2 >> 26; $g2 &= 0x3ffffff;
		$g3 = $h3 + $c; $c = $g3 >> 26; $g3 &= 0x3ffffff;
		$g4 = $h4 + $c - (1 << 26);

		$mask = (1 & ($g4 >> 63)) - 1;
		$g0 &= $mask;
		$g1 &= $mask;
		$g2 &= $mask;
		$g3 &= $mask;
		$g4 &= $mask;
		$mask = ~$mask;
		$h0 = ($h0 & $mask) | $g0;
		$h1 = ($h1 & $mask) | $g1;
		$h2 = ($h2 & $mask) | $g2;
		$h3 = ($h3 & $mask) | $g3;
		$h4 = ($h4 & $mask) | $g4;

		$h0 = (($h0      ) | ($h1 << 26)) & 0xffffffff;
		$h1 = (($h1 >>  6) | ($h2 << 20)) & 0xffffffff;
		$h2 = (($h2 >> 12) | ($h3 << 14)) & 0xffffffff;
		$h3 = (($h3 >> 18) | ($h4 <<  8)) & 0xffffffff;

		$f = $h0 + $this->ctx[2][0]             ; $h0 = $f;
		$f = $h1 + $this->ctx[2][1] + ($f >> 32); $h1 = $f;
		$f = $h2 + $this->ctx[2][2] + ($f >> 32); $h2 = $f;
		$f = $h3 + $this->ctx[2][3] + ($f >> 32); $h3 = $f;

		$this->store($out,  0, $h0);
		$this->store($out,  4, $h1);
		$this->store($out,  8, $h2);
		$this->store($out, 12, $h3);

		$this->ctx[0][0] = 0;
		$this->ctx[0][1] = 0;
		$this->ctx[0][2] = 0;
		$this->ctx[0][3] = 0;
		$this->ctx[0][4] = 0;
		$this->ctx[1][0] = 0;
		$this->ctx[1][1] = 0;
		$this->ctx[1][2] = 0;
		$this->ctx[1][3] = 0;
		$this->ctx[1][4] = 0;
		$this->ctx[2][0] = 0;
		$this->ctx[2][1] = 0;
		$this->ctx[2][2] = 0;
		$this->ctx[2][3] = 0;

		return $out;
	}

	public static function verify($mac1, $mac2) {
		if (count($mac1) !== count($mac2)) {
			return false;
		}

		$dif = 0;
		for ($i = 0; $i < 16; $i++) {
			$dif |= ($mac1[$i] ^ $mac2[$i]);
		}
		$dif = ($dif - 1) >> 31;

		return (($dif & 1) === 1);
	}

	public static function auth($key, $data) {
		$p = new Poly1305($key);
		$p->update($data);
		return $p->finish();
	}

}
