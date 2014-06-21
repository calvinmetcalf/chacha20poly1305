<?php

class Chacha20Poly1305 {

	protected $key;

	public function __construct($key) {
		$this->key = $key;
	}

	protected function init(Chacha20 $ctx, $nonce) {
		$ctx->keysetup($this->key);
		$ctx->ivsetup($nonce);

		$subkey = new SplFixedArray(64);
		$ctx->keystream($subkey, 64);

		$out = new SplFixedArray(32);
		for ($i = 32; $i--;) $out[$i] = $subkey[$i];
		return $out;
	}

	protected function store64($dst, $pos, $num) {
		$dst[$pos]   = $num & 0xff; $num >>= 8;
		$dst[$pos+1] = $num & 0xff; $num >>= 8;
		$dst[$pos+2] = $num & 0xff; $num >>= 8;
		$dst[$pos+3] = $num & 0xff; $num >>= 8;
		$dst[$pos+4] = $num & 0xff; $num >>= 8;
		$dst[$pos+5] = $num & 0xff; $num >>= 8;
		$dst[$pos+6] = $num & 0xff; $num >>= 8;
		$dst[$pos+7] = $num & 0xff;
	}

	protected function tag($key, $ciphertext, $data) {
		$clen = count($ciphertext);
		$dlen = count($data);
		$m = new SplFixedArray($clen + $dlen + 16);

		for ($i = $dlen; $i--;) $m[$i] = $data[$i];
		$this->store64($m, $dlen, $dlen);

		for ($i = $clen; $i--;) $m[$dlen+8+$i] = $ciphertext[$i];
		$this->store64($m, $clen + $dlen + 8, $clen);

		return Poly1305::auth($key, $m);
	}

	public function encrypt($nonce, $input, $data) {
		$c20 = new Chacha20();
		$key = $this->init($c20, $nonce);

		$ilen = count($input);
		$ciphertext = new SplFixedArray($ilen);
		$c20->encrypt($ciphertext, $input, $ilen);

		$mac = $this->tag($key, $ciphertext, $data);

		return array_merge($ciphertext->toArray(), $mac->toArray());
	}

	public function decrypt($nonce, $ciphertext, $data) {
		$c20 = new Chacha20();
		$key = $this->init($c20, $nonce);

		$clen = count($ciphertext) - 16;

		$digest = array_slice($ciphertext, $clen);

		$mac = $this->tag($key, array_slice($ciphertext, 0, $clen), $data);

		if ( ! Poly1305::verify($digest, $mac)) {
			return false;
		}

		$out = new SplFixedArray($clen);
		$c20->decrypt($out, $ciphertext, $clen);
		return $out->toArray();
	}

}
