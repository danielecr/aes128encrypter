<?php

/**
Requirements:
 - a initial string from which I create a key ($string)
 - for decryption:
   - given a base64 encoded string to be decrypted -> return clear text
 - for encryption:
   - given a clear Text -> return a base64 encoded string
 - every object is instanziated by the initial string:
   var encObj = new sswEncrypter($string);
   var aClearText = encObj.decrypt(base64encodedString);
   var aBase64EncodedString = encObj.encrypt(aClearText);
*/

class AES128encrypter
{
	public $key;
	
	function __construct($string)
	{
		$this->key = pack('H*',md5($string));
	}
	
	private function pkcs5_pad ($text, $blocksize) { 
		$pad = $blocksize - (strlen($text) % $blocksize);
		if($pad == 0) {
			$pad = $blocksize;
		}
		return $text . str_repeat(chr($pad), $pad); 
	}

	function encrypt($clearText,$ivStr = NULL)
	{
		$key = $this->key;
		$key_size = strlen($key);
		// text has to be divisible by block size, thus a possibile padding is added
		$plaintext = $this->pkcs5_pad($clearText,mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC));
		$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
		$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
		if($ivStr != NULL) {
			for($i = 0; $i<$iv_size && $i<strlen($ivStr); $i++) {
				$iv[$i] = $ivStr[$i];
			}
		}
		$ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key,
					     $plaintext, MCRYPT_MODE_CBC, $iv);
		# prepend the IV for it to be available for decryption
		$ciphertext = $iv . $ciphertext;
		$ciphertext_base64 = base64_encode($ciphertext);
		return $ciphertext_base64;
	}

	function decrypt($base64EncodedStr)
	{
		$sKey = $this->key;
		$ciphertext_dec = base64_decode($base64EncodedStr);
		$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
		# retrieves the IV, iv_size should be created using mcrypt_get_iv_size()
		$iv_dec = substr($ciphertext_dec, 0, $iv_size);
    
		# retrieves the cipher text (everything except the $iv_size in the front)
		$ciphertext_dec = substr($ciphertext_dec, $iv_size);
		$plaintext_dec = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $sKey,
						$ciphertext_dec, MCRYPT_MODE_CBC, $iv_dec);
		// and now remove the padding (possible)
		$dec_s = strlen($plaintext_dec); 
		$padding = ord($plaintext_dec[$dec_s-1]);
		$plaintext_dec = substr($plaintext_dec, 0, -$padding);
		return $plaintext_dec;
	}

	function getIV($base64EncodedStr) {
		$ciphertext_dec = base64_decode($base64EncodedStr);
		$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
		# retrieves the IV, iv_size should be created using mcrypt_get_iv_size()
		$iv_dec = substr($ciphertext_dec, 0, $iv_size);

		return $iv_dec;
	}

}
