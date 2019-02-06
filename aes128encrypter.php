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

	const METHOD = 'aes-256-cbc';

	public function __construct($string)
	{
		$this->key = pack('H*',md5($string));
	}


	public function encrypt($clearText, $ivStr = NULL)
	{
		$key = $this->key;
		$key_size = strlen($key);
		// OLD: text has to be divisible by block size, thus a possibile padding is added
		// now done by default by openssl_encrypt

		$ivsize = openssl_cipher_iv_length(self::METHOD);
        $iv = openssl_random_pseudo_bytes($ivsize);

		if($ivStr != NULL) {
			for($i = 0; $i<$ivsize && $i<strlen($ivStr); $i++) {
				$iv[$i] = $ivStr[$i];
			}
		}
		$ciphertext = openssl_encrypt(
            $clearText,
            self::METHOD,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
		# prepend the IV for it to be available for decryption
		$ciphertext = $iv . $ciphertext;
		$ciphertext_base64 = base64_encode($ciphertext);
		return $ciphertext_base64;
	}

	public function decrypt($base64EncodedStr)
	{
		$sKey = $this->key;
		$ciphertext_dec = base64_decode($base64EncodedStr);

		$ivsize = openssl_cipher_iv_length(self::METHOD);
		$iv = mb_substr($ciphertext_dec, 0, $ivsize, '8bit');
		$ciphertext = mb_substr($ciphertext_dec, $ivsize, null, '8bit');

		return openssl_decrypt(
			$ciphertext,
			self::METHOD,
			$sKey,
			OPENSSL_RAW_DATA,
			$iv
		);


	}

	public function getIV($base64EncodedStr) {
		$ciphertext_dec = base64_decode($base64EncodedStr);
		$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
		# retrieves the IV, iv_size should be created using mcrypt_get_iv_size()
		$iv_dec = substr($ciphertext_dec, 0, $iv_size);

		return $iv_dec;
	}

}
