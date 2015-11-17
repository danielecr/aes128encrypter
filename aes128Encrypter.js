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


var Crypto = require('crypto')

function pack_an_md5($string) {
    var hash = Crypto.createHash('md5');
    hash.update($string);
    var value = hash.digest('hex');
    var tpack = new Buffer(value,'hex');
    return tpack;
}

function encrypt(clearText,key,ivStr) {
    var iv = Crypto.randomBytes(16);
    if( ! (typeof ivStr === 'undefined') && (typeof ivStr === 'string')) {
	for(var i =0; i<ivStr.length && i<16; i++) {
	    iv[i] = ivStr.charCodeAt(i);
	}
	if(ivStr.length>=16) {
	    console.log('warning ivStr length is too much');
	}
    }
    var cipher = Crypto.createCipheriv('aes-128-cbc', new Buffer(key), iv);
    var encrypted = cipher.update(clearText);
    var finalBuffer = Buffer.concat([encrypted, cipher.final()]);
    //Need to retain IV for decryption, prepended, we know the length
    var encryptedHex = iv.toString('hex') + finalBuffer.toString('hex')
    return (new Buffer(encryptedHex,'hex')).toString('base64');
}


//var encryptedArray = encryptedHex.split(':');
function decryptHex(encryptedHex,key) {
    var encryptedArray = [encryptedHex.substr(0,32),encryptedHex.substr(32)];
    //console.log('encrypted arr',encryptedArray);
    var iv = new Buffer(encryptedArray[0], 'hex');
    var encrypted = new Buffer(encryptedArray[1], 'hex');
    var decipher = Crypto.createDecipheriv('aes-128-cbc', new Buffer(key), iv);
    var decrypted = decipher.update(encrypted);
    var clearText = Buffer.concat([decrypted, decipher.final()]).toString();

    return clearText;
}

var aes128Encrypter = function(string) {
    this.key = pack_an_md5(string);
}

aes128Encrypter.prototype = {
    encrypt: function(clearText,ivStr) {
	return encrypt(clearText,this.key,ivStr);
    },
    decrypt: function(base64EncodedString) {
	return decryptHex((new Buffer(base64EncodedString,'base64')).toString('hex'),this.key);
    },
    getIV: function(base64EncodedString) {
	var ivHex = (new Buffer(base64EncodedString,'base64')).toString('hex').substr(0,32);
	return new Buffer(ivHex,'hex');
    },
}

module.exports = aes128Encrypter;

