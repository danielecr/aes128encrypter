

var sswEnc = require ('./aes128Encrypter.js');

var encrypter = new sswEnc('somestring that will never happens in this planet');

console.log('initialization');

var codedStr = encrypter.encrypt("example di cose che non vanno nel modo odierno");
console.log('encrypting: ' , codedStr);

console.log('decrypted to: "'+encrypter.decrypt(codedStr));


var codedStr = encrypter.encrypt("example di cose che non vanno nel modo odierno");
console.log('encrypting: ' , codedStr);

console.log('decrypted to: "'+encrypter.decrypt(codedStr));

var fromPHP = "btTYBYm2FYg04mJ/AlLtM8ExkauYFixsx9Zeaf5hp1s4cr6mx+tJS4va9WRKMhOld7HMlbNUi0IoCR2FyNIK2A==";
var fromPHP = "WrVPI/Jp2vQfNGBF/cV+1Wa26DREf35lIjGEnxzhK6WVXvh0hpPKj3oWlly/vsoFXxpuSwOhIxZgHyO06ru6iA==";
console.log(fromPHP, 'decrypted to: "'+encrypter.decrypt(fromPHP));


var codedStr = encrypter.encrypt("example di cose che non vanno nel modo odierno","012345678901234567890123456789");
console.log('encrypting: ' , codedStr);

console.log('iv from encr:', encrypter.getIV(codedStr).toString());
