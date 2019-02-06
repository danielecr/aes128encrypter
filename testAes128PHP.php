<?php

include 'aes128encrypter.php';
$value = "example di cose che non vanno nel modo odierno";
$key = 'somestring that will never happens in this planet';
$sswenc = new AES128encrypter($key);

print "\n";
$b64encoded = $sswenc->encrypt($value,'base');
print $b64encoded;
print "\n";
$value2 = $sswenc->decrypt($b64encoded);
print $value2;
print "\n";
print strlen($value);

print "\n";

$value = $sswenc->decrypt($b64encoded);
print $value;

print "\n";

$fromOut = "WrVPI/Jp2vQfNGBF/cV+1Wa26DREf35lIjGEnxzhK6WVXvh0hpPKj3oWlly/vsoFXxpuSwOhIxZgHyO06ru6iA==";
print "$fromOut\n";
$value = $sswenc->decrypt($fromOut);
print $value;


print "\n";

print strlen($value);


$value = $sswenc->decrypt($b64encoded);
print $value;


print "\n";

print "\n";
