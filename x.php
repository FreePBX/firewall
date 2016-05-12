<?php

$i = '[face:b0de::';

$z = preg_replace('/^\[?([^\]]+)\]?$/', '\1', $i);
print "I have $z\n";

var_dump(filter_var($z, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6));
