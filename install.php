<?php

// Temporary:  Trigger firewalld to ensure that any old
// firewalld is killed
//
$file = "/var/spool/asterisk/incron/firewall.firewall";
fclose(fopen($file, "c"));

