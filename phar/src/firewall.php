<?php

require 'common.php';

echo "I'm in firewall.php\n";

while(true) {
	sleep(5);
	print "A loop!\n";
	if (pharChanged()) {
		print "It changed!\n";
		exit;
	}
}

