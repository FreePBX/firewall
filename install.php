<?php

// There's been reports of empty networkmaps being discovered. This
// searches for them and deletes them if they exist.
try {
	$f = \FreePBX::Firewall();
	$nets = $f->getConfig("networkmaps");
	if (is_array($nets) && isset($nets[""])) {
		unset ($nets[""]);
		$f->setConfig("networkmaps", $nets);
	}
} catch (\Exception $e) {
	// First install. Ignore error.
}

// Trigger firewalld to ensure that any old firewalld is killed
$file = "/var/spool/asterisk/incron/firewall.firewall";
fclose(fopen($file, "c"));


