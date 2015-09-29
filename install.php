<?php

// Temporary:  Trigger firewalld to ensure that any old
// firewalld is killed
//
$file = "/var/spool/asterisk/incron/firewall.firewall";
fclose(fopen($file, "c"));

// Warn about firewall page changing location
\FreePBX::create()->Notifications()->add_warning('firewall', 'hasmoved', _("Firewall Configuration has moved!"),
	_("The Firewall configuration menu option has moved to 'Connectivity'"),
	false,
	true,
	true);

