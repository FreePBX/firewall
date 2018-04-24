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

$defaults = array(
	"name" => "firewall",
	"secret" => "fpbxfirewall*secret",
	"deny" => "0.0.0.0/0.0.0.0",
	"permit" => "127.0.0.1/255.255.255.0",
	"read" => "all",
	"write" => "user",
	"writetimeout" => 100
);

// See if the firewall manager user exists
$m = \FreePBX::Database()->query('SELECT * FROM `manager` WHERE `name`="firewall"')->fetchAll();
if (!$m) {
	// It doesn't. Create it.
	$p = \FreePBX::Database()->prepare('INSERT INTO `manager` (`name`, `secret`, `deny`, `permit`, `read`, `write`, `writetimeout`) values (:name, :secret, :deny, :permit, :read, :write, :writetimeout)');
	$p->execute($defaults);
	$m = array($defaults);
	needreload();
}

// If our settings aren't correct, fix them
$repair = false;
foreach ($defaults as $k => $v) {
	if ($m[0][$k] !== $v) {
		$repair = true;
		break;
	}
}

if ($repair) {
	$p = \FreePBX::Database()->prepare('UPDATE `manager` set `secret`=:secret, `deny`=:deny, `permit`=:permit, `read`=:read, `write`=:write, `writetimeout`=:writetimeout WHERE `name`=:name');
	$p->execute($defaults);
	needreload();
}

// Trigger firewalld to ensure that any old firewalld is killed
$file = "/var/spool/asterisk/incron/firewall.firewall";
fclose(fopen($file, "c"));


