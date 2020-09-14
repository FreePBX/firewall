<?php
//check ipset  installed or not 
$ipset = `yum list installed | grep ipset`;
preg_match('/ipset/', $ipset, $output_array);
if(count($output_array)== 0){
	outn(_("A required rpm package ipset is not present. We are installing  'yum install ipset' this may take some time "));
	$res =	`yum install ipset -y`;
	$output = preg_grep('/Complete!/', explode("\n", $res));
	if(count($output) == 1){
		outn(_('ipset installed successfully'));
	} else {
		outn(_("Unable to install the required rpm package 'ipset', please install it manually by running 'yum install ipset -y' from the command line and re-install the firewall module. Latest firewall module is depends on 'ipset' package so please install 'ipset' package first and then try to upgrade firewall module"));
		exit;
	}
}
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


