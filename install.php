<?php
//check ipset  installed or not 
$ipset = fpbx_which("ipset");
if ($ipset == "") {
	out( _("Latest firewall module is depends on 'ipset' utility which is missing so please install this by either 'yum install ipset -y' for distro(centos) or equivalent package install command as per your OS and try again.") );
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
//reponseive firewall defaults 
$responsive['fpbxratelimit']['TIER3'] = ['seconds'=>86400,'hitcount'=>200,'type'=>'BLOCK'];
$responsive['fpbxratelimit']['TIER2'] = ['seconds'=>300,'hitcount'=>100,'type'=>'BLOCK'];
$responsive['fpbxratelimit']['TIER1'] = ['seconds'=>60,'hitcount'=>50,'type'=>'SHORTBLOCK'];
$responsive['fpbxrfw']['TIERA'] = ['seconds'=>10,'hitcount'=>50,'type'=>'BLOCK'];
$responsive['fpbxrfw']['TIERB'] = ['seconds'=>60,'hitcount'=>10,'type'=>'SHORTBLOCK'];
$responsive['fpbxrfw']['TIERC'] = ['seconds'=>86400,'hitcount'=>100,'type'=>'BLOCK'];
foreach($responsive as $id => $rows){
	foreach($rows as $key => $val){
		if(!is_array(\FreePBX::Firewall()->getConfig($key,$id))){
			\FreePBX::Firewall()->SetConfig($key,$val,$id);
		}
	}
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

