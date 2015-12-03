<?php

include '/etc/freepbx.conf';
include __DIR__."/Attacks.class.php";
$f = \FreePBX::Firewall();
$a = new \FreePBX\modules\Firewall\Attacks($f->getJiffies());
$smart = $f->getSmartObj();
print_r($a->getAllAttacks($smart->getRegistrations()));
