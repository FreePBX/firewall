<?php

include '/etc/freepbx.conf';
include 'Attacks.class.php';
use \FreePBX\modules\Firewall\Attacks;

$smart = \FreePBX::Firewall()->getSmartObj();
$j = \FreePBX::Firewall()->getJiffies();
$a = new Attacks($j);
$z = $a->getAllAttacks($smart->getRegistrations());
print_r($z['summary']);
// print_r($j->calcJiffies());
