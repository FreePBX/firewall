<?php

include 'Jiffies.class.php';

$j = new FreePBX\modules\Firewall\Jiffies();

var_dump($j->getKnownJiffies());

