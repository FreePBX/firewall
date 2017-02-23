<?php
// i18n
$in = _("Interface Name");
$dz = _("Default Zone");
?>

<div class='container-fluid'>
  <h3><?php echo _("Default Traffic Zones"); ?></h3>
  <p><?php echo _("All interfaces must be assigned to a default zone. Any traffic received by this interface, unless overridden in Networks, will have access to the services available to this zone."); ?></p>
  <p><?php echo _("Most interfaces should be set to <strong>Internet</strong>."); ?></p>
  <p><?php echo _("A 'Trusted' interface means that <strong>no filtering</strong> will be applied to any traffic arriving at that interface. Newly discovered interfaces are set to this zone so they can be configured correctly without interfering with existing traffic."); ?></p>

<table class="table" id='interfacestable'>
  <thead>
    <tr>
      <th><?php echo $in; ?></th>
      <th><?php echo $dz; ?></th>
    </tr>
  </thead>
<?php
$ints = $fw->getInterfaces();
$z = $fw->getZones();

$counter = 0;

// We need the length of 'in' so the width is calculated
// correctly in whatever language this session is in
$llen = ceil(strlen($in)*.75);

foreach ($ints as $i => $conf) {
	$counter++;
	$currentzone = $fw->getZone($i);
	render_interface($i, $currentzone, $conf, $counter, $z, $llen);
}
?>
</table>

</div>
<?php

// Render the interface select
function render_interface($name, $current, $conf, $counter, $zones, $llen) {
	print "<tr id='intcount-$counter' class='intzone int-$counter' zone='$current' data-counter='$counter'>";
	print "<td style='width: ${llen}em '><tt class='intname'>".htmlentities($name, ENT_QUOTES)."</tt></td>";
	if (strpos($name, "tun") === 0) {
		$tun = _("All Tunnel Interfaces are automatically set to Local");
	} else {
		$tun = false;
	}

	if ($tun || $conf['config']['PARENT']) {
		$seldisabled = "disabled";
	} else {
		$seldisabled = "";
	}
	if ($conf['config']['PARENT']) {
		$linked = "parent='".$conf['config']['PARENT']."'";
	} else {
		$linked = "";
	}
	print "<td><select $seldisabled $linked class='form-control intselect' name='zone-$counter' data-rowid='$counter' data-type='int' data-intname='$name'>";
	foreach ($zones as $zn => $zone) {
		if ($current === $zn) {
			$selected = "selected";
		} else {
			$selected = "";
		}
		if ($conf['config']['PARENT']) {
			print "<option value='$zn' $selected>".$zone['name']." (".sprintf(_("Linked to Interface %s"), $conf['config']['PARENT']).")</option>";
		} elseif ($tun) {
			print "<option value='$zn' $selected>".$zone['name']." ($tun)</option>";
		} else {
			print "<option value='$zn' $selected>".$zone['name']." (".$zone['summary'].")</option>";
		}
	}
	print "</select>";
	// var_dump($conf);
	print "</tr></td>";

	// IP Addresses
	print "<tr data-counter='$counter' class='int-$counter descrow' zone='$current'><td>";

	if (empty($conf['addresses'])) {
		print "</td><td><strong>"._("No IP Addresses assigned to this interface.")."</strong>";
	} else {
		if (count($conf['addresses']) > 1) {
			print "<strong>"._("IP Addresses: ")."</td>";
		} else {
			print "<strong>"._("IP Address: ")."</td>";
		}
		$tmparr = array();
		foreach ($conf['addresses'] as $ips) {
			$tmparr[] = $ips[0]."/".$ips[2];
		}
		print "<td>".join(", ", $tmparr)."</td>";
	}
	print "</tr>";

	// Render the description box
	if (!isset($conf['config']['DESCRIPTION'])) {
		$desc = "";
	} else {
		$desc = htmlentities($conf['config']['DESCRIPTION'], ENT_QUOTES);
	}

	if ($seldisabled) {
		$placeholder = "";
	} else {
		$placeholder = _("You can enter a short description for this interface here.");
	}

	print "<tr id='intdescription-$counter' zone='$current' class='int-$counter descrow'><td colspan=2><input counter='$counter' $seldisabled class='description form-control' type='text' name='intdescr-$counter' placeholder='$placeholder' value='$desc'></td></tr>";
}

