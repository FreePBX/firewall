
<div class='container-fluid'>
<h3><?php echo _("Known Network Definitions"); ?></h3>

<p><?php echo _("You can add individual hosts and networks to override the default permission for an interface."); ?></p>
<p><?php echo _("Example: Interface eth0 is assigned to the 'Internet' zone, and you then add '203.55.66.77' to the 'Local' zone on this page. Any traffic arriving from 203.55.66.77 will be granted access to services usable by 'Local' zone."); ?></p>
<p><?php echo _("Any traffic arriving at eth0 from 203.55.66.88 (or any other undefined host or network) will only have access to services available to the 'Internet' zone, as that has been set to be the default zone for traffic arriving at that interface."); ?></p>
<p><?php echo _("You may also enter hostnames here (including Dynamic DNS hosts), which will be automatically monitored and updated."); ?></p>
</div>
<table class="table" id='networkstable'>
  <thead>
    <tr>
      <th><input type='checkbox' id='toggleall'></th>
      <th><?php echo _("Network/Host"); ?></th>
      <th><?php echo _("Assigned Zone"); ?></th>
    </tr>
  </thead>

<?php
$nets = $fw->getConfig("networkmaps");
$descs = $fw->getNetworkDescriptions();

if (!is_array($nets)) {
	$nets = array();
}
// Add a blank one to the bottom..
$nets[""] = "internal";

$z = $fw->getZones();
$hidden = $fw->getConfig("hiddennets");

// No reject on networks.
unset($z['reject']);

// Now, loop through our networks and display them.
$counter = 0;
foreach ($nets as $net => $currentzone) {
	$counter++;
	if (isset($hidden[$net]) && !isset($_REQUEST['showhidden'])) {
		continue;
	}
	if (isset($descs[$net])) {
		$desc = htmlentities($descs[$net], ENT_QUOTES);
	} else {
		$desc = "";
	}
	render_network($net, $currentzone, $desc, $counter, $z);
}
?>
</table>
<?php

// Render the interface select
function render_network($name, $current, $desc, $counter, $zones) {
	print "<tr class='net-$counter netzone' zone='$current' data-counter='$counter'>";
	// If name is not empty, render a normal line.
	if ($name) {
		print "<td><input data-counter='$counter' type='checkbox' class='checkbox'></td>";
		print "<td><tt counter='$counter'>".htmlentities($name, ENT_QUOTES)."</tt></td>";
		print "<td><select class='form-control' name='zone-$counter' data-rowid='$counter' data-type='net'>";
		$newentry = "";

	} else {
		print "<td></td>"; // No checkbox
		print "<td><input class='form-control newentry' type='text' name='newentry' data-counter='$counter' placeholder='"._("Enter new IP or Hostname here")."'></input></td>";
		print "<td><select class='form-control form-inline newnetsel' name='newnetworke' data-rowid='$counter' data-type='net'>";
		$newentry = "newentry";
	}

	// Render the available zones
	foreach ($zones as $zn => $zone) {
		if ($current === $zn) {
			$selected = "selected";
		} else {
			$selected = "";
		}
		print "<option value='$zn' $selected>".$zone['name']." (".$zone['summary'].")</option>";
	}
	print "</select>";
	
	// Are we displaying the 'add' button?
	if (!$name) {
		print "<button data-counter='$counter' class='addnetwork btn x-btn btn-success pull-right' title='"._("Add New")."'><i data-counter='$counter' class='glyphicon glyphicon-plus'></i></button>";
	}

	print "</tr></td>";

	// Render the description box
	print "<tr id='description-$counter' zone='$current' class='net-$counter descrow'><td></td><td colspan=2><input counter='$counter' class='description $newentry form-control' type='text' name='netdescr-$counter' placeholder='"._("You can enter a short description for this network here.")."' value='$desc'></td></tr>";
}

