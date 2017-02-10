
<div class='container-fluid'>
<h3><?php echo _("External Network Definitions"); ?></h3>

<p><?php echo _("Individual hosts and networks are specified here to override the default rule for an interface."); ?></p>
<p><?php echo _("For example, if interface eth0 is assigned to the 'Internet' zone, here you can add a specific <strong>source</strong> network to the 'Trusted' zone."); ?></p>
<p><?php echo _("Afte that, any connections <strong>originating</strong> from that network (and arriving on <i>any interface</i>) will be treated as 'Trusted'. All other traffic arriving at that interface is only allowed access to services available to the 'Internet' zone."); ?></p>
<p><?php echo _("You may also enter hostnames here (for example, DDNS), which will be automatically monitored and updated as required."); ?></p>
</div>
<form role='form' class='form-inline'>
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
</form>
<?php

// Render the interface select
function render_network($name, $current, $desc, $counter, $zones) {
	print "<tr id='netcount-$counter' class='netzone' zone='$current' data-counter='$counter'>";
	// If name is not empty, render a normal line.
	if ($name) {
		print "<td><input data-counter='$counter' type='checkbox' class='checkbox'></td>";
		print "<td><tt counter='$counter'>".htmlentities($name, ENT_QUOTES)."</tt></td>";
		print "<td><select class='form-control' name='zone-$counter' data-rowid='$counter'>";

	} else {
		print "<td></td>"; // No checkbox
		print "<td><input class='form-control' type='text' name='newentry' placeholder='"._("Enter new IP or Hostname here")."'></input></td>";
		print "<td><select class='form-control form-inline newnetsel' name='newnetworke' data-rowid='$counter'>";
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
	print "<tr id='description-$counter' zone='$current' class='descrow'><td></td><td colspan=2><input counter='$counter' class='description form-control' type='text' name='descr-$counter' placeholder='"._("You can enter a short description for this network here.")."' value='$desc'></td></tr>";
}

