
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
      <th><input type='checkbox' /></th>
      <th><?php echo _("Network/Host"); ?></th>
      <th><?php echo _("Assigned Zone"); ?></th>
    </tr>
  </thead>

<?php
$nets = $fw->getConfig("networkmaps");

if (!is_array($nets)) {
	$nets = array();
}
// Add a blank one to the bottom..
$nets[" "] = "internal";

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
	render_network($net, $currentzone, $counter, $z);
}
?>
</table>
</form>
<?php

// Render the interface select
function render_network($name, $current, $counter, $zones) {
	print "<tr id='netcount-$counter' class='netzone' zone='$current' data-nextid='".($counter+1)."'>";
	// If name is empty, that means we want an input box.
	if (empty(trim($name))) {
		print "<td></td>";
		print "<td><input class='form-control' type='text' name='newentry' placeholder='"._("Enter new IP or Hostname here")."'></input></td>";
		$width = 'calc(100% - 4em)';
		$end = "<button type='button' class='btn x-btn btn-success pull-right' title='"._("Add New")."'><span class='glyphicon glyphicon-plus'></span></button>";
		$selname = "newentry";
	} else {
		print "<td><input type='checkbox'></td>";
		print "<td><tt>$name</tt></td>";
		$width = '100%';
		$end = "";
		$selname = "update-$counter";
	}
	print "<td class='netzone'><select style='width: $width; display: inline' class='form-control form-inline netsel' name='$selname' data-rowid='$counter'>";
	foreach ($zones as $zn => $zone) {
		if ($current === $zn) {
			$selected = "selected";
		} else {
			$selected = "";
		}
		print "<option value='$zn' $selected>".$zone['name']." (".$zone['summary'].")</option>";
	}
	print "</select>$end</td></tr>";
	print "<tr id='description-$counter' zone='$current' class='descrow'><td></td><td colspan=2><input class='form-control' type='text' name='descr-$counter' placeholder='"._("You can enter a short description for this network here.")."'></td></tr>";
}

