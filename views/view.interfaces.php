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
	$currentzone = $fw->getZone($i);
	render_interface($i, $currentzone, $conf, $counter, $z, $llen);
}
?>
</table>

</div>
<?php

// Render the interface select
function render_interface($name, $current, $conf, $counter, $zones, $llen) {
	print "<tr id='intcount-$counter' class='intzone' zone='$current' data-counter='$counter'>";
	print "<td style='width: ${llen}em '><tt counter='$counter'>".htmlentities($name, ENT_QUOTES)."</tt></td>";
	print "<td><select class='form-control' name='zone-$counter' data-rowid='$counter'>";
	foreach ($zones as $zn => $zone) {
		if ($current === $zn) {
			$selected = "selected";
		} else {
			$selected = "";
		}
		print "<option value='$zn' $selected>".$zone['name']." (".$zone['summary'].")</option>";
	}
	print "</select>";
	// var_dump($conf);
	print "</tr></td>";

	// Render the description box
	if (!isset($conf['config']['DESCRIPTION'])) {
		$desc = "";
	} else {
		$desc = htmlentities($conf['config']['DESCRIPTION'], ENT_QUOTES);
	}
	print "<tr id='intdescription-$counter' zone='$current' class='descrow'><td></td><td colspan=2><input counter='$counter' class='description $newentry form-control' type='text' name='descr-$counter' placeholder='"._("You can enter a short description for this interface here.")."' value='$desc'></td></tr>";
}

