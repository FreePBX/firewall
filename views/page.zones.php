<form method='post'>
<div class="display no-border">
  <div class="nav-container">
    <ul class="nav nav-tabs list" role="tablist">
      <li role="presentation" data-name="zonedocs" class="active">
        <a href="#zonedocs" aria-controls="zonedocs" role="tab" data-toggle="tab"><?php echo _("Zone Information")?> </a>
      </li>
      <li role="presentation" data-name="zonesettings">
        <a href="#zonesettings" aria-controls="zonesettings" role="tab" data-toggle="tab"><?php echo _("Zone Assignments")?> </a>
      </li>
    </ul>
    <div class="tab-content display">
      <div role="tabpanel" id="zonedocs" class="tab-pane active">
        <h3><?php echo _("About Zones"); ?></h3>
<?php
echo "<p>"._("Each network interface on your machine must be mapped to a Zone. Note that, by default, all interfaces are mapped to trusted (Trusted networks are not filtered at all, so this disables the firewall for any traffic coming in from that interface). The zones you can use are:")."</p>";
echo "<ul>";
$z = $fw->getZones();
foreach ($z as $zone) {
	print "<li><strong>".$zone['name']."</strong><br/>".$zone['descr']."</li>\n";
}
echo "</ul>";
?>

      </div>
      <div role="tabpanel" id="zonesettings" class="tab-pane">
      <p><?php echo _("Please assign a zone to all interfaces. Note that 'Trusted' means that <strong>no filtering</strong> will be applied to this interface. 'Reject' means <strong>no inbound connections will be permitted</strong> to that interface."); ?></p>
<?php
$ints = $fw->getInterfaces();

// This is for screenreaders. The IDs mean nothing.
$counter = 0;

foreach ($ints as $i => $conf) {
	$currentzone = $fw->getZone($i);
?>
<div class='element-container'>
  <div class='row'>
    <div class='col-md-3'>
      <label class='control-label' for='int-<?php echo $i; ?>'><?php echo $i;?></label>
    </div>
    <div class='col-md-9'>
      <span class='radioset'>
<?php
	foreach ($z as $zn => $zone) {
		if ($zn === $currentzone) {
			$active = "active";
			$checked = "checked";
		} else {
			$active = "";
			$checked = "";
		}
		print "<input type='radio' name='int-$i' id='int-$i-$zn' $checked><label for='int-$i-$zn'>".$zone['name']."</label>\n";
	}
?>
      </span>
    </div>
    <div class='col-md-9 col-md-offset-3'>
<?php
	if (empty($conf['addresses'])) {
		print _("No IP Addresses assigned to this interface.");
	} else {
		print _("IP Address(es): ");
		$tmparr = array();
		foreach ($conf['addresses'] as $ips) {
			$tmparr[] = $ips[0]."/".$ips[2];
		}
		print join(", ", $tmparr);
	}
?>
    </div>
  </div>
</div>
<?php // foreach ints
}
?>
      </div>
    </div>
  </div>
</div>

</form>
