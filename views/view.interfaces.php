<div class='container-fluid'>
  <p><?php echo _("All interfaces must be assigned to a default zone. All traffic received by this physical interface will have access to services available to that zone, unless the traffic originates from an otherwise defined network."); ?></p>
  <p><?php echo _("Most interfaces should be set to <strong>Internet</strong>."); ?></p>
  <p><?php echo _("A 'Trusted' interface means that <strong>no filtering</strong> will be applied to any traffic arriving at that interface. Newly discovered interfaces are set to this zone so they can be configured correctly without interfering with existing traffic."); ?></p>
<?php
$fw = \FreePBX::Firewall();
$ints = $fw->getInterfaces();
$z = $fw->getZones();

// This is for screenreaders. The IDs mean nothing.
$counter = 0;

foreach ($ints as $i => $conf) {
	$currentzone = $fw->getZone($i);
	if (strpos($i, "tun") === 0) {
		$tun = true;
	} else {
		$tun = false;
	}
?>
<div class='element-container'>
  <div class='row'>
    <div class='col-md-3'>
      <label class='control-label' for='int-<?php echo $i; ?>'><?php echo $i;?></label>
    </div>
<?php render_interface($i, $parent, $z); ?>
    <div class='col-md-9 col-md-offset-3'>
<?php
	if ($tun) {
		print "<i><strong>"._("Note:")."</strong> "._("Tunnel interfaces are automatically assigned to the Internal zone")."</i><br>\n";
	}
	if (empty($conf['addresses'])) {
		print _("No IP Addresses assigned to this interface.");
	} else {
		if (count($conf['addresses']) > 1) {
			print _("IP Addresses: ");
		} else {
			print _("IP Address: ");
		}
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
<?php

// Render the interface select
function render_interface($name, $parent, $zones, $disabled = false) {
	$current = \FreePBX::Firewall()->getZone($name);
	print "<div class='col-md-8'><select class='form-control' name='derp'>";
	foreach ($zones as $zn => $zone) {
		if ($current === $zn) {
			$selected = "selected";
		} else {
			$selected = "";
		}
		print "<option value='$zn' $selected>".$zone['name']." (".$zone['summary'].")</option>";
	}
	print "</select></div>";
	if (!$disabled && strpos($name, "tun") !== 0) {
		print "<div class='col-md-1'><button type='button' class='pull-right btn x-btn btn-success intbutton $disabled' $disabled data-int='$name' data-action='update' title='"._("Save Changes")."'><span class='glyphicon glyphicon-ok' data-int='$name' data-action='update'></span></button></div>\n";
	}
}

