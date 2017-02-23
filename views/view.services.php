<div class='container-fluid'>
  <h3><?php echo _("Core Services"); ?></h3>
  <p><?php echo _("Services that are assigned to zones <strong>are accessible</strong> to connections matching the zones."); ?></p>
  <p><?php echo _("Note that the 'Reject' setting explicitly blocks that service totally, and can only be overridden by access from a Trusted Zone. This is functionally equivalent to turning off access from all zones, unless you are running an extra Firewall plugin."); ?></p>
<?php
foreach ($coresvc as $s) {
	$currentzones = array();
	$svc = $fw->getService($s);
	foreach ($svc['zones'] as $zone) {
		$currentzones[$zone] = true;
	}
	// Display the buttons
	displayService($s, $svc, $z, $currentzones);
} ?>
</div>

<?php

function displayService($sn, $svc, $z, $currentzones) {
	print "<div class='element-container'><div class='row'><div class='col-sm-3 col-md-4'><label class='control-label' for='svc[$sn]'>";
	print $svc['name']."</label></div><div class='col-sm-9 col-md-8 noright'><span class='radioset'>";
	// Display the buttons
	foreach ($z as $zn => $zone) {
		if (!$zone['selectable']) {
			continue;
		}
		if (isset($currentzones[$zn])) {
			$active = "active";
			$checked = "checked";
		} else {
			$active = "";
			$checked = "";
		}

		$disabled = "";
		$data = "data-svc='$sn'";
		$class = "svcbutton svc-$sn";
		if ($zn === "reject") {
		       if (isset($svc['noreject'])) {
			       $disabled = "disabled";
		       }
		       $class = "rejectbutton svc-$sn";
		} elseif (isset($svc['disabled'])) {
			$disabled = "disabled";
		}

		print "<input type='checkbox' class='$class' name='svc[$sn][$zn]' id='stuff-$sn-$zn' $data $checked $disabled><label for='stuff-$sn-$zn'>".$zone['name']."</label>\n";

		// We want 'Reject' to be seperate
		if ($zn === "reject") {
			print "</span><span class='radioset'>\n";
		}
	}
	print "</span></div>\n";
	
	// Help text.
	print "<div class='hidden-xs col-sm-11 col-sm-offset-1 col-md-12 col-md-offset-0'><span class='help-block'>".$svc['descr']."</span></div>\n";

	// /row and /element-container
	print "</div></div>\n";
}

