<p><?php echo _("Custom services can be defined on this page. Please check to make sure you don't accidentally expose an automatically configured service by using the same port and protocol."); ?></p>
<button type='button' class='btn btn-default pull-right' id='newcust'><?php echo _("Create new Service"); ?></button>
<div class='clearfix'></div>
<h2><?php echo _("Custom Services"); ?></h2>
<?php

// We never want to show reject on this page.
unset($z['reject']);

if (empty($services['custom'])) {
	echo "<p>"._("No custom services currently defined.")."</p>";
} else {
	foreach ($services['custom'] as $sid => $service) {
		$currentzones = $fw->getCustomServiceZones($sid);
		displayCustomService($service, $sid, $z, $currentzones);
	}
}

function displayCustomService($svc, $svcid, $zones, $currentzones) {
	print "<div class='element-container'><div class='row'><div class='col-sm-3'><label class='control-label' for='csvc-$svcid'>";
	print $svc['name']."</label></div><div class='col-sm-9 noright'><span class='radioset'>";
	// Display the buttons
	foreach ($zones as $zn => $zone) {
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
		$data = "data-zone='$zn'";
		$class = "csbutton";

		print "<input type='checkbox' class='$class $svcid' name='csvc-$svcid-$zn' id='csvc-$svcid-$zn' $data $checked $disabled><label for='csvc-$svcid-$zn'>".$zone['name']."</label>\n";

	}
	print "</span>\n";
	print "<button type='button' class='btn x-btn btn-success csbutton $svcid' data-action='save' data-svcid='$svcid' title='"._("Save")."'><span data-action='save' data-svcid='$svcid' class='glyphicon glyphicon-ok'></span></button>";
	print "<button type='button' class='btn x-btn btn-warning csbutton $svcid' data-action='edit' data-svcid='$svcid' title='"._("Edit")."'><span data-action='edit' data-svcid='$svcid' class='glyphicon glyphicon-pencil'></span></button>";
	print "<button type='button' class='btn x-btn btn-danger csbutton $svcid' data-action='delete' data-svcid='$svcid' title='"._("Delete")."'><span data-action='delete' data-svcid='$svcid' class='glyphicon glyphicon-remove'></span></button>";
	print "</div>\n";
	
	// What does this service do?
	$c = $svc['custfw'];
	if ($c['protocol'] == "both") {
		$protocol = _("Protocol: TCP and UDP");
	} elseif ($c['protocol'] == "tcp") {
		$protocol = _("Protocol: TCP");
	} else {
		$protocol = _("Protocol: UDP");
	}

	// Port range?
	if (strpos($c['port'], ":") !== false) {
		$port = sprintf(_("Port Range: %s"), $c['port']);
	} elseif (strpos($c['port'], ",") !== false) {
		$port = sprintf(_("Multiple Ports: %s"), $c['port']);
	} else {
		// Single port!
		$port = sprintf(_("Single Port: %s"), (int) $c['port']);
	}

	print "<div class='hidden-xs col-sm-11 col-sm-offset-1 col-md-10 col-md-offset-2'><span class='help-block'>$protocol</br>$port</span></div>\n";

	// Used when editing
	print "<input type='hidden' id='csvc-$svcid' data-protocol='".$c['protocol']."' data-port='".$c['port']."' data-name='".htmlentities($svc['name'], \ENT_QUOTES, "UTF-8", false)."'>\n";

	// /row and /element-container
	print "</div></div>\n";
}


