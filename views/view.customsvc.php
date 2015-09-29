<div class='container-fluid'>
<p><?php echo _("Custom services can be defined on this page. Please check to make sure you don't accidentally expose an automatically configured service by using the same port and protocol."); ?></p>
<button type='button' class='btn btn-default pull-right' id='newcust'><?php echo _("Create new Service"); ?></button>
<div class='clearfix'></div>
<h2><?php echo _("Custom Services"); ?></h2>
<?php
$z = $fw->getZones();
unset($z['reject']);
$cs = $fw->getServices();
$cs['custom'] = array(
	"1" => array(
		"name" => _("XSSH"),
		"defzones" => array("internal"),
		"descr" => _("SXSH is the most commonly used system administration tool. It is also a common target for hackers. We <strong>strongly recommend</strong> using a strong password and SSH keys."),
		"custfw" => array("protocol" => "tcp", "port" => 22),
		"noreject" => true,
	),
);
if (empty($cs['custom'])) {
	echo "<p>"._("No custom services currently defined.")."</p>";
} else {
	foreach ($cs['custom'] as $sid => $service) {
		displayCustomService($service, $sid, $z,  array("trusted" => "trusted"));
	}
}
?>
</div>

<?php

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
		$data = "data-svc='$svcid'";
		$class = "csbutton";

		print "<input type='checkbox' class='$class' name='csvc-$svcid' id='csvc-$svcid-$zn' $data $checked $disabled><label for='csvc-$svcid-$zn'>".$zone['name']."</label>\n";

	}
	print "</span>\n";
	print "<button type='button' class='btn x-btn btn-success csbutton' data-action='save' data-svcid='$svcid' title='"._("Save")."'><span data-action='save' data-svcid='$svcid' class='glyphicon glyphicon-ok'></span></button>";
	print "<button type='button' class='btn x-btn btn-warning csbutton' data-action='edit' data-svcid='$svcid' title='"._("Edit")."'><span data-action='edit' data-svcid='$svcid' class='glyphicon glyphicon-pencil'></span></button>";
	print "<button type='button' class='btn x-btn btn-danger csbutton' data-action='remove' data-svcid='$svcid' title='"._("Delete")."'><span data-action='remove' data-svcid='$svcid' class='glyphicon glyphicon-remove'></span></button>";
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
	if (substr(":", $c['port']) !== false) {
		$port = sprintf(_("Port Range: %s"), $c['port']);
	} elseif (substr(",", $c['port']) !== false) {
		$port = sprintf(_("Selected Ports: %s"), $c['port']);
	} else {
		// Single port!
		$port = sprintf(_("Single Port: %s"), (int) $c['port']);
	}

	print "<div class='hidden-xs col-sm-11 col-sm-offset-1 col-md-10 col-md-offset-2'><span class='help-block'>$protocol</br>$port</span></div>\n";

	// /row and /element-container
	print "</div></div>\n";
}


