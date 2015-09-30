<?php
$services = $fw->getServices();
$z = $fw->getZones();

$coresvc = $services['core'];
$extrasvc = $services['extra'];
$customsvc = $services['custom'];
?>

<p><?php echo _("This page displays the detected ports and port ranges for all known services."); ?></p>
<h3><?php echo _("Core Services"); ?></h3>
<?php
foreach ($coresvc as $svc) {
	displayService($fw, $svc);
}
?>
<h3><?php echo _("Extra Services"); ?></h3>
<?php
foreach ($extrasvc as $svc) {
	displayService($fw, $svc);
}
?>
<h3><?php echo _("Custom Services"); ?></h3>
<?php
if (!$customsvc) {
	echo "<p>"._("No Custom services defined.")."</p>";
} else {
	foreach ($customsvc as $svc) {
		displayService($fw, $svc);
	}
}

function displayService($fw, $svc) {
	if (is_array($svc)) {
		$s = $svc;
		$err = _("See Custom Service page");
	} else {
		$s = $fw->getService($svc);
		$err = _("Service unavailable");
	}
	print "<div class='element-container'><div class='row'><div class='col-sm-4'><h4>".$s['name']."</h4></div>\n";
	if (!isset($s['fw']) || !is_array($s['fw'])) {
		print "<div class='col-sm-8'>$err</div>";
	} else {
		print "<div class='col-sm-8'>";
		$protocols = array("udp" => array(), "tcp" => array());
		foreach ($s['fw'] as $e) {
			$protocols[$e['protocol']][] = $e['port'];
		}
		if (!$protocols['udp']) {
			// Don't display anything if it doesn't use that protocol.
			// print "    <div class='col-sm-12 col-md-12'>"._("Does not use UDP")."</div>\n";
		} elseif (count($protocols['udp']) == 1) {
			print "    "._("UDP Port:")."\n";
			print "    ".$protocols['udp'][0]." <br/>\n";
		} else {
			print "    "._("UDP Ports:")."\n";
			print "    ".join(", ", $protocols['udp'])."<br/>\n";
		}

		if (!$protocols['tcp']) {
			// Don't display anything if it doesn't use that protocol.
			// print "    <div class='col-sm-12'>"._("Does not use TCP")."</div>\n";
		} elseif (count($protocols['tcp']) == 1) {
			print "    "._("TCP Port:")."\n";
			print "    ".$protocols['tcp'][0]."<br/>\n";
		} else {
			print "    "._("TCP Ports:")."\n";
			print "    ".join(", ", $protocols['tcp'])."<br/>\n";
		}
		print "</div>\n";
	}
	if (!empty($s['guess'])) {
		print "<div class='col-sm-10 col-sm-offset-1'><div class='alert alert-warning'>".$s['guess']."</div></div>";
	}
	print "</div>\n";
	print "</div>\n";
}



