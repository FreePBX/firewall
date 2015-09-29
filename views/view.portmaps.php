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
	$s = $fw->getService($svc);
	print "<div class='element-container'><div class='row'><div class='col-sm-4 col-md-3'><h4>".$s['name']."</h4></div>\n";
	print "<div class='col-sm-8 col-md-9'>";
	if (!isset($s['fw']) || !is_array($s['fw'])) {
		print _("Service unavailable");
	} else {
		$protocols = array("udp" => array(), "tcp" => array());
		foreach ($s['fw'] as $e) {
			$protocols[$e['protocol']][] = $e['port'];
		}
		print "<div class='cxontainer-fluid'>\n";
		if (!$protocols['udp']) {
			print "    <div class='col-sm-12 col-md-12'>"._("Does not use UDP")."</div>\n";
		} elseif (count($protocols['udp']) == 1) {
			print "    <div class='col-sm-3'>"._("UDP Port:")."</div>\n";
			print "    <div class='col-sm-9'> ".$protocols['udp'][0]." </div>\n";
		} else {
			print "    <div class='col-sm-3'>"._("UDP Ports:")."</div>\n";
			print "    <div class='col-sm-9'>".join(", ", $protocols['udp'])."</div>\n";
		}

		if (!$protocols['tcp']) {
			print "    <div class='col-sm-12'>"._("Does not use TCP")."</div>\n";
		} elseif (count($protocols['tcp']) == 1) {
			print "    <div class='col-sm-3'>"._("TCP Port:")."</div>\n";
			print "    <div class='col-sm-9'> ".$protocols['tcp'][0]."</div>\n";
		} else {
			print "    <div class='col-sm-3'>"._("TCP Ports:")."</div>\n";
			print "    <div class='col-sm-9'>".join(", ", $protocols['tcp'])."</div>\n";
		}
		print "</div>\n";
	}
	print "</div></div></div>\n";
}



