<?php
$ssf = "Sangoma "._("Smart Firewall");

$period = _("Refresh Period");

$tr = _("Temporary Registrations");
$to = _("Registration Timeout");

?>
<h3><?php echo $ssf; ?></h3>
<?php
$docs = array(
	"$ssf "._("is a fully integrated and tightly coupled firewall that constantly monitors the remote clients allowed to connect to this machine, and automatically allows access from expected hosts."),
	_("This is done by a small process that runs on your FreePBX server that automatically updates firewall rules based on the current trunk and extension configuration of FreePBX. When Smart Firewall is turned on, there is no need to explicitly add exclusions for SIP or IAX peers, and a best effort is made to automatically allow remote extensions through the firewall."),
);

foreach ($docs as $p) {
	print "<p>$p</p>\n";
}
print "<div class='row'>\n";

// Are we actually enabled?
if (isset($smart['ssf']) && $smart['ssf']) {
	$disabled = false;
} else {
	$disabled = true;
}

showRadio("ssf", $ssf, !$disabled, false);
showText("period", $period, $smart['period'], $disabled);
showRadio("tempreg", $tr, $smart['tempreg'], $disabled);
showText("tempregto", $to, $smart['tempregto'], $disabled);

print "</div>\n";

// Disabled is the prop disabled, not a value.
function showRadio($k, $title, $val = false, $disabled = false) {
	$ena = $dis = "";
	$e = _("Enabled");
	$d = _("Disabled");
	if ($val) {
		$ena = "checked";
	} else {
		$dis = "checked";
	}

	if ($disabled) {
		$pd = " disabled";
	} else {
		$pd = "";
	}
	print "<div class='form-horizontal clearfix'>\n";
	print " <div class='col-sm-4'>\n";
	print "  <label class='control-label' for='$k'>$title</label>\n";
	print " </div>\n";
	print " <div class='col-sm-8'>\n";
	print "  <span class='radioset'>\n";
	print "   <input type='radio' name='$k' id='${k}enabled' $ena $pd><label for='${k}enabled'>$e</label>\n";
	print "   <input type='radio' name='$k' id='${k}disabled' $dis $pd><label for='${k}disabled'>$d</label>\n";
	print "  </span>\n";
	print " </div>\n";
	print "</div>\n";
}

// Disabled is the prop disabled, not a value.
function showText($k, $title, $val = "0", $disabled = false) {
	if ($disabled) {
		$pd = " disabled";
	} else {
		$pd = "";
	}
	print "<div class='form-horizontal clearfix'>\n";
	print " <div class='col-sm-4'>\n";
	print "  <label class='control-label' for='$k'>$title</label>\n";
	print " </div>\n";
	print " <div class='col-sm-8'>\n";
	print "  <input class='form-control' type='text' name='$k' id='$k' value='$val' $pd>\n";
	print " </div>\n";
	print "</div>\n";
}

