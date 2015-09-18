<?php
$ssf = "Sangoma "._("Smart Firewall");

$period = _("Refresh Period");
$periods = array("normal" => _("Normal"), "fast" => _("Fast"), "slow" => _("Slow"));


?>
<h3><?php echo $ssf; ?></h3>
<?php
$docs = array(
	"$ssf "._("is a fully integrated and tightly coupled firewall that constantly monitors the remote clients allowed to connect to this machine, and automatically allows access from valid hosts."),
	_("This is done by a small process that runs on your FreePBX server that automatically updates firewall rules based on the current trunk and extension configuration of FreePBX."),
	_("The 'Refresh Period' is how often the firewall updates its rules. You would set it to 'fast' if you have many endpoints that are constantly registering and de-registering, or 'slow' if you are on a low powered machine."),
);

foreach ($docs as $p) {
	print "<p>$p</p>\n";
}
if (!$smart['responsive']) {
	print "<div class='alert alert-warning'>";
	$docs = array(
		_("<strong>Responsive Firewall is not enabled</strong>."),
		_("Responsive Firewall allows your machine to automatically block attacks to your machine, while learning and automatically granting permission to authorized devices, without the need to manually configure them."),
		_("You can enable Responsive Firewall in the 'Responsive Firewall' tab."),
	);
} else {
	print "<div class='alert alert-success'>";
	$docs = array(
		_("Responsive Firewall is <strong>enabled</strong>."),
		_("There is no need to explicitly add definitions for peers, as they are automatically allowed through the firewall after successfully registering."),
		_("After an endpoint is registered, the source of that endpoint is <strong>automatically granted</strong> permission to use UCP, if UCP is enabled."),
	);
}
foreach ($docs as $p) {
	print "<p>$p</p>\n";
}
print "</div>";
?>

<div class='row'>
  <div class='form-horizontal clearfix'>
    <div class='col-sm-4'>
      <label class='control-label' for='ssf'><?php echo $ssf; ?></label>
    </div>
    <div class='col-sm-8'>
      <button type='submit' name='action' value='disablefw' class='btn btn-default'><?php echo _("Disable"); ?></button>
    </div>
  </div>
</div>

<div class='row'>
  <div class='form-horizontal clearfix'>
    <div class='col-sm-4'>
      <label class='control-label' for='period'><?php echo $period; ?></label>
    </div>
    <div class='col-sm-8'>
      <select class='form-control' id='period'>
<?php
$current = \FreePBX::Firewall()->getConfig('refreshperiod');
if (!$current) {
	$current = "normal";
	\FreePBX::Firewall()->setConfig('refreshperiod', 'normal');
}

foreach ($periods as $name => $val) {
	if ($current == $name) {
		$selected = "selected";
	} else {
		$selected = "";
	}
	print "<option value='$name' $selected>$val</option>\n";
}
?>
      </select>
    </div>
  </div>
</div>


