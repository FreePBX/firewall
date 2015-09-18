<?php
$ssf = "Sangoma "._("Smart Firewall");

$period = _("Refresh Period");
$periods = array("normal" => _("Normal"), "fast" => _("Fast"), "slow" => _("Slow"));


?>
<h3><?php echo $ssf; ?></h3>
<?php
$docs = array(
	"$ssf "._("is a fully integrated and tightly coupled firewall that constantly monitors the remote clients allowed to connect to this machine, and automatically allows access from valid hosts."),
	_("This is done by a small process that runs on your FreePBX server that automatically updates firewall rules based on the current trunk and extension configuration of FreePBX.")
);

if ($smart['responsive']) {
	$docs[] = _("Responsive Firewall is <strong>enabled</strong>.");
	$docs[] = _("There is no need to explicitly add exclusions for SIP or IAX peers, as they are automatically allowed through the firewall after successfully registering.");
	$docs[] = _("After an endpoint is registered, an automatic firewall rule is additionally granted to allow that IP Address to access other services, as defined in the Smart Firewall tab");
} else {
	$docs[] = _("Responsive Firewall is <strong>not enabled</strong>.");
	$docs[] = _("Responsive Firewall allows your machine to automatically block attacks to your machine, and additionally permit valid clients access to services.");
}

$docs[] = _("The 'Refresh Period' is how often the firewall updates its rules. You would set it to 'fast' if you have many endpoints that are constantly registering and de-registering, or 'slow' if you are on a low powered machine.");

foreach ($docs as $p) {
	print "<p>$p</p>\n";
}
?>

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

