<?php
$ssf = _("System Firewall");

?>
<h3><?php echo $ssf; ?></h3>
<?php
$docs = array(
	"$ssf "._("is a fully integrated and tightly coupled firewall that constantly monitors the remote clients allowed to connect to this machine, and automatically allows access from valid hosts."),
	_("This is done by a small process that runs on your FreePBX server that automatically updates firewall rules based on the current trunk and extension configuration of FreePBX."),
	_("When 'Safe Mode' is enabled, if this machine is rebooted <strong>twice</strong> within 5 minutes, the firewall will be disabled for 5 minutes after the second reboot. This is useful when originally setting up your Firewall, as it allows you an easy way to recover from an accidental misconfiguration."),
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

$safemode = _("Safe Mode");
$ena = _("Available");
$dis = _("Disabled");

// If Safe mode is enabled, show the warning to turn it off.
if ($fw->isSafemodeEnabled()) {
	$style = "";
	$senabled = "checked";
	$sdisabled = "";
} else {
	$style = "display: none";
	$senabled = "";
	$sdisabled = "checked";
}

print "<div class='alert alert-info' id='safewarning' style='$style'>";
$docs = array(
	_("<strong>Safe mode is available.</strong>"),
	_("Safe mode can bet used when setting up your Firewall for the first time. It gives you the ability to recover from an accidental misconfiguration by temporarily disabling the firewall if the machine is rebooted two times in succession."),
	_("After the original configuration is complete, there is no reason to keep this turned on."),
);
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
      <button type='submit' name='action' value='disablefw' class='btn btn-default'><?php echo _("Disable Firewall"); ?></button>
    </div>
  </div>
</div>

<div class='row'>
  <div class='form-horizontal clearfix'>
    <div class='col-sm-4'>
      <label class='control-label' for='safemode'><?php echo $safemode; ?></label>
    </div>
    <div class='col-sm-8'>
      <span class='radioset'>
	<input type='radio' class='safemode' name='safemode' id='sena' value='enabled' <?php echo $senabled; ?>><label for='sena'><?php echo $ena; ?></label>
	<input type='radio' class='safemode' name='safemode' id='sdis' value='disabled' <?php echo $sdisabled; ?>><label for='sdis'><?php echo $dis; ?></label>
      </span>
    </div>
  </div>
</div>

<div class='row'>
  <div class='form-horizontal clearfix'>
    <div class='col-sm-4'>
      <label class='control-label' for='ssfwiz'><?php echo _("Firewall Wizard"); ?></label>
    </div>
    <div class='col-sm-8'>
      <button type='button' class='btn btn-default' id='rerunwiz'><?php echo _("Re-Run Wizard"); ?></button>
    </div>
  </div>
</div>

<?php
$ftype = _("Filter Type");
$reject = _("Reject");
$drop = _("Drop");

if ($fw->getConfig("dropinvalid")) {
	$rdrop = "checked";
	$rreject = "";
} else {
	$rdrop = "";
	$rreject = "checked";
}
?>

<div class='row'>
  <div class='form-horizontal clearfix'>
    <div class='col-sm-4'>
      <label class='control-label' for='rejmode'><?php echo $ftype; ?></label>
    </div>
    <div class='col-sm-8'>
      <span class='radioset'>
	<input type='radio' class='rejmode' name='rejmode' id='rreject' value='reject' <?php echo $rreject; ?>><label for='rreject'><?php echo $reject; ?></label>
	<input type='radio' class='rejmode' name='rejmode' id='rdrop' value='drop' <?php echo $rdrop; ?>><label for='rdrop'><?php echo $drop; ?></label>
      </span>
    </div>
  </div>
</div>

<script type='text/javascript'>
$(document).ready(function() { 
	$("#rerunwiz").click(function() {
		// Restart oobe
		$.ajax({
			url: window.ajaxurl,
			data: { command: 'restartoobe', module: 'firewall' },
			success: function(data) { window.location.reload(); },
		});
	});
});
</script>
