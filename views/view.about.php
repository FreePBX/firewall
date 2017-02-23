<div class='container-fluid'>
<?php
$ssf = _("System Firewall");

?>
<h3><?php echo $ssf; ?></h3>
<?php
$docs = array(
	"$ssf "._("is a fully integrated and tightly coupled firewall that constantly monitors the remote clients allowed to connect to this machine, and automatically allows access from valid hosts."),
	_("This is done by a small process that runs on your FreePBX server that automatically updates firewall rules based on the current trunk and extension configuration of FreePBX."),
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

if (file_exists("/etc/asterisk/firewall.lock")) {
	$candisable = false;
} else {
	$candisable = true;
}

?>

<div class='row'>
  <div class='form-horizontal clearfix'>
    <div class='col-sm-4'>
      <label class='control-label' for='ssf'><?php echo $ssf; ?></label>
    </div>
    <div class='col-sm-8'>
<?php if ($candisable) { ?>
      <button type='submit' name='action' value='disablefw' class='btn btn-default'><?php echo _("Disable Firewall"); ?></button>
<?php } else { ?>
      <button type='button' class='btn btn-info' disabled><?php echo _("Can not Disable Firewall"); ?></button>
<?php } ?>
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

<script type='text/javascript'>
$(document).ready(function() {
	$("#rerunwiz").click(function() {
		// Restart oobe
		$.ajax({
			url: window.FreePBX.ajaxurl,
			data: { command: 'restartoobe', module: 'firewall' },
			success: function(data) { window.location.reload(); },
		});
	});
});
</script>

</div>
