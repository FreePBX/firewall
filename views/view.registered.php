<div class='container-fluid'>

<h3><?php echo _("Successfully Registered Endpoints"); ?></h3>
<?php
$h = array(
	_("Below is a list of clients that have successfully registered and been validated by Responsive Firewall."),
	_("This does <strong>not</strong> include Endpoints that are already assigned to a Zone, or, Endpoints that were <strong>already registered</strong> when the firewall restarted, as they are automatically granted access. This is only for previously unknown hosts who have been authorized by Asterisk and granted access by the firewall."),
	_("This page (and all tabs) automatically update every 15 seconds."),
);

foreach ($h as $p) {
	print "<p>$p</p>\n";
}

$loading = _("Loading...");
$none = _("No Endpoints have been allowed through the Responsive Firewall");

?>
<h4 class='loading'><?php echo $loading; ?></h4>
<div id='noreged' class='alert alert-warning' style='display: none'><?php echo $none; ?></div>
<div class='notloading' id='regul'></div>

</div>
