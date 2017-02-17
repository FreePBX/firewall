<div class='container-fluid'>

<h3><?php echo _("Advanced Settings"); ?></h3>

<?php
// i18n common things
$ena = _("Enabled");
$dis = _("Disabled");

$sections = array(
	"safemode" => array( "desc" => _("Safe Mode"), "values" => array("enabled" => $ena, "disabled" => $dis), "docs" => array(
		_("Safe mode gives you the ability to recover from an accidental misconfiguration by temporarily disabling the firewall if the machine is rebooted two times in succession."),
		_("This should be disabled if there is the possibility of malicious individuals rebooting your machine without your knowledge. Otherwise it should be left <strong>Enabled</strong>"),
		),
	),
	"masq" => array( "desc" => _("Outbound Masquerading"), "values" => array("enabled" => $ena, "disabled" => $dis), "docs" => array(
		_("This enables the 'MASQUERADE' iptables rule for any traffic that is <strong>FORWARDED</strong> through this machine."),
		_("<strong>This does not enable forwarding!</strong> To enable forwarding, you need to enable the sysctl parameters 'net.ipv4.ip_forward' and 'net.ipv6.ip_forward' manually. If those settings are not enabled, this option has no effect."),
		_("Masquerading is only done for traffic that is being transmitted out an interface that is assigned to the 'Internet' zone. This setting should be <strong>Enabled</strong> unless you have a complex network environment."),
		),
	),
	"customrules" => array( "desc" => _("Custom Firewall Rules"), "values" => array("enabled" => $ena, "disabled" => $dis), "docs" => array(
		_("This authorizes the system to import custom iptables rules after the firewall has started."),
		_("The files /etc/firewall-4.rules and /etc/firewall-6.rules (for IPv4 and IPv6 rules) must be owned by the 'root' user and not writable by any other user. Each line in the file will be given as a parameter to 'iptables' or 'ip6tables, respectively."),
		_("This allows expert users to customize the firewall to their specifications. This should be <strong>Disabled</strong> unless you explicitly know why it is enabled."),
		),
	),
);

foreach ($sections as $key => $tmparr) {
	print "<div class='well'><h4>".$tmparr['desc']."</h4>";
	foreach ($tmparr['docs'] as $row) {
		print "<p>$row</p>";
	}
	print "<div class='row'><div class='form-horizontal clearfix'><div class='col-sm-4'>";
	print "<label class='control-label' for='$key'>".$tmparr['desc']."</label></div>";
	print "<div class='col-sm-8'><span class='radioset'>";
	foreach ($tmparr['values'] as $k => $v) {
		print "<input type='radio' class='$key' name='$key' id='${key}_$k' value='$k' ><label for='${key}_$k'>$v</label>";
	}
	print "</span> </div> </div> </div> </div>";
}

print "</div>";

