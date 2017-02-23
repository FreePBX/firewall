<div class='container-fluid'>

<h3><?php echo _("Advanced Settings"); ?></h3>

<?php
// i18n common things
$ena = _("Enabled");
$dis = _("Disabled");

$advanced = $fw->getAdvancedSettings();

$sections = array(
	"safemode" => array( "desc" => _("Safe Mode"), "values" => array("enabled" => $ena, "disabled" => $dis), "docs" => array(
		_("Safe mode gives you the ability to recover from an accidental misconfiguration by temporarily disabling the firewall if the machine is rebooted two times in succession."),
		_("This should be disabled if there is the possibility of malicious individuals rebooting your machine without your knowledge. Otherwise it should be left <strong>Enabled</strong>"),
		),
	),
	/*
	 * Disabled - unused. Masq is always on, there's no reason to turn it off.
	"masq" => array( "desc" => _("Outbound Masquerading"), "values" => array("enabled" => $ena, "disabled" => $dis), "docs" => array(
		_("This enables the 'MASQUERADE' iptables rule for any traffic that is <strong>FORWARDED</strong> through this machine."),
		_("<strong>This does not enable forwarding!</strong> To enable forwarding, you need to enable the sysctl parameters 'net.ipv4.ip_forward' and 'net.ipv6.ip_forward' manually. If those settings are not enabled, this option has no effect."),
		_("Masquerading is only done for traffic that is being transmitted out an interface that is assigned to the 'Internet' zone. This setting should be <strong>Enabled</strong> unless you have a complex network environment."),
		),
	),
	 */
	"customrules" => array( "desc" => _("Custom Firewall Rules"), "values" => array("enabled" => $ena, "disabled" => $dis), "docs" => array(
		_("This authorizes the system to import custom iptables rules after the firewall has started."),
		_("The files /etc/firewall-4.rules and /etc/firewall-6.rules (for IPv4 and IPv6 rules) must be owned by the 'root' user and not writable by any other user. Each line in the file will be given as a parameter to 'iptables' or 'ip6tables, respectively."),
		_("This allows expert users to customize the firewall to their specifications. This should be <strong>Disabled</strong> unless you explicitly know why it is enabled."),
		),
	),
	"rejectpackets" => array( "desc" => _("Reject Packets"), "values" => array("enabled" => $ena, "disabled" => $dis), "docs" => array(
		_("This configures what happens when a packet is received by the Firewall that <strong>will not be allowed</strong> through to the system."),
		_("Enabling 'Reject Packets' sends an explicit response to the other machine, telling them that their traffic has been administratively blocked. Leaving this disabled silently discards the packet, giving no indication to the attacker that their traffic has been intercepted."),
		_("By sending a Reject packet, the attacker knows that they have discovered a machine. By dropping the packet silently, no response is sent to the attacker, and they may move on to a different target."),
		_("Normally this should be set to <strong>Disabled</strong> unless you are debugging network connectivity."),
		),
	),
);

foreach ($sections as $key => $tmparr) {
	if (!isset($advanced[$key])) {
		throw new \Exception("Advanced setting '$key' is unknown");
	}
	$current = $advanced[$key];

	print "<div class='well'><h4>".$tmparr['desc']."</h4>";
	foreach ($tmparr['docs'] as $row) {
		print "<p>$row</p>";
	}
	print "<div class='row'><div class='form-horizontal clearfix'><div class='col-sm-4'>";
	print "<label class='control-label' for='$key'>".$tmparr['desc']."</label></div>";
	print "<div class='col-sm-8'><span class='radioset'>";
	foreach ($tmparr['values'] as $k => $v) {
		if ($current === $k) {
			$checked = "checked";
		} else {
			$checked = "";
		}
		print "<input $checked type='radio' class='advsetting $key' name='$key' id='${key}_$k' value='$k' ><label for='${key}_$k'>$v</label>";
	}
	print "</span> </div> </div> </div> </div>";
}

print "</div>";

