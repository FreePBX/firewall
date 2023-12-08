<?php
// i18n common things
$ena = _("Enabled");
$leg = _("Legacy");
$dis = _("Disabled");

$advanced = $fw->getAdvancedSettings();
$sections = array(
	"safemode" => array( "desc" => _("Safe Mode"), "values" => array("enabled" => $ena, "disabled" => $dis), "docs" => array(
		_("Safe mode gives you the ability to recover from an accidental misconfiguration by temporarily disabling the firewall if the machine is rebooted two times in succession."),
		_("This should be disabled if there is the possibility of malicious individuals rebooting your machine without your knowledge. Otherwise it should be left <strong>Enabled</strong>"),
		),
	),
	"lefilter" => array( "desc" => _("Responsive LetsEncrypt Rules"), "values" => array("enabled" => $ena, "disabled" => $dis), "docs" => array(
		_("Allows <strong>temporary</strong> Internet zone access to the LetsEncrypt acme-challenge folder during an active certificate update request."),
		_("This should be <strong>Enabled</strong> unless you wish to manage LetsEncrypt access manually."),
		"<span style='font-size:smaller;'>"._("Note: LetsEncrypt will always send challenge queries to port 80.  If this server is not listening on port 80, certificate requests will fail unless an upstream firewall or proxy redirects requests to the server port.")."</span>",
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
	"id_service" => array( "desc" => _("Intrusion Detection Service"), "values" => array("enabled" => $ena, "disabled" => $dis), "docs" => array(
		_("Enable / Disable Intrusion Detection service on boot.").
		"<br>"._("<strong>Enabled</strong>: This service will be started on boot.").
		"<br>"._("<strong>Disabled</strong>: This service will be stopped and Intrusion Detection will not run on boot. Intrusion Detection will be stopped as well."),
		),
	),
	"id_sync_fw" => array( "desc" => _("Intrusion Detection Sync Firewall"), "values" => array("enabled" => $ena, "legacy" => $leg), "docs" => array(
		_("<strong>Enabled</strong>: Automatically synchronize IPs from specific firewall zones to the whitelist. E.g: When you add to a trusted zone, local or otherwise, they will be added to the Intrusion Detection whitelist.").
		"<br>"._("<strong>Legacy</strong>: Intrusion Detection whitelist will work like in the past with no automated synchronization to the whitelist.")
		),
	),
	"import_hosts" => array( "desc" => _("Add etc/hosts as Trusted"), "values" => array("enabled" => $ena, "disabled" => $dis), "docs" => array(
		_("Automatically add hosts from file /etc/hosts to Trusted Zone").
		"<br>"._("<strong>Enabled</strong>: All hosts defined are added to the Trusted Zone (default)").
		"<br>"._("<strong>Disabled</strong>: Hosts defined in /etc/hosts are not added to Trusted Zone except localhost."),
		),
	),
);
$sa = $fw->sysadmin_info();
if(empty($sa) || (!empty($sa) && !FreePBX::Sysadmin()->isActivated())){
	unset($sections["id_service"]);
	unset($sections["id_sync_fw"]);
}
?>

<div class='container-fluid'>
	<h3><?php echo _("Advanced Settings"); ?></h3>

<?php
foreach ($sections as $key => $tmparr) {
	if (!isset($advanced[$key])) {
		throw new \Exception("Advanced setting '$key' is unknown");
	}
	$current = $advanced[$key];

	print "<div class='well'>";
	print "		<h4>".$tmparr['desc']."</h4>";
	foreach ($tmparr['docs'] as $row) {
		print "	<p>$row</p>";
	}
	print "		<div class=''>";
	print "			<div class='row form-horizontal clearfix'>";
	print "				<div class='col-sm-4'>";
	print "					<label class='control-label' for='$key'>".$tmparr['desc']."</label>";
	print "				</div>";
	print "				<div class='col-sm-8'>";
	print "					<span class='radioset'>";
	foreach ($tmparr['values'] as $k => $v) {
		if ($current === $k) {
			$checked = "checked";
		} else {
			$checked = "";
		}
		print "					<input $checked type='radio' class='advsetting $key' name='$key' id='{$key}_$k' value='$k' ><label for='{$key}_$k'>$v</label>";
	}
	print "					</span>";
	print "				</div>";
	print "			</div>";
	print "		</div>";
	print "</div>";
}
?>

</div>
