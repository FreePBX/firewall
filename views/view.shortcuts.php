<?php
// Text for Shortcuts is here
$rfc = array(
	_("RFC1918/RFC4193"),
	_("RFC1918 and RFC4193 are the RFCs that define the reserved, internal, network address space to be used when you're not directly connected to the internet, or do not want your address space routable. This adds the IPv4 networks 192.168.0.0/16, 172.16.0.0/12, and 10.0.0.0/8 and IPv6 networks fc00::/8 and fd00::/8 to the 'Trusted' zone, and excludes it from all firewalls."),
       _("<strong>Important Warning!</strong> If you are in a hosted environment (for example, AWS) and you enable this, you may be inadvertently allowing other hosted clients unrestricted access to your machine! Please use common sense to make sure that you are only allowing known trusted networks."),
	_("Add to Trusted"),
);

$ym = array(
	_("Your Client"),
	_("This explicitly grants permission to the machine that is managing the firewall service now. If you select 'Add Network', it will add the entire network that the server sees you coming from (%s), or if you select 'Add Host' it will only add the individual IP address (%s). When starting to configure your firewall, it is wise to enable this to ensure you don't lock yourself out of your machine."),
	_("If you are coming from an IPv6 Network, it <strong>not recommended</strong> to only add your 'Host', as MAC address changes, or IPv6 Security Extensions, will randomly and unexpectedly change your IP address. Ensure you add the complete network."),
	_("Add Network"),
	_("Add Host"),
);

$thisnet = $fw->detectNetwork();
$thishost = $fw->detectHost();

?>
<div class='container-fluid'>
  <p><?php echo sprintf(_("This allows you to simply add a pre-configured set of networks to your trusted zone. Once you have added your selections, you can fine-tune them, if required, %s on the Networks tab. %s"), "<a href='?display=firewall&page=about&tab=networks'>", "</a>") ; ?></p>
  <div class='panel panel-default'>
    <div class='panel-body'>
      <h3><?php echo $rfc[0]; ?></h3>
      <p><?php echo $rfc[1]; ?></p>
      <p><?php echo $rfc[2]; ?></p>
    </div>
    <div class='panel-footer clearfix'>
<?php
$e = _("Present");
if ($fw->rfcNetsAdded()) {
	echo "<button type='button' class='btn btn-default pull-right' disabled>$e</button>\n";
} else {
	echo "<button type='button' class='btn btn-default pull-right' id='addrfc'>$rfc[3]</button>\n";
}
?>
    </div>
  </div>
  <div class='panel panel-default'>
    <div class='panel-body'>
      <h3><?php echo $ym[0]; ?></h3>
      <p><?php printf($ym[1], $thisnet, $thishost); ?></p>
      <p><?php echo $ym[2]; ?></p>
    </div>
  </div>
  <div class='panel-footer clearfix'>
<?php
if ($fw->thisNetAdded()) {
	echo "<button type='button' class='btn btn-default pull-right' disabled>$e</button>\n";
} else {
	echo "<button type='button' class='btn btn-default pull-right' id='addnetwork'>$ym[3]</button>\n";
}
if ($fw->thisHostAdded()) {
	echo "<button type='button' class='btn btn-default pull-right' disabled>$e</button>\n";
} else {
	echo "<button type='button' class='btn btn-default pull-right' id='addhost'>$ym[4]</button>\n";
}
?>
  </div>
</div>
