<?php
if (!isset($_REQUEST['tab'])) {
	$tab = "about";
} else {
	$tab = $_REQUEST['tab'];
}
$about = "active";
$smart = $shortcuts = $services = "";

switch ($tab) {
case 'smart':
	$about = "";
	$smart = "active";
	break;
case 'shortcuts':
	$about = "";
	$shortcuts = "active";
	break;
case 'services':
	$about = "";
	$services = "active";
	break;
}

$ss = $fw->getSmartSettings();

?>

<script type='text/javascript' src='modules/firewall/assets/js/views/advanced.js'></script>
<form method='post'>
<div class="display no-border">
  <div class="nav-container">
    <ul class="nav nav-tabs list" role="tablist">
      <li role="presentation" data-name="about" class="<?php echo $about; ?>">
        <a href="#about" aria-controls="about" role="tab" data-toggle="tab"><?php echo _("Settings")?> </a>
      </li>
      <li role="presentation" data-name="smart" class="<?php echo $smart; ?>">
        <a href="#smart" aria-controls="smart" role="tab" data-toggle="tab"><?php echo _("Responsive Firewall")?> </a>
      </li>
      <li role="presentation" data-name="shortcuts" class="<?php echo $shortcuts; ?>">
        <a href="#shortcuts" aria-controls="shortcuts" role="tab" data-toggle="tab"><?php echo _("Preconfigured")?> </a>
      </li>
      <li role="presentation" data-name="services" class="<?php echo $services; ?>">
        <a href="#services" aria-controls="services" role="tab" data-toggle="tab"><?php echo _("Port/Service Maps")?> </a>
      </li>
    </ul>
    <div class="tab-content display">
      <div role="tabpanel" id="about" class="tab-pane <?php echo $about; ?>">
        <div class='container-fluid'>
          <?php echo load_view(__DIR__."/view.about.php", array("smart" => $ss, "fw" => $fw)); ?>
        </div>
      </div>
      <div role="tabpanel" id="smart" class="tab-pane <?php echo $smart; ?>">
        <div class='container-fluid'>
          <?php echo load_view(__DIR__."/view.smart.php", array("smart" => $ss)); ?>
        </div>
      </div>
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
      <div role="tabpanel" id="shortcuts" class="tab-pane <?php echo $shortcuts; ?>">
        <div class='container-fluid'>
	  <p><?php echo _("This allows you to simply add a pre-configured set of networks to your trusted zone. Once you have added your selections, you can fine-tune them, if required, <a href='?display=firewall&page=zones&tab=netsettings'>on the Networks tab.</a>"); ?></p>
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
        </div>
      </div>
      <div role="tabpanel" id="services" class="tab-pane <?php echo $services; ?>">
        <div class='container-fluid'>
          <?php echo load_view(__DIR__."/view.portmaps.php", array("fw" => $fw)); ?>
        </div>
      </div>
    </div>
  </div>
</div>

</form>
