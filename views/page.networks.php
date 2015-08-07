<form method='post'>
<div class="display no-border">
  <div class="nav-container">
    <ul class="nav nav-tabs list" role="tablist">
      <li role="presentation" data-name="networks" class="active">
        <a href="#networks" aria-controls="networks" role="tab" data-toggle="tab"><?php echo _("Networks")?> </a>
      </li>
      <li role="presentation" data-name="shortcuts">
        <a href="#shortcuts" aria-controls="shortcuts" role="tab" data-toggle="tab"><?php echo _("Preconfigured")?> </a>
      </li>
      <li role="presentation" data-name="overrides">
        <a href="#overrides" aria-controls="overrides" role="tab" data-toggle="tab"><?php echo _("Smart Overrides")?> </a>
      </li>
    </ul>
    <div class="tab-content display">
      <div role="tabpanel" id="networks" class="tab-pane active">
	<p><?php echo _("Individual networks may be specified to override the default rule for an interface. For example, if interface eth0 is configured to use the 'Block' zone, you could add a source network to the 'Trusted' zone, whilst all traffic NOT originating from that network is Blocked."); ?></p>
        <p><?php echo _("Note that several common settings are available in the 'Preconfigured' tab."); ?></p>
<?php
$nets = $fw->getZoneNetworks();
// Add a blank one to the bottom..
$nets[" "] = "trusted";

$z = $fw->getZones();

// Now, loop through our networks and display them.
$counter = 1;
foreach ($nets as $net => $currentzone) {
?>
<div class='element-container'>
  <div class='row'>
    <div class='col-sm-4 col-md-3'>
      <input type='text' name='netname[<?php echo $counter; ?>]' value='<?php echo $net; ?>'>
    </div>
    <div class='col-sm-8 col-md-9'>
      <span class='radioset'>
<?php
	// Display the buttons
	foreach ($z as $zn => $zone) {
		if ($zn === $currentzone) {
			$active = "active";
			$checked = "checked";
		} else {
			$active = "";
			$checked = "";
		}
		print "<input type='radio' name='net-$counter' id='net-$counter-$zn' value='$zn' $checked><label class='$active' for='net-$counter-$zn'>".$zone['name']."</label>\n";
	}
?>
      </span>
<?php
	// Add the 'remove' X if the net isn't empty
	if (trim($net)) {
		print "<button type='button' class='btn x-btn x-btn-danger'><span class='glyphicon glyphicon-remove'></span></button>";
	} else {
		// Or a '+' add if it is.
		print "<button type='button' class='btn x-btn x-btn-success'><span class='glyphicon glyphicon-plus'></span></button>";
	}
?>
    </div>
  </div>
</div>
<?php
$counter++;
} // foreach nets

// Text for Shortcuts is here
$rfc = array(
	_("RFC1918"),
	_("RFC1918 is the RFC that defineds the reserved, internal, network address space to be used when you're not directly connected to the internet. This adds 192.168.0.0/16, 172.16.0.0/12, and 10.0.0.0/8 to the 'Trusted' zone, and excludes it from all firewalls. Be warned that if you are in a hosted environment (for example, AWS), and you enable this, you may be inadvertently allowing other hosted clients unrestricted access to your machine."),
	_("Add to Trusted"),
);

$ym = array(
	_("Your Client"),
	_("This explicitly grants permission to the machine that is managing the firewall service now. If you select 'Add Network', it will add the entire Class C that the server sees you coming from (%s), or if you select 'Add Host' it will only add the individual IP address (%s). When starting to configure your firewall, it is wise to enable this to ensure you don't lock yourself out of your machine."),
	_("Add Network"),
	_("Add Host"),
);

$thisnet = $fw->detectNetwork();
$thishost = $fw->detectHost();

?>
      </div>
      <div role="tabpanel" id="shortcuts" class="tab-pane">
        <div class='container-fluid'>
	  <p><?php echo _("This allows you to simply add a pre-configured set of networks to your trusted zone. Once you have added your selections, you can fine-tune them, if required, on the Networks tab."); ?></p>
          <div class='panel panel-default'>
	    <div class='panel-body'>
	      <h3><?php echo $rfc[0]; ?></h3>
	      <p><?php echo $rfc[1]; ?></p>
            </div>
            <div class='panel-footer clearfix'>
	      <button type='button' class='btn btn-default pull-right'><?php echo $rfc[2]; ?></button>
            </div>
          </div>
          <div class='panel panel-default'>
            <div class='panel-body'>
	      <h3><?php echo $ym[0]; ?></h3>
	      <p><?php printf($ym[1], $thisnet, $thishost); ?></p>
            </div>
            <div class='panel-footer clearfix'>
	      <button type='button' class='btn btn-default pull-right'><?php echo $ym[2]; ?></button>
	      <button type='button' class='btn btn-default pull-right'><?php echo $ym[3]; ?></button>
            </div>
          </div>
        </div>
      </div>
      <div role="tabpanel" id="overrides" class="tab-pane">
        <p>Stuff about overrides here...</p>
      </div>
    </div>
  </div>
</div>

</form>
