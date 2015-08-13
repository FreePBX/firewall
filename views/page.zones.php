<?php
if (!isset($_REQUEST['tab'])) {
	$tab = "zonedocs";
} else {
	$tab = $_REQUEST['tab'];
}

$docs = "active";
$net = $int = "";

switch ($tab) {
case 'intsettings':
	$docs = "";
	$int = "active";
	break;
case 'netsettings':
	$docs = "";
	$net = "active";
	break;
}
?>

<script type='text/javascript' src='modules/firewall/assets/js/views/zones.js?1'></script>
<form method='post'>
<div class="display no-border">
  <div class="nav-container">
    <ul class="nav nav-tabs list" role="tablist">
    <li role="presentation" data-name="zonedocs" class="<?php echo $docs; ?>">
        <a href="#zonedocs" aria-controls="zonedocs" role="tab" data-toggle="tab"><?php echo _("Zone Information")?> </a>
      </li>
      <li role="presentation" data-name="intsettings" class="<?php echo $int; ?>">
        <a href="#intsettings" aria-controls="intsettings" role="tab" data-toggle="tab"><?php echo _("Interfaces")?> </a>
      </li>
      <li role="presentation" data-name="netsettings"  class="<?php echo $net; ?>">
        <a href="#netsettings" aria-controls="netsettings" role="tab" data-toggle="tab"><?php echo _("Networks")?> </a>
      </li>
    </ul>
    <div class="tab-content display">
    <div role="tabpanel" id="zonedocs" class="tab-pane <?php echo $docs; ?>">
        <h3><?php echo _("About Zones"); ?></h3>
<?php
echo "<p>"._("Each network interface on your machine must be mapped to a Zone. Note that, by default, all interfaces are mapped to trusted (Trusted networks are not filtered at all, so this disables the firewall for any traffic coming in from that interface). The zones you can use are:")."</p>";
echo "<ul>";
$z = $fw->getZones();
foreach ($z as $zone) {
	print "<li><strong>".$zone['name']."</strong><br/>".$zone['descr']."</li>\n";
}
echo "</ul>";
?>

      </div>
      <div role="tabpanel" id="intsettings" class="tab-pane <?php echo $int; ?>">
        <p><?php echo _("All interfaces must be assigned to a default zone. Any traffic entering this interface (that does not originate from a network in the Networks tab) is firewalled to the rules of that zone. Note that 'Trusted' means that <strong>no filtering</strong> will be applied to this interface. 'Reject' means <strong>no inbound connections will be permitted</strong> to that interface."); ?></p>
<?php
$ints = $fw->getInterfaces();

// This is for screenreaders. The IDs mean nothing.
$counter = 0;

foreach ($ints as $i => $conf) {
	$currentzone = $fw->getZone($i);
?>
<div class='element-container'>
  <div class='row'>
    <div class='col-md-3'>
      <label class='control-label' for='int-<?php echo $i; ?>'><?php echo $i;?></label>
    </div>
    <div class='col-md-9'>
      <span class='radioset'>
<?php
	foreach ($z as $zn => $zone) {
		if ($zn === $currentzone) {
			$active = "active";
			$checked = "checked";
		} else {
			$active = "";
			$checked = "";
		}
		print "<input type='radio' name='int-$i' id='int-$i-$zn' $checked><label for='int-$i-$zn'>".$zone['name']."</label>\n";
	}
?>
      </span>
    </div>
    <div class='col-md-9 col-md-offset-3'>
<?php
	if (empty($conf['addresses'])) {
		print _("No IP Addresses assigned to this interface.");
	} else {
		print _("IP Address(es): ");
		$tmparr = array();
		foreach ($conf['addresses'] as $ips) {
			$tmparr[] = $ips[0]."/".$ips[2];
		}
		print join(", ", $tmparr);
	}
?>
    </div>
  </div>
</div>
<?php // foreach ints
}
?>
      </div>

      <div role="tabpanel" id="netsettings" class="tab-pane <?php echo $net; ?>">
	<p><?php echo _("Individual networks may be specified to override the default rule for an interface. For example, if interface eth0 is assigned to the 'External' zone, you can add a specific <strong>source</strong> network to the 'Trusted' zone. This will override the default rule for that interface, so traffic from that network will be treated as 'Trusted',  whilst all traffic NOT originating from that network is Filtered by the default rules."); ?></p>
        <p><?php echo _("Note that several common settings are available on the 'Advanced' page."); ?></p>
<?php
$nets = $fw->getZoneNetworks();
// Add a blank one to the bottom..
$nets[" "] = "trusted";

$z = $fw->getZones();

// Now, loop through our networks and display them.
$counter = 1;
foreach ($nets as $net => $currentzone) {
	if (trim($net)) {
		$ro = "readonly disabled";
	} else {
		$ro = "";
	}
?>
        <div class='element-container' id='element-<?php echo $counter; ?>'>
          <div class='row'>
            <div class='col-sm-4 col-md-3'>
              <input type='text' name='netname[<?php echo $counter; ?>]' value='<?php echo $net; ?>' <?php echo $ro; ?>>
            </div>
            <div class='col-sm-8 col-md-9'>
              <span class='radioset'>
<?php
	// Display the buttons
	foreach ($z as $zn => $zone) {
		if ($zn == "reject") {
			// Don't show 'reject', as it's not intuitive. It adds a network to an
			// interface that's defined as reject, so that'll be PERMITTED, and..
			// yeah. Let's just avoid that.
			continue;
		}
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
		print "<button type='button' class='btn x-btn x-btn-danger fwbutton' data-counter='$counter' data-action='remove'><span class='glyphicon glyphicon-remove'></span></button>";
		print "<button type='button' class='btn x-btn x-btn-warning fwbutton' data-counter='$counter' data-action='update'><span class='glyphicon glyphicon-pencil'></span></button>";
	} else {
		// Or a '+' add if it is.
		print "<button type='button' class='btn btn-success x-btn x-btn-success fwbutton' data-counter='$counter' data-action='create'><span class='glyphicon glyphicon-plus'></span></button>";
	}
?>
            </div>
          </div>
        </div>
<?php
	$counter++;
} // foreach $nets
?>
      </div>
    </div>
  </div>
</div>

</form>
