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
    <div class='col-sm-3'>
      <input type='text' name='netname[<?php echo $counter; ?>]' value='<?php echo $net; ?>'>
    </div>
    <div class='col-sm-8 noright'>
      <div class='btn-group' data-toggle='buttons'>
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
		print "<label class='btn btn-primary $active'><input type='radio' name='int-$counter' $checked>".$zone['name']."</label>\n";
	}
?>
      </div>
    </div>
    <div class='col-sm-1 noleft'>
<?php
	// Add the 'remove' X if the net isn't empty
	if (trim($net)) {
		print "<button type='button' class='btn x-btn x-btn-danger noleft'><span class='glyphicon glyphicon-remove'></span></button>";
	} else {
		// Or a '+' add if it is.
		print "<button type='button' class='btn x-btn x-btn-success noleft'><span class='glyphicon glyphicon-plus'></span></button>";
	}
?>
    </div>
  </div>
</div>
<?php
} // foreach nets
$counter++;
?>
      </div>
      <div role="tabpanel" id="shortcuts" class="tab-pane">
	<p><?php echo _("This covers a pre-configured set of networks to ease configuration. Setting a network to 'No Assignment' does <strong>not</strong> override an assignment in the 'Networks' tab."); ?></p>
      </div>
      <div role="tabpanel" id="overrides" class="tab-pane">
        <p>Stuff about overrides here...</p>
      </div>
    </div>
  </div>
</div>

</form>
