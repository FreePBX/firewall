<form method='post'>

<div class="display no-border">
  <div class="nav-container">
    <ul class="nav nav-tabs list" role="tablist">
      <li role="presentation" data-name="services" class="active">
        <a href="#services" aria-controls="services" role="tab" data-toggle="tab"><?php echo _("Services")?></a>
      </li>
      <li role="presentation" data-name="customsvc">
        <a href="#customsvc" aria-controls="customsvc" role="tab" data-toggle="tab"><?php echo _("Custom Services")?></a>
      </li>
    </ul>
    <div class="tab-content display">
      <div role="tabpanel" id="services" class="tab-pane active">
	<p><?php echo _("Services that are assigned to zones <strong>are accessable</strong> to connections matching the zones."); ?></p>
        <p><?php echo _("Note that the 'Blocked' setting explicitly blocks that service totally, and can only be overridden by whitelisting."); ?></p>
<?php
$services = $fw->getServices();
$z = $fw->getZones();

foreach ($services as $s) {
	$currentzones = array();
	$svc = $fw->getService($s);
	if (!is_array($svc['zones'])) {
		$svc['zones'] = $svc['defzones'];
	}
	foreach ($svc['zones'] as $zone) {
		$currentzones[$zone] = true;
	}
?>
<div class='element-container'>
  <div class='row'>
    <div class='col-sm-4'>
      <label class='control-label' for='svc[<?php echo $s; ?>]'><?php echo $svc['name']; ?></label>
    </div>
    <div class='col-sm-8 noright'>
      <div class='btn-group' data-toggle='buttons'>
<?php
	// Display the buttons
	foreach ($z as $zn => $zone) {
		if (isset($currentzones[$zn])) {
			$active = "active";
			$checked = "checked";
		} else {
			$active = "";
			$checked = "";
		}
		print "<label class='btn btn-primary $active'><input type='checkbox' name='svc[$s][$zn]' $checked>".$zone['name']."</label>\n";
	}
?>
      </div>
    </div>
  </div>
</div>

<?php
}
?>

      </div>
      <div role="tabpanel" id="customsvc" class="tab-pane">
	<p>Define custom services here...</p>
      </div>
    </div>
  </div>
</div>

</form>
