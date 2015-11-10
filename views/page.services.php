<script type='text/javascript' src='modules/firewall/assets/js/views/services.js'></script>
<form class="fpbx-submit" name="saveServices" method="post">
<input type='hidden' name='action' value='updateservices'>
<?php
if (!isset($_REQUEST['tab'])) {
	$tab = "services";
} else {
	$tab = $_REQUEST['tab'];
}
$svcs = "active";
$extraservices = $customsvc = "";

switch ($tab) {
case 'extraservices':
	$svcs = "";
	$extraservices = "active";
	break;
case 'customsvc':
	$svcs = "";
	$customsvc = "active";
	break;
}

$services = $fw->getServices();
$z = $fw->getZones();
$coresvc = $services['core'];
$extrasvc = $services['extra'];
?>

<div class="display no-border">
  <div class="nav-container">
    <ul class="nav nav-tabs list" role="tablist">
      <li role="presentation" data-name="services" class="<?php echo $svcs; ?>">
        <a href="#services" aria-controls="services" role="tab" data-toggle="tab"><?php echo _("Services")?></a>
      </li>
      <li role="presentation" data-name="extraservices" class="<?php echo $extraservices; ?>">
        <a href="#extraservices" aria-controls="extraservices" role="tab" data-toggle="tab"><?php echo _("Extra Services")?></a>
      </li>
      <li role="presentation" data-name="customsvc" class="<?php echo $customsvc; ?>">
        <a href="#customsvc" aria-controls="customsvc" role="tab" data-toggle="tab"><?php echo _("Custom Services")?></a>
      </li>
    </ul>
    <div class="tab-content display">
      <div role="tabpanel" id="services" class="tab-pane <?php echo $svcs; ?>">
        <div class='container-fluid'>
	  <p><?php echo _("Services that are assigned to zones <strong>are accessible</strong> to connections matching the zones."); ?></p>
          <p><?php echo _("Note that the 'Reject' setting explicitly blocks that service totally, and can only be overridden by access from a Trusted Zone. This is functionally equivalent to turning off access from all zones, unless you are running an extra Firewall plugin."); ?></p>
<?php
foreach ($coresvc as $s) {
	$currentzones = array();
	$svc = $fw->getService($s);
	foreach ($svc['zones'] as $zone) {
		$currentzones[$zone] = true;
	}
	// Display the buttons
	displayService($s, $svc, $z, $currentzones);
} ?>
        </div>
      </div>
      <div role="tabpanel" id="extraservices" class="tab-pane <?php echo $extraservices; ?>">
        <div class='container-fluid'>
<?php
foreach ($extrasvc as $s) {
	$currentzones = array();
	$svc = $fw->getService($s);
	if (!is_array($svc['zones'])) {
		$svc['zones'] = $svc['defzones'];
	}
	foreach ($svc['zones'] as $zone) {
		$currentzones[$zone] = true;
	}
	displayService($s, $svc, $z, $currentzones);
} ?>
        </div>
      </div>
      <div role="tabpanel" id="customsvc" class="tab-pane <?php echo $customsvc; ?>">
        <div class='container-fluid'>
          <?php echo load_view(__DIR__."/view.customsvc.php", array("services" => $services, "z" => $z, "fw" => $fw)); ?>
        </div>
      </div>
    </div>
  </div>
</div>

</form>


<?php

function displayService($sn, $svc, $z, $currentzones) {
	print "<div class='element-container'><div class='row'><div class='col-sm-3 col-md-4'><label class='control-label' for='svc[$sn]'>";
	print $svc['name']."</label></div><div class='col-sm-9 col-md-8 noright'><span class='radioset'>";
	// Display the buttons
	foreach ($z as $zn => $zone) {
		if (!$zone['selectable']) {
			continue;
		}
		if (isset($currentzones[$zn])) {
			$active = "active";
			$checked = "checked";
		} else {
			$active = "";
			$checked = "";
		}

		$disabled = "";
		$data = "data-svc='$sn'";
		$class = "svcbutton svc-$sn";
		if ($zn === "reject") {
		       if (isset($svc['noreject'])) {
			       $disabled = "disabled";
		       }
		       $class = "rejectbutton svc-$sn";
		} elseif (isset($svc['disabled'])) {
			$disabled = "disabled";
		}

		print "<input type='checkbox' class='$class' name='svc[$sn][$zn]' id='stuff-$sn-$zn' $data $checked $disabled><label for='stuff-$sn-$zn'>".$zone['name']."</label>\n";

		// We want 'Reject' to be seperate
		if ($zn === "reject") {
			print "</span><span class='radioset'>\n";
		}
	}
	print "</span></div>\n";
	
	// Help text.
	print "<div class='hidden-xs col-sm-11 col-sm-offset-1 col-md-12 col-md-offset-0'><span class='help-block'>".$svc['descr']."</span></div>\n";

	// /row and /element-container
	print "</div></div>\n";
}

