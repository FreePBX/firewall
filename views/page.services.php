<script type='text/javascript' src='modules/firewall/assets/js/views/services.js'></script>
<form class="fpbx-submit" name="saveServices" method="post">
<input type='hidden' name='action' value='updateservices'>
<?php
if (!isset($_REQUEST['tab'])) {
	$tab = "services";
} else {
	$tab = $_REQUEST['tab'];
}
$servicestab = $extraservices = $customsvc = $blacklist = "";

switch ($tab) {
case 'extraservices':
case 'customsvc':
case 'blacklist':
	${$tab} = "active";
	break;
default: 
	$servicestab = "active";
}

$services = $fw->getServices();
$z = $fw->getZones();
$coresvc = $services['core'];
$extrasvc = $services['extra'];
?>

<div class="display no-border">
  <div class="nav-container">
    <ul class="nav nav-tabs list" role="tablist">
      <li role="presentation" data-name="services" class="<?php echo $servicestab; ?>">
        <a href="#servicestab" aria-controls="servicestab" role="tab" data-toggle="tab"><?php echo _("Services")?></a>
      </li>
      <li role="presentation" data-name="extraservices" class="<?php echo $extraservices; ?>">
        <a href="#extraservices" aria-controls="extraservices" role="tab" data-toggle="tab"><?php echo _("Extra Services")?></a>
      </li>
      <li role="presentation" data-name="customsvc" class="<?php echo $customsvc; ?>">
        <a href="#customsvc" aria-controls="customsvc" role="tab" data-toggle="tab"><?php echo _("Custom Services")?></a>
      </li>
      <li role="presentation" data-name="blacklist" class="<?php echo $blacklist; ?>">
        <a href="#blacklist" aria-controls="blacklist" role="tab" data-toggle="tab"><?php echo _("Blacklist")?></a>
      </li>
    </ul>
    <div class="tab-content display">
      <div role="tabpanel" id="servicestab" class="tab-pane <?php echo $servicestab; ?>">
        <?php echo load_view(__DIR__."/view.services.php", array("fw" => $fw, "coresvc" => $coresvc, "z" => $z)); ?>
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
      <div role="tabpanel" id="blacklist" class="tab-pane <?php echo $blacklist; ?>">
        <div class='container-fluid'>
          <?php echo load_view(__DIR__."/view.blacklist.php", array("fw" => $fw)); ?>
        </div>
      </div>
    </div>
  </div>
</div>

</form>

