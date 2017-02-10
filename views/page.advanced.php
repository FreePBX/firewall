<?php
if (!isset($_REQUEST['tab'])) {
	$tab = "status";
} else {
	$tab = $_REQUEST['tab'];
}

$zoneinfo = "active";
$services = $shortcuts = "";

switch ($tab) {
case 'services':
	$status = "";
	$services = "active";
	break;
case 'shortcuts':
	$status = "";
	$shortcuts = "active";
	break;
}
?>

<div class="display no-border">
  <div class="nav-container">
    <ul class="nav nav-tabs list" role="tablist">
      <li role="presentation" data-name="zoneinfo" class="<?php echo $zoneinfo; ?>">
        <a href="#zoneinfo" aria-controls="zoneinfo" role="tab" data-toggle="tab"><?php echo _("Zone Information")?> </a>
      </li>
      <li role="presentation" data-name="services" class="<?php echo $services; ?>">
        <a href="#services" aria-controls="services" role="tab" data-toggle="tab"><?php echo _("Port/Service Maps")?> </a>
      </li>
      <li role="presentation" data-name="shortcuts" class="<?php echo $shortcuts; ?>">
        <a href="#shortcuts" aria-controls="shortcuts" role="tab" data-toggle="tab"><?php echo _("Preconfigured")?> </a>
      </li>
    </ul>
    <div class="tab-content display">
      <div role="tabpanel" id="zoneinfo" class="tab-pane <?php echo $zoneinfo; ?>">
        <?php echo load_view(__DIR__."/view.zoneinfo.php", array("fw" => $fw)); ?>
      </div>
      <div role="tabpanel" id="services" class="tab-pane <?php echo $services; ?>">
        <div class='container-fluid'>
          <?php echo load_view(__DIR__."/view.portmaps.php", array("fw" => $fw)); ?>
        </div>
      </div>
      <div role="tabpanel" id="shortcuts" class="tab-pane <?php echo $shortcuts; ?>">
        <?php echo load_view(__DIR__."/view.shortcuts.php", array("fw" => $fw)); ?>
      </div>
    </div>
  </div>
</div>

