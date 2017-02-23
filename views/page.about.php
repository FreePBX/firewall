<?php
if (!isset($_REQUEST['tab'])) {
	$tab = "about";
} else {
	$tab = $_REQUEST['tab'];
}
$about = $smart = $shortcuts = $services = $interfaces = $networks = "";

switch ($tab) {
case 'smart':
case 'interfaces':
case 'networks':
	${$tab} = "active";
	break;
default:
	$about = "active";
}

$ss = $fw->getSmartSettings();

?>

<script type='text/javascript' src='modules/firewall/assets/js/views/main.js'></script>
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
      <li role="presentation" data-name="interfaces" class="<?php echo $interfaces; ?>">
        <a href="#interfaces" aria-controls="interfaces" role="tab" data-toggle="tab"><?php echo _("Interfaces")?> </a>
      </li>
      <li role="presentation" data-name="networks" class="<?php echo $networks; ?>">
        <a href="#networks" aria-controls="networks" role="tab" data-toggle="tab"><?php echo _("Networks")?> </a>
      </li>
    </ul>
    <div class="tab-content display">
      <div role="tabpanel" id="about" class="tab-pane <?php echo $about; ?>">
        <?php echo load_view(__DIR__."/view.about.php", array("smart" => $ss, "fw" => $fw)); ?>
      </div>
      <div role="tabpanel" id="interfaces" class="tab-pane <?php echo $interfaces; ?>">
        <?php echo load_view(__DIR__."/view.interfaces.php", array("fw" => $fw)); ?>
      </div>
      <div role="tabpanel" id="smart" class="tab-pane <?php echo $smart; ?>">
        <?php echo load_view(__DIR__."/view.smart.php", array("smart" => $ss)); ?>
      </div>
      <div role="tabpanel" id="networks" class="tab-pane <?php echo $networks; ?>">
        <?php echo load_view(__DIR__."/view.networks.php", array("fw" => $fw)); ?>
      </div>
    </div>
  </div>
</div>

</form>
