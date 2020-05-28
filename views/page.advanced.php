<?php
if (!isset($_REQUEST['tab'])) {
	$tab = "status";
} else {
	$tab = $_REQUEST['tab'];
}

$zoneinfo = $services = $shortcuts = $settings = $advanced_customrules ="";

switch ($tab) {
case 'services':
case 'shortcuts':
case 'settings':
case 'advanced_customrules':
	${$tab} = "active";
  break;

default:
	$zoneinfo = "active";
}
?>

<script type='text/javascript' src='modules/firewall/assets/js/views/advanced.js'></script>
<script type='text/javascript' src='modules/firewall/vendor/npm-asset/codemirror/lib/codemirror.js'></script>
<script type='text/javascript' src='modules/firewall/vendor/npm-asset/codemirror/addon/scroll/simplescrollbars.js'></script>
<script type='text/javascript' src='modules/firewall/vendor/npm-asset/codemirror/addon/display/fullscreen.js'></script>
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
      <li role="presentation" data-name="settings" class="<?php echo $settings; ?>">
        <a href="#settings" aria-controls="settings" role="tab" data-toggle="tab"><?php echo _("Advanced Settings")?> </a>
      </li>
      <li role="presentation" data-name="advanced_customrules" class="<?php echo $advanced_customrules; ?>">
        <a href="#advanced_customrules" aria-controls="advanced_customrules" role="tab" data-toggle="tab"><?php echo _("Advanced Custom Rules")?> </a>
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
      <div role="tabpanel" id="settings" class="tab-pane <?php echo $settings; ?>">
        <?php echo load_view(__DIR__."/view.settings.php", array("fw" => $fw)); ?>
      </div>
      <div role="tabpanel" id="advanced_customrules" class="tab-pane <?php echo $advanced_customrules; ?>">
        <?php echo load_view(__DIR__."/view.advanced_customrules.php", array("fw" => $fw)); ?>
      </div>
    </div>
  </div>
</div>

