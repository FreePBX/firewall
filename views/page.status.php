<?php
if (!isset($_REQUEST['tab'])) {
	$tab = "status";
} else {
	$tab = $_REQUEST['tab'];
}

$status = $registered = $blockedtab = "";

switch ($tab) {
case 'blockedtab':
case 'registered':
	${$tab} = "active";
	break;
default:
	$status = "active";
}

if(!empty($module_status["sysadmin"]) && ($sa = FreePBX::Sysadmin()) && $sa->getIntrusionDetection() != false){
  $salic    = true;
}

?>

<script type='text/javascript' src='modules/firewall/assets/js/views/status.js'></script>
<div class="display no-border">
  <div class="nav-container">
    <ul class="nav nav-tabs list" role="tablist">
    <li role="presentation" data-name="status" >
        <a class="nav-link <?php echo $status; ?>" href="#status" aria-controls="status" role="tab" data-toggle="tab"><?php echo _("Status Overview")?> </a>
      </li>
      <li role="presentation" data-name="registered" >
        <a class="nav-link <?php echo $registered; ?>" href="#registered" aria-controls="registered" role="tab" data-toggle="tab"><?php echo _("Registered Endpoints")?> </a>
      </li>
      <li role="presentation" data-name="blockedtab"  >
        <a class="nav-link <?php echo $blockedtab; ?>" href="#blockedtab" aria-controls="blockedtab" role="tab" data-toggle="tab"><?php echo _("Blocked Hosts")?> </a>
      </li>
    </ul>
    <div class="tab-content display">
      <div role="tabpanel" id="status" class="tab-pane <?php echo $status; ?>">
        <?php echo load_view(__DIR__."/view.status.php"); ?>
      </div>
      <div role="tabpanel" id="registered" class="tab-pane <?php echo $registered; ?>">
        <?php echo load_view(__DIR__."/view.registered.php"); ?>
      </div>
      <div role="tabpanel" id="blockedtab" class="tab-pane <?php echo $blockedtab; ?>">
        <?php echo load_view(__DIR__."/view.blocked.php", array("intdet" => $salic)); ?>
      </div>
    </div>
  </div>
</div>

