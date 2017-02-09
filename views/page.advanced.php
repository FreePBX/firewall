<?php
if (!isset($_REQUEST['tab'])) {
	$tab = "status";
} else {
	$tab = $_REQUEST['tab'];
}

$status = "active";
$registered = $blockedtab = "";

switch ($tab) {
case 'registered':
	$status = "";
	$registered = "active";
	break;
case 'blockedtab':
	$status = "";
	$blockedtab = "active";
	break;
}
?>

<div class="display no-border">
  <div class="nav-container">
    <ul class="nav nav-tabs list" role="tablist">
      <li role="presentation" data-name="status" class="<?php echo $status; ?>">
        <a href="#status" aria-controls="status" role="tab" data-toggle="tab"><?php echo _("Status Overview")?> </a>
      </li>
      <li role="presentation" data-name="registered" class="<?php echo $registered; ?>">
        <a href="#registered" aria-controls="registered" role="tab" data-toggle="tab"><?php echo _("Registered Endpoints")?> </a>
      </li>
      <li role="presentation" data-name="blockedtab"  class="<?php echo $blockedtab; ?>">
        <a href="#blockedtab" aria-controls="blockedtab" role="tab" data-toggle="tab"><?php echo _("Blocked Hosts")?> </a>
      </li>
      <li role="presentation" data-name="services" class="<?php echo $services; ?>">
        <a href="#services" aria-controls="services" role="tab" data-toggle="tab"><?php echo _("Port/Service Maps")?> </a>
      </li>
      <li role="presentation" data-name="shortcuts" class="<?php echo $shortcuts; ?>">
        <a href="#shortcuts" aria-controls="shortcuts" role="tab" data-toggle="tab"><?php echo _("Preconfigured")?> </a>
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
        <?php echo load_view(__DIR__."/view.blocked.php"); ?>
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

