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

<script type='text/javascript' src='modules/firewall/assets/js/views/status.js'></script>
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
    </div>
  </div>
</div>

