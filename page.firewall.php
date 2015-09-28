<?php
$fw = FreePBX::create()->Firewall;
?>

<div class='fpbx-container container-fluid'>
  <h1><?php echo _("Firewall"); ?></h1>
    <div class='alert alert-danger'>
      <h3><?php echo _("THIS IS BETA SOFTWARE"); ?></h3>
      <p><?php echo _("<strong>THIS IS THE LAST RELEASE THAT EXPLICITLY PERMITS ACCESS TO PORT 22</strong>."); ?></p>
      <p><?php echo _("We are confident that the firewall service is sufficiently stable, and does not require an emergency backdoor. If you have had issues with firewall and have not reported them in the forums, please do so!"); ?></p>
      <p><a href='http://community.freepbx.org/t/31067/2' target=_new><?php echo _("This is the 'Current State' post in the forum thread discussing the development and testing of this module."); ?></a></p>
    </div>
  <div class='row'>
<?php
if (!$fw->isEnabled()) {
	// No bootnav.
    	print "<div class='col-sm-12'>";
	print $fw->showDisabled();
	print "</div>";
} else {
    	print "<div class='col-sm-9'>";
	$fw->showLockoutWarning();
	if (!empty($_REQUEST['page'])) {
		$page = $_REQUEST['page'];
	} else {
		$page = "about";
	}
	print $fw->showPage($page);
	print "</div>"; // col-sm-9
	print "<div class='col-sm-3 hidden-xs bootnav'>".$fw->showBootnav($page)."</div>";
}
?>
  </div> <!-- /row -->
</div> <!-- /container-fluid -->
