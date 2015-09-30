<?php
$fw = FreePBX::create()->Firewall;
?>

<div class='fpbx-container container-fluid'>
  <h1><?php echo _("Firewall"); ?></h1>
    <div class='alert alert-danger'>
      <h3><?php echo _("THIS IS BETA SOFTWARE"); ?></h3>
      <p><?php echo _("<strong>THERE IS NO LONGER UNFILTERED ACCESS TO PORT 22</strong>."); ?></p>
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

<?php
if (isset($page) && $page == "services") {
	include 'views/modal.customsvc.php';
}
