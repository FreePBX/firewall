<?php
$fw = FreePBX::create()->Firewall;
?>

<div class='container-fluid'>
  <h1><?php echo _("Firewall"); ?></h1>
  <div class='row'>
    <div class='col-sm-9'>
<?php
if (!$fw->isEnabled()) {
	print $fw->showDisabled();
} else {
	print $fw->showPage();
}
?>
    </div>
    <div class='col-sm-3 hidden-xs bootnav'>
      <?php print $fw->showBootnav(); ?>
    </div>
  </div>
</div>


