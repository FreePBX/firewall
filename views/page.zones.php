<div class="display no-border">
  <div class="nav-container">
    <ul class="nav nav-tabs list" role="tablist">
      <li role="presentation" data-name="zonedocs" class="active">
        <a href="#zonedocs" aria-controls="zonedocs" role="tab" data-toggle="tab"><?php echo _("Zone Information")?> </a>
      </li>
      <li role="presentation" data-name="zonesettings">
        <a href="#zonesettings" aria-controls="zonesettings" role="tab" data-toggle="tab"><?php echo _("Zone Assignments")?> </a>
      </li>
    </ul>
    <div class="tab-content display">
      <div role="tabpanel" id="zonedocs" class="tab-pane active">
        <h3><?php echo _("About Zones"); ?></h3>
<?php
echo "<p>"._("Each network interface on your machine must be mapped to a Zone. Note that, by default, all interfaces are mapped to trusted, which disables the firewall. The zones you can use are:")."</p>";
echo "<ul>";
$z = $fw->getZones();
foreach ($z as $zone) {
	print "<li><strong>".$zone['name']."</strong><br/>".$zone['descr']."</li>\n";
}
echo "</ul>";
?>

      </div>
      <div role="tabpanel" id="zonesettings" class="tab-pane">
<p>Setings panel</p>
      </div>
    </div>
  </div>
</div>


