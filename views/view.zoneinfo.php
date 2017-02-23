<div class='container-fluid'>
  <h3><?php echo _("About Zones"); ?></h3>
<?php
echo "<p>"._("Each network interface on your machine must be mapped to a Zone. Note that, by default, all interfaces are mapped to trusted (Trusted networks are not filtered at all, so this disables the firewall for any traffic arriving at that interface). The zones you can use are:")."</p>";
echo "<ul>";
$z = $fw->getZones();
foreach ($z as $zone) {
	print "<li><strong>".$zone['name']."</strong><br/>".$zone['descr']."</li>\n";
}
echo "</ul>";
?>

</div>
