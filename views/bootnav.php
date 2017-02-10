<div class='list-group'>
<?php
// I18n page names
$rawnames = array(
	"about" => _("Main"),
	"status" => _("Status"),
	"services" => _("Services"),
	"advanced" => _("Advanced"),
);

// Let other modules hook into our array
$names = \FreePBX::Firewall()->getNameHooks($rawnames);

// Get our list of pages
$known = array("about" => $names['about']);
foreach ($names as $name => $p) {
	if ($thispage == $name) {
		$active = "active";
	} else {
		$active = "";
	}
	echo "  <a href='?display=firewall&page=$name' class='list-group-item $active'>$p</a>\n";
}
?>
</div>

