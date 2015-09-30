<div class='list-group'>
<?php
// I18n page names
$names = array(
	"about" => _("About"),
	"services" => _("Services"),
	"zones" => _("Zones"),
	"status" => _("Status"),
);
// Get our list of pages
$pages = glob(__DIR__."/page.*.php");
// Put them in a useful format
$known = array("about" => $names['about']);
foreach ($pages as $p) {
	if (preg_match("/page\.(.+)\.php$/", $p, $out)) {
		// About is always first, and is added later
		if ($out[1] !== "about") {
			if (isset($names[$out[1]])) {
				$known[$out[1]] = $names[$out[1]];
			} else {
				// I should throw an exception here, I guess...
				$known[$out[1]] = ucfirst($out[1]);
			}
		}
	}
}


// And display!
foreach ($known as $k => $v) {
	if ($thispage == $k) {
		$active = "active";
	} else {
		$active = "";
	}
	echo "  <a href='?display=firewall&page=$k' class='list-group-item $active'>$v</a>\n";
}
?>
</div>

