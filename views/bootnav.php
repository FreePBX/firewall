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
	$list_items = "";
	foreach ($names as $name => $p) {
		if (($thispage["page"] ?? '') == $name){
			$active = "active";
		} else {
			$active = "";
		}
		if(empty($thispage["page"]) && $name == "about" ){
			$active = "active";
		}
		$list_items .= "<a href='?display=firewall&page=$name' class='list-group-item $active'>$p</a>";
	}
?>
<div class="bootnav">
	<div class='list-group'>
		<?php echo $list_items; ?>
	</div>
</div>