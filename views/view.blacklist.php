<p> <?php echo _("This firewall runs in a Deny-By-Default configuration. However, if you enable 'Responsive Firewall', your Signalling ports are exposed to the internet, and may be attackable.");?> </p>
<p> <?php echo _("To alleviate any potential attacks, you can add any number of hosts or networks here and any traffic from these entries will be silently ignored. They will NOT be permitted to access the Responsive Firewall service."); ?></p>
<p> <?php echo _("You can <strong>override</strong> the blacklist by assigning a network to a Zone. Please read the Wiki for more information."); ?></p>
<p> <?php echo _("Note that changes to the firewall are effective immediately."); ?></p>

<?php

$b = $fw->getBlacklist();
$i = 0;
$del = _("Delete");
foreach ($b as $entry => $resolved) {
	print "<div class='element-container' id='bl-$i'>\n";
	print "  <div class='row'>\n";
	print "    <div class='col-sm-4 col-md-3'>\n";
	print "      <input type='text' name='bl-$i' value='$entry' readonly disabled>\n";
	print "    </div>\n";
	print "    <div class='col-sm-8 col-md-9'>\n";
	if ($resolved !== false) {
		if (!$resolved) {
			print _("Warning: Unable to resolve this entry!");
		} else {
			print "      (".join(", ", $resolved).")\n";
		}
	}
	print "      <button type='button' class='pull-right x-btn btn btn-danger blbutton' data-action='remove' data-id='$i' title='$del'>\n";
	print "        <span class='glyphicon glyphicon-remove'></span>\n";
	print "      </button>\n";
	print "    </div>\n";
	print "  </div>\n";
	print "</div>\n";
}
?>

<div class='element-container' id='bl-new'>
  <div class='row'>
    <div class='col-sm-4 col-md-3'>
      <input type='text' name='bl-new'>
    </div>
    <div class='col-sm-8 col-md-9'>
      <button type='button' class='pull-right x-btn btn btn-success blbutton' data-action='create' data-id='new' title='<?php echo _("Add New"); ?>'>
        <span class='glyphicon glyphicon-plus'></span>
      </button>
    </div>
  </div>
</div>


