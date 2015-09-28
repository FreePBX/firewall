<p> <?php echo _("This firewall runs in a Deny-By-Default configuration. However, if you enable 'Responsive Firewall', this does expose your Signalling ports to the internet.");?> </p>
<p> <?php echo _("You can add any number of hosts or networks here, and any traffic from these entries will be silently ignored, and they will NOT be permitted to access the Responsive Firewall service."); ?></p>
<p> <?php echo _("You can <strong>override</strong> the blacklist by assigning a network to a Zone. Please read the Wiki for more information."); ?></p>
<p> <?php echo _("Note that changes to the firewall are effective immediately."); ?></p>

<?php

$b = $fw->getBlacklist();
foreach ($b as $i => $entry) {
	print "<div class='element-container' id='bl-$i'>\n";
	print "  <div class='row'>\n";
	print "    <div class='col-sm-4 col-md-3'>\n";
	print "      <input type='text' name='bl-$i' value='$entry' readonly disabled>\n";
	print "    </div>\n";
	print "    <div class='col-sm-8 col-md-9'>\n";
	print "      <button type='button' class='btn btn-danger blbutton' data-action='remove' data-id='$i'>\n";
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
      <button type='button' class='btn btn-success blbutton' data-action='create' data-id='new'>
        <span class='glyphicon glyphicon-plus'></span>
      </button>
    </div>
  </div>
</div>


