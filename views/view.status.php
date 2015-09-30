<div class='container-fluid'>

<h3><?php echo _("Summary"); ?></h3>
<?php
$h = array(
	_("This page gives you a summary of the status of the Responsive Firewall."),
	_("If you are not using the Responsive Firewall, there will be no useful information available here."),
	_("This page (and all tabs) automatically update every 15 seconds."),
);

foreach ($h as $p) {
	print "<p>$p</p>\n";
}

$loading = _("Loading...");

$rgd = _("Total number of Registered Hosts:");
$slowed = _("Total number of Rate-Limited Hosts:");
$blocked = _("Total number of Attackers detected:");

?>

<div class='row'>
  <div class='col-sm-8 col-md-5'><?php echo $rgd; ?></div>
  <div class='col-sm-4 col-md-7 loading' id='rgd' data-loading='<?php echo $loading; ?>'><?php echo $loading; ?></div>
</div>

<div class='row'>
  <div class='col-sm-8 col-md-5'><?php echo $slowed; ?></div>
  <div class='col-sm-4 col-md-7 loading' id='slowed' data-loading='<?php echo $loading; ?>'><?php echo $loading; ?></div>
</div>

<div class='row'>
  <div class='col-sm-8 col-md-5'><?php echo $blocked; ?></div>
  <div class='col-sm-4 col-md-7 loading' id='blocked' data-loading='<?php echo $loading; ?>'><?php echo $loading; ?></div>
</div>

</div>
