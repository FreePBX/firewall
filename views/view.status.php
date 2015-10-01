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

$rgd = _("Total number of Registered Clients:");
$slowed = _("Total number of Rate-Limited Clients:");
$curslowed = _("Number of Currently Rate-Limited Clients:");
$blocked = _("Total number of Attackers detected:");
$curblocked = _("Number of currently blocked Attackers:");
$total = _("Cumulative Total of remote clients:");
?>

<div class='row'>
  <div class='col-sm-8 col-md-6'><?php echo $rgd; ?></div>
  <div class='col-sm-4 col-md-6'><span class='loading'><?php echo $loading; ?></span><span class='notloading' id='rgd'></span></div>
</div>

<div class='row'>
  <div class='col-sm-8 col-md-6'><?php echo $slowed; ?></div>
  <div class='col-sm-4 col-md-6'><span class='loading'><?php echo $loading; ?></span><span class='notloading' id='slowed'></span></div>
</div>

<div class='row'>
  <div class='col-sm-8 col-md-6'><?php echo $curslowed; ?></div>
  <div class='col-sm-4 col-md-6'><span class='loading'><?php echo $loading; ?></span><span class='notloading' id='curslowed'></span></div>
</div>

<div class='row'>
  <div class='col-sm-8 col-md-6'><?php echo $blocked; ?></div>
  <div class='col-sm-4 col-md-6'><span class='loading'><?php echo $loading; ?></span><span class='notloading' id='blocked'></span></div>
</div>

<div class='row'>
  <div class='col-sm-8 col-md-6'><?php echo $curblocked; ?></div>
  <div class='col-sm-4 col-md-6'><span class='loading'><?php echo $loading; ?></span><span class='notloading' id='curblocked'></span></div>
</div>

<div class='row'>
  <div class='col-sm-8 col-md-6'><?php echo $total; ?></div>
  <div class='col-sm-4 col-md-6'><span class='loading'><?php echo $loading; ?></span><span class='notloading' id='totalremotes'></span></div>
</div>

</div>
