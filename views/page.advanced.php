<form method='post'>
<div class="display no-border">
  <div class="nav-container">
    <ul class="nav nav-tabs list" role="tablist">
      <li role="presentation" data-name="advanced" class="active">
        <a href="#advanced" aria-controls="advanced" role="tab" data-toggle="tab"><?php echo _("Advanced")?> </a>
      </li>
      <li role="presentation" data-name="shortcuts">
        <a href="#shortcuts" aria-controls="shortcuts" role="tab" data-toggle="tab"><?php echo _("Preconfigured")?> </a>
      </li>
      <li role="presentation" data-name="overrides">
        <a href="#overrides" aria-controls="overrides" role="tab" data-toggle="tab"><?php echo _("Smart Overrides")?> </a>
      </li>
    </ul>
    <div class="tab-content display">
      <div role="tabpanel" id="networks" class="tab-pane active">
        <p>Text for advanved goes here...</p>
      </div>
<?php
// Text for Shortcuts is here
$rfc = array(
	_("RFC1918"),
	_("RFC1918 is the RFC that defineds the reserved, internal, network address space to be used when you're not directly connected to the internet. This adds 192.168.0.0/16, 172.16.0.0/12, and 10.0.0.0/8 to the 'Trusted' zone, and excludes it from all firewalls. Be warned that if you are in a hosted environment (for example, AWS), and you enable this, you may be inadvertently allowing other hosted clients unrestricted access to your machine."),
	_("Add to Trusted"),
);

$ym = array(
	_("Your Client"),
	_("This explicitly grants permission to the machine that is managing the firewall service now. If you select 'Add Network', it will add the entire Class C that the server sees you coming from (%s), or if you select 'Add Host' it will only add the individual IP address (%s). When starting to configure your firewall, it is wise to enable this to ensure you don't lock yourself out of your machine."),
	_("Add Network"),
	_("Add Host"),
);

$thisnet = $fw->detectNetwork();
$thishost = $fw->detectHost();

?>
      <div role="tabpanel" id="shortcuts" class="tab-pane">
        <div class='container-fluid'>
	  <p><?php echo _("This allows you to simply add a pre-configured set of networks to your trusted zone. Once you have added your selections, you can fine-tune them, if required, on the Networks tab."); ?></p>
          <div class='panel panel-default'>
	    <div class='panel-body'>
	      <h3><?php echo $rfc[0]; ?></h3>
	      <p><?php echo $rfc[1]; ?></p>
            </div>
            <div class='panel-footer clearfix'>
	      <button type='button' class='btn btn-default pull-right'><?php echo $rfc[2]; ?></button>
            </div>
          </div>
          <div class='panel panel-default'>
            <div class='panel-body'>
	      <h3><?php echo $ym[0]; ?></h3>
	      <p><?php printf($ym[1], $thisnet, $thishost); ?></p>
            </div>
            <div class='panel-footer clearfix'>
	      <button type='button' class='btn btn-default pull-right'><?php echo $ym[2]; ?></button>
	      <button type='button' class='btn btn-default pull-right'><?php echo $ym[3]; ?></button>
            </div>
          </div>
        </div>
      </div>
      <div role="tabpanel" id="overrides" class="tab-pane">
        <p>Stuff about overrides here...</p>
      </div>
    </div>
  </div>
</div>

</form>
