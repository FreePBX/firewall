<?php
if (!isset($_REQUEST['tab'])) {
	$tab = "about";
} else {
	$tab = $_REQUEST['tab'];
}
$about = $smart = $shortcuts = $services = $interfaces = $networks = $intrusion_detection = "";

switch ($tab) {
case 'smart':
case 'interfaces':
case 'networks':
case 'intrusion_detection':
	${$tab} = "active";
	break;
default:
	$about = "active";
}

$ss     = $fw->getSmartSettings();
$asfw   = $fw->getAdvancedSettings();
$salic  = false;

if(!empty($module_status["sysadmin"]) &&  ($sa = FreePBX::Sysadmin()) && $sa->getIntrusionDetection() != false){
  $salic                  = true;
  $indetec                = $sa->getIntrusionDetection();
  $indetec["idregextip"]  = $fw->getConfig("idregextip")  == "true"   ? "Active"  : "";
  $indetec["trusted"]     = $fw->getConfig("trusted")     == "true"   ? "Active"  : "";
  $indetec["local"]       = $fw->getConfig("local")       == "true"   ? "Active"  : "";
  $indetec["other"]       = $fw->getConfig("other")       == "true"   ? "Active"  : "";
  $indetec["idstatus"]    = $indetec["status"]            == "stopped"? "style='display: none;'": "";
  $indetec["legacy"]      = $asfw["id_sync_fw"]           == "legacy" ? "style='display: none;'": "";
  if($indetec["legacy"] == ""){
    $indetec["ids"]["fail2ban_whitelist"] = preg_replace('!\n+!', chr(10), $fw->getConfig("dynamic_whitelist"));
  }
    
  $wl_filter              = "^(\b(?:\d{1,3}\.){3}\d{1,3}\b)$";                    // IPV4
  $wl_filter             .= "|^(\b(?:\d{1,3}\.){3}\d{1,3}\b)\/\d{1,2}$";          // IPV4 + subnet
  $wl_filter             .= "|^((\w|\d|[-\.]){1,})+(\w|\d|[-])$";                 // Domains
  $wl_filter             .= "|^()$";                                              // Nothing (CR)
  $wl_filter             .= "|^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}";        // IPV6 
  $wl_filter             .= "|([0-9a-fA-F]{1,4}:){1,7}:";
  $wl_filter             .= "|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}";
  $wl_filter             .= "|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}";
  $wl_filter             .= "|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}";
  $wl_filter             .= "|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}";
  $wl_filter             .= "|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}";
  $wl_filter             .= "|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})";
  $wl_filter             .= "|:((:[0-9a-fA-F]{1,4}){1,7}|:)";
  $wl_filter             .= "|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}";
  $wl_filter             .= "|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]";
  $wl_filter             .= "|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]";
  $wl_filter             .= "|(2[0-4]";
  $wl_filter             .= "|1{0,1}[0-9]){0,1}[0-9])";
  $wl_filter             .= "|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]";
  $wl_filter             .= "|(2[0-4]";
  $wl_filter             .= "|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]";
  $wl_filter             .= "|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$";
  
  $indetec["wl_filter"]   = $wl_filter;
}
?>

<script type='text/javascript' src='modules/firewall/assets/js/views/main.js'></script>
<div class="container-fluid">
    <div class="row">
      <div class="col-md-12">
        <div class="alert alert-dismissable alert-warning">				 
          <button type="button" class="close" data-dismiss="alert" aria-hidden="true"> × </button>
          <h4> Warning! </h4> 
          <?php echo _("Note: Intrusion detection handling method is been updated recently. Please clear your browser cache and try if you are having issue with Intrusion Detection Start/Restart/Stop button.") ?>
        </div>
      </div>
    </div>
</div> 
<form method='post'>
<div class="display no-border">
  <div class="nav-container">
    <ul class="nav nav-tabs list" role="tablist">
      <li role="presentation" data-name="about" class="<?php echo $about; ?>">
        <a href="#about" aria-controls="about" role="tab" data-toggle="tab"><?php echo _("Settings")?> </a>
      </li>
      <li role="presentation" data-name="smart" class="<?php echo $smart; ?>">
        <a href="#smart" aria-controls="smart" role="tab" data-toggle="tab"><?php echo _("Responsive Firewall")?> </a>
      </li>
      <li role="presentation" data-name="interfaces" class="<?php echo $interfaces; ?>">
        <a href="#interfaces" aria-controls="interfaces" role="tab" data-toggle="tab"><?php echo _("Interfaces")?> </a>
      </li>
      <li role="presentation" data-name="networks" class="<?php echo $networks; ?>">
        <a href="#networks" aria-controls="networks" role="tab" data-toggle="tab"><?php echo _("Networks")?> </a>
      </li>
      <?php if($salic) { ?>
      <li role="presentation" data-name="intrusion_detection" class="<?php echo $intrusion_detection; ?>">
        <a href="#intrusion_detection" aria-controls="intrusion_detection" role="tab" data-toggle="tab"><?php echo _("Intrusion Detection")?> </a>
      </li>
      <?php } ?>
    </ul>
    <div class="tab-content display">
      <div role="tabpanel" id="about" class="tab-pane <?php echo $about; ?>">
        <?php echo load_view(__DIR__."/view.about.php", array("smart" => $ss, "fw" => $fw)); ?>
      </div>
      <div role="tabpanel" id="interfaces" class="tab-pane <?php echo $interfaces; ?>">
        <?php echo load_view(__DIR__."/view.interfaces.php", array("fw" => $fw)); ?>
      </div>
      <div role="tabpanel" id="smart" class="tab-pane <?php echo $smart; ?>">
        <?php echo load_view(__DIR__."/view.smart.php", array("smart" => $ss)); ?>
      </div>
      <div role="tabpanel" id="networks" class="tab-pane <?php echo $networks; ?>">
        <?php echo load_view(__DIR__."/view.networks.php", array("fw" => $fw)); ?>
      </div>
      <?php if($salic) { ?>
      <div role="tabpanel" id="intrusion_detection" class="tab-pane <?php echo $intrusion_detection; ?>">
        <?php echo load_view(__DIR__."/intrusion_detection.php", $indetec); ?>
      </div>
      <?php } ?>
    </div>
  </div>
</div>

</form>
