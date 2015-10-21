<div class='container-fluid'>
<h2 class='s1'><?php echo _("Sangoma Smart Firewall is now enabled!"); ?></h2>
<div class='row s1'>
  <div class='col-sm-12'>
    <img src='modules/firewall/assets/firewall-logo.png' class='img-responsive'>
  </div>
  <div class='col-sm-12'>
    <div class='alert alert-danger'>
      <p><?php echo _("To receive the full benefits of the Sangoma Smart Firewall, you should ensure that <strong>no other firewall</strong> is intercepting traffic to this machine. This is normally accomplished by configuring your internet connection to place this machine in the 'DMZ' of your gateway."); ?></p>
      <p><?php echo _("If you are unable to do this, it is unlikely that Responsive Firewall will work correctly, if at all."); ?></p>
    </div>
  </div>
</div>

<div class='row s2' style='display: none'>
  <div class='col-sm-8 s2' style='display: none'>
    <div class='container-fluid'>
      <div class='row hides3'>
<?php
echo "<p>"._("Sangoma Smart Firewall is a revolutionary Open Source Firewall solution, designed from the ground up to completely secure your VoIP system.")."</p>";
echo "<p>"._("To start using Sangoma Smart Firewall you simply need to answer a couple of questions, and your Firewall will be configured and activated immediately.")."</p>";
echo "<p>"._("If you do not wish to use Sangoma Smart Firewall, simply click 'Abort'. You may return to this setup wizard via the 'Firewall' option in the Connectivity menu.")."</p>";
?>

      </div>
      <div class='row s3' style='display: none' id='qdiv'>
        <p>Loading...</p>
      </div>
    </div>
  </div>
  <div class='col-sm-4'>
    <img src='modules/firewall/assets/firewall-logo.png' class='img-responsive'>
  </div>
</div>
<div class='row s2' style='display: none'>
  <div class='col-sm-12 s2' style='display: none' id='alertsdiv'></div>
</div>

</div></div><div class='panel-footer clearfix'>
  <span id='buttonsdiv'></span>
  <button type='button' class='pull-right btn btn-default s1hide' id='ssf1'>Continue</button>
  <button type='button' class='pull-right btn btn-default s2show' style='display: none' id='ssf2'>Next</button>
  <button type='button' class='pull-right btn btn-default' id='ssfabort'>Abort</button>
