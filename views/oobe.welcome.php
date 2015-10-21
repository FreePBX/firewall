<div class='container-fluid'>
<h2 class='s1'><?php echo _("You now have access to the Sangoma Smart Firewall!"); ?></h2>
<div class='row s1'>
  <div class='col-sm-12'>
    <img src='modules/firewall/assets/firewall-logo.png' class='img-responsive'>
  </div>
</div>

<div class='row s2' style='display: none'>
  <div class='col-sm-8 s2' style='display: none'>
    <div class='container-fluid'>
      <div class='row hides3'>
<?php
echo "<p>"._("Sangoma Smart Firewall is a revolutionary Open Source Firewall solution, designed from the ground up to completely secure your VoIP system.")."</p>";
echo "<p>"._("To activate Sangoma Smart Firewall you simply need to answer a couple of questions, and your Firewall will be configured and activated immediately.")."</p>";
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

</div></div><div class='panel-footer clearfix'>
  <button type='button' class='pull-right btn btn-default s1hide' id='ssf1'>1Continue</button>
  <button type='button' class='pull-right btn btn-default s2show' style='display: none' id='ssf2'>2Continue</button>
  <button type='button' class='pull-right btn btn-default' id='ssfabort'>Abort</button>
