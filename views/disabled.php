<form method='post'>

<div class='panel panel-default'>
  <div class='panel-body'>
    <div class='alert alert-danger'>
      <h3><?php echo _("THIS IS BETA SOFTWARE"); ?></h3>
      <p><?php echo _("This software is under constant and active development. It is possible that you may lock yourself out of your system!"); ?></p>
      <p><?php echo _("Note that during testing, port 22 - ssh - is <strong>explicitly excluded</strong> from the firewall, so you will always be able to log into the server directly and reset the firewall rules."); ?></p>
      <p><?php echo _("To remove all firewall rules on this machine, run the following command as root, after ssh-ing into the server:"); ?></p>
      <p><tt>/etc/init.d/iptables stop</tt></p>
    </div>
    <div class='alert alert-warning'>
      <h3><?php echo _("Warning"); ?></h3>
      <p><?php echo _("The firewall module is not enabled!"); ?></p>
    </div>
<?php
print "<p>"._("This Firewall module is a tightly integrated, system level firewall that continually monitors and blocks attacks on your system, while allowing valid traffic through.")."</p>";
print "<p>"._("It continously monitors the configuration of your machine, automatically opening and closing ports to known trunks (eg, VoIP providers), and allows you to limit the services this machine provides to clients.")."</p>";

print "<p>"._("Please visit the FreePBX Wiki for more information on the firewall.")."</p>";
?>
  </div>
  <div class='panel-footer clearfix'>
    <div class='btn-group pull-right'>
      <button type='submit' name='action' value='enablefw' class='btn btn-default'>Enable Firewall</button>
    </div>
  </div>
</div>

</form>
