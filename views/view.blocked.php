<div class='container-fluid'>

<h3><?php echo _("Rate Limited Hosts"); ?></h3>
<p><?php echo _("Any hosts in this section have been rate limited, because they have sent too much data to this machine without successfully registering."); ?></p>
<p><?php echo _("There is no need to manually remove entries from this section, as their rate limiting will be completely removed in 60 seconds. If they continue to send invalid data, they will be marked as an Attacker."); ?></p>
<div id='noratelimited' class='alert alert-success'>
  <h4><?php echo _("No hosts!"); ?></h4>
  <p><?php echo _("There are no hosts that are currently being rate limited."); ?></p>
</div>

<h3><?php echo _("Blocked Attackers"); ?></h3>
<p><?php echo _("Any hosts in this section have been classified as an attacker. All traffic from them will be ignored until they have not contacted the server at all for more than 24 hours."); ?></p>
<p><?php echo _("If you believe one of the hosts has been added in error, you can click the red 'X' to remove the block. If the host continues to send invalid data, it will be automatically re-added."); ?></p>
<div id='noattackers' class='alert alert-success'>
  <h4><?php echo _("No hosts!"); ?></h4>
  <p><?php echo _("There are no hosts that have been detected as attacking this server."); ?></p>
</div>

</div>

