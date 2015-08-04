<form method='post'>

<div class='alert alert-warning'>
  <p><?php echo _("This module is not enabled!"); ?></p>
</div>
<div class='panel panel-default'>
  <div class='panel-body'>
    <p>Don't need a header</p>
    <p>Text goes here to check for prerequisites</p>
    <p>Make sure we're good</p>
  </div>
  <div class='panel-footer clearfix'>
    <div class='btn-group pull-right'>
      <button type='submit' name='action' value='enablefw' class='btn btn-default'>Enable Firewall</button>
    </div>
  </div>
</div>

</form>
