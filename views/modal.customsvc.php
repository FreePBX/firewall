<div class='modal fade' id='custmodal'>
  <div class='modal-dialog'>
    <div class='modal-content'>
      <div class='modal-header'>
        <h3 id='mheader' class="mr-auto">Header</h4>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
      </div>
      <div class='modal-body'>
        <form class='form-horizontal' id='customport'>
          <div class="form-group clearfix row">
	    <label for="cportname" class="col-lg-3 col-sm-3 control-label"><?php echo _("Description"); ?></label>
            <div class="col-sm-12 col-lg-9">
	      <input id="cportname" name="cportname" class="form-control autofocus" type="text" placeholder="<?php echo _("Any name"); ?>">
            </div>
          </div>
          <div class="form-group clearfix row">
	    <label for="cprotocol" class="col-lg-3 col-sm-3 control-label"><?php echo _("Protocol"); ?></label>
            <div class="col-sm-12 col-lg-9">
	      <select id="cprotocol" name="cprotocol" class="form-control">
		<option value='both'><?php echo _("Both (TCP and UDP)"); ?></option>
		<option value='tcp'><?php echo _("TCP"); ?></option>
		<option value='udp'><?php echo _("UDP"); ?></option>
	      </select>
            </div>
          </div>
          <div class="form-group clearfix row">
	    <label for="cportrange" class="col-lg-3 col-sm-3 control-label"><?php echo _("Port Range"); ?></label>
            <div class="col-sm-12 col-lg-9">
	      <input id="cportrange" name="cportrange" class="form-control" type="text" aria-describedby="porthelptext">
            </div>
          </div>
	  <span id="porthelptext" class="help-block"><?php echo _("Port ranges may be either a single number (9898), a selection of numbers (9898,9777,862), or a range delimited by a colon (9000:9500)"); ?>.</span>
        </form>
      </div>
      <div class='modal-footer'>
	<button type="button" class="btn btn-default" data-dismiss="modal"><?php echo _("Cancel"); ?></button>
	<button type="button" class="btn btn-primary" id='cssave'><?php echo _("Save"); ?></button>
      </div>
    </div>
  </div>
</div>

