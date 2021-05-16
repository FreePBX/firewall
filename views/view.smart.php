<div class='container-fluid'>
<?php
$rf = _("Responsive Firewall");

$ena = _("Enabled");
$dis = _("Disabled");

if ($smart['responsive']) {
	$rfwon = "checked";
	$rfwoff = "";
	$d = "";
} else {
	$rfwon = "";
	$rfwoff = "checked";
	$d = "disabled";
}

$protocols = $smart['rprotocols'];
?>
<h3>Sangoma <?php echo $rf; ?></h3>

<?php
$docs = array(
	_("When this is enabled, any incoming VoIP connection attempts that would be otherwise rejected are <strong>not blocked</strong>, and instead allowed a <strong>very limited</strong> amount of registration attempts."),
	_("If the registration attempt is successful, the remote host is then added to a 'Known Good' zone, that has permission to use that protocol, and is additionally granted access to UCP, if UCP is enabled."),
	_("If the incoming connection attempts are invalid, traffic from that machine will be dropped for a short period of time. If attempts to authenticate continue without success, the attacking host will be blocked for 24 hours."),
	_("If fail2ban is enabled and configured on this machine, fail2ban will send you email alerts when this happens."),
	_("Note that if you have explicitly granted 'External' connections access to a protocol, this filtering and rate limiting will not be used.  This is only used when an incoming connection <strong>would normally be blocked</strong>."),
);

foreach ($docs as $p) {
	print "<p>$p</p>\n";
}
?>
<div class='row'>
  <div class='form-horizontal clearfix'>
    <div class='col-sm-4'>
      <label class='control-label' for='rfwstat'><?php echo $rf; ?></label>
    </div>
    <div class='col-sm-8'>
<?php if ($smart['responsive']) {
	echo "<button type='submit' class='btn btn-default' name='action' id='rfwstate' value='disablerfw'>"._("Disable")."</button>";
} else {
	echo "<button type='submit' class='btn btn-default' name='action' id='rfwstate' value='enablerfw'>"._("Enable")."</button>";
}
?>
      </span>
    </div>
  </div>
</div>

<?php
foreach ($protocols as $id => $tmparr) {
	$desc = $tmparr['descr'];
	if ($tmparr['state']) {
		$on = "checked";
		$off = "";
	} else {
		$on = "";
		$off = "checked";
	}
?>
<div class='row'>
  <div class='form-horizontal clearfix'>
    <div class='col-sm-4'>
      <label class='control-label' for='<?php echo $id; ?>'><?php echo $desc; ?></label>
    </div>
    <div class='col-sm-8'>
      <span class='radioset'>
	<input type='radio' class='rfw' name='<?php echo $id; ?>' id='<?php echo $id; ?>1' value='true' <?php echo "$on $d"; ?>><label for='<?php echo $id; ?>1'><?php echo $ena; ?></label>
	<input type='radio' class='rfw' name='<?php echo $id; ?>' id='<?php echo $id; ?>2' value='false' <?php echo "$off $d"; ?>><label for='<?php echo $id; ?>2'><?php echo $dis; ?></label>
      </span>
    </div>
  </div>
</div>
<?php
}
?>
<div class="container-fluid">
<div class="element-container">
<div class='row'>
  <div class="section-title" data-for="Reponsive"><h3><i class="fa fa-plus"></i> <?php echo _('Responsive firewall threshold parameters') ?></h3>
  <div class="row">
	<div class="col-md-12">
		<div class="alert alert-warning" role="alert">
			<?php echo _("Exercise extreme caution when editing Responsive Threshold Parameters. Improper config can block legitimate registrations or expand access from untrusted sources");?></span>
		</div>
	</div>
</div>
  </div>
  
    <div class="section" data-id="Reponsive" style="display: none;">  
		<div class="section-title" data-for="Ratelimit"><h3><i class="fa fa-minus"></i> Ratelimit threshold</h3></div>
			<div class="section" data-id="Ratelimit">
				<form  id="formreponsiveset" name="formreponsiveset">
				<?php
				foreach($smart['fpbxratelimit'] as $key => $value){
				?>
				<div class="element-container">
					<div class='row'>
						<div class='form-horizontal '>
							<div class='col-sm-2'>
								<label class='control-label' for='ratelimitth'><?php echo _($key); ?></label>
							</div>
							<div class='col-sm-2'>
								<?php echo _('Duration(s)') ?></div><div class='col-sm-2'><input type='number' min='0' class='form-control' name='fpbxratelimit_<?php echo $key; ?>_seconds' id='fpbxratelimit_<?php echo $key; ?>_seconds' value=<?php echo $value['seconds'];?> >
							</div>
							<div class='col-sm-2'>
								<?php echo _('Count') ?></div><div class='col-sm-2'><input type='number' min='0' class='form-control' name='fpbxratelimit_<?php echo $key; ?>_hitcount' id='fpbxratelimit_<?php echo $key; ?>_hitcount' value=<?php echo $value['hitcount'];?> >
							</div>
							<div class='col-sm-2'>	
									<?php echo $value['type'] ?>
									<input type='hidden' name='fpbxratelimit_<?php echo $key; ?>_type' id='fpbxratelimit_<?php echo $key; ?>_type' value=<?php echo $value['type'];?> >
							</div>
						</div>
					</div>
				</div>
				<?php 
					}
				?>
			</div>
			<div class="section-title" data-for="block"><h3><i class="fa fa-minus"></i> Block threshold</h3></div>
				<div class="section" data-id="block">
				<?php
					foreach($smart['fpbxrfw'] as $key => $value){
				?>
					<div class="element-container">
						<div class='row'>
							<div class='form-horizontal '>
								<div class='col-sm-2'>
									<label class='control-label' for='fpbxrfwth'><?php echo _($key); ?></label>
								</div>
								<div class='col-sm-2'>
									<?php echo _('Duration(s)') ?></div><div class='col-sm-2'><input type='number' min='0' class='form-control' name='fpbxrfw_<?php echo $key; ?>_seconds' id='fpbxrfw_<?php echo $key; ?>_seconds' value=<?php echo $value['seconds'];?> >
								</div>
								<div class='col-sm-2'>	
									<?php echo _('Count') ?></div><div class='col-sm-2'><input type='number' min='0' class='form-control' name='fpbxrfw_<?php echo $key; ?>_hitcount' id='fpbxrfw_<?php echo $key; ?>_hitcount' value=<?php echo $value['hitcount'];?> >
								</div>
								<div class='col-sm-2'>	
									<?php echo $value['type'] ?>
									<input type='hidden' name='fpbxrfw_<?php echo $key; ?>_type' id='fpbxrfw_<?php echo $key; ?>_type' value=<?php echo $value['type'];?> >
								</div>
							</div>
						</div>
					</div>
					<?php 
					}
				?>
				</div>
			
			<input type="button" id="submitbutton" value="Save settings">
			<input type="button" id="reponsivereset" value="Reset to Default">
			</form>
			</div>
		</div>
	</div>
</div>

</div>
<br>
<div class='container-fluid'>
<?php
$docs = array(
	_("By default, Fail2Ban remains active even when responsive firewall is enabled.  This provides additional protection against attackers with access to an IP with a registered device or comprimised SIP credentials."),
	_("In some situations, it may be desirable to have Responsive Firewall whitelist known registrations from Fail2Ban, so that an incorrectly configured device doesn't trip the firewall and cause legitimate devices behind the same public IP to be blocked."),
	_("By enabling the bypass below, an exemption will be added to Fail2Ban for any IP that has successfully registered through the Responsive Firewall."),
);
foreach ($docs as $p) {
	print "<p>$p</p>\n";
}

if (\FreePBX::Firewall()->getConfig('fail2banbypass')) {
		$on = "checked";
		$off = "";
	} else {
		$on = "";
		$off = "checked";
	}
?>
<div class='row'>
  <div class='form-horizontal clearfix'>
    <div class='col-sm-4'>
      <label class='control-label' for='fail2banbypass'>Fail2Ban Bypass</label>
    </div>
    <div class='col-sm-8'>
      <span class='radioset'>
	<input type='radio' class='f2bmode' name='fail2banbypass' id='fail2banbypass1' value='true' <?php echo "$on $d"; ?>><label for='fail2banbypass1'><?php echo $ena; ?></label>
	<input type='radio' class='f2bmode' name='fail2banbypass' id='fail2banbypass2' value='false' <?php echo "$off $d"; ?>><label for='fail2banbypass2'><?php echo $dis; ?></label>
      </span>
    </div>
  </div>
</div>
</div>
