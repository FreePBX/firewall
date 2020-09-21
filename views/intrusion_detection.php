<?php
echo '<script type="text/javascript" src="modules/sysadmin/assets/js/views/intrusion_detection.js"></script>';
$info = _("When the service is running, attempts to compromise your system are logged. If the attempts exceed the
Max Retry limit, the remote IP is blocked from accessing the system for the length of Ban Time.  The number
of attempts are reset after the Find Time is exceeded.<br />
We recommend this service always run.");
if ($i_d_conf) {
	$statmsg = '<span class="label label-success">'.$status.'</span>';
	switch ($status) {
		case 'stopped':
			$idinput = '<input type="submit" name="intrusion_detection" id="intrusion_detection_start" value="Start"/>';
		break;
		case 'running':
			$idinput = '<input type="submit" name="intrusion_detection" id="intrusion_detection_stop" value="Stop"/>';
			$idinput .= '<input type="submit" name="intrusion_detection" id="intrusion_detection_restart" value="Restart"/>';

			break;
	}
}else{
	$statmsg = '<span class="label label-danger">'._("It seems that you are missing the necessary files to start Intrusion Detection.").'</span>';
}

?>
<h1><?php echo _("Intrusion Detection")?></h1>
<div class="well">
	<?php echo $info ?>
</div>

<form method="post" action="">
<!--Status-->
<div class="element-container">
	<div class="row">
		<div class="form-group">
			<div class="col-md-3">
				<label class="control-label" for="sw"><?php echo _("Status") ?></label>
			</div>
			<div class="col-md-9">
				<?php echo $statmsg?>
			</div>
		</div>
	</div>
</div>
<!--END Status-->
<!--Intrusion Detection-->
<div class="element-container">
	<div class="row">
		<div class="form-group">
			<div class="col-md-3">
				<label class="control-label" for="idwrap"><?php echo _("Intrusion Detection") ?></label>
				<i class="fa fa-question-circle fpbx-help-icon" data-for="idwrap"></i>
			</div>
			<div class="col-md-9">
				<?php if($status == "running"){
					?>
					<input type="submit" name="idaction" id="id_stop" value="Stop">
					<input type="submit" name="idaction" id="id_restart" value="Restart">
					<?php
				}
				else{
					?>
					<input type="submit" name="idaction" id="id_start" value="Start">					
					<?php
				}
				?>
				<span id="doing"></span>
			</div>
		</div>
	</div>
	<div class="row">
		<div class="col-md-12">
			<span id="idwrap-help" class="help-block fpbx-help-block"><?php echo _("Control intrusion detection.")?></span>
		</div>
	</div>
</div>
</form>
<!--END Intrusion Detection-->
<?php

$ftbhtml = '<!--Ban Time-->
<div class="element-container" '.$idstatus.'>
	<div class="row">
		<div class="form-group">
			<div class="col-md-3">
				<label class="control-label" for="ban_time">'. _("Ban Time") .'</label>
				<i class="fa fa-question-circle fpbx-help-icon" data-for="ban_time"></i>
			</div>
			<div class="col-md-9">
				<input type="text" class="form-control" id="ban_time" name="ban_time" value="'.$ids['fail2ban_ban_time'].'" placeholder="ban_time">
			</div>
		</div>
	</div>
	<div class="row">
		<div class="col-md-12">
			<span id="ban_time-help" class="help-block fpbx-help-block">'. _("Length of time in seconds a remote IP is banned before being reset.").'</span>
		</div>
	</div>
</div>
<!--END Ban Time-->
<!--Max Retry-->
<div class="element-container" '.$idstatus.'>
	<div class="row">
		<div class="form-group">
			<div class="col-md-3">
				<label class="control-label" for="max_retry">'. _("Max Retry") .'</label>
				<i class="fa fa-question-circle fpbx-help-icon" data-for="max_retry"></i>
			</div>
			<div class="col-md-9">
				<input type="text" class="form-control" id="max_retry" name="max_retry" value="'.$ids['fail2ban_max_retry'].'" placeholder="max_retry">
			</div>
		</div>
	</div>
	<div class="row">
		<div class="col-md-12" '.$idstatus.'>
			<span id="max_retry-help" class="help-block fpbx-help-block">'. _("How many times a remote IP can try to connect during the find time.").'</span>
		</div>
	</div>
</div>
<!--END Max Retry-->
<!--Find Time-->
<div class="element-container" '.$idstatus.'>
	<div class="row">
		<div class="form-group">
			<div class="col-md-3">
				<label class="control-label" for="find_time">'. _("Find Time") .'</label>
				<i class="fa fa-question-circle fpbx-help-icon" data-for="find_time"></i>
			</div>
			<div class="col-md-9">
				<input type="text" class="form-control" id="find_time" name="find_time" value="'.$ids['fail2ban_find_time'].'" placeholder="find_time">
			</div>
		</div>
	</div>
	<div class="row">
		<div class="col-md-12">
			<span id="find_time-help" class="help-block fpbx-help-block">'. _("Number of seconds before attempts are reset.").'</span>
		</div>
	</div>
</div>
<!--END Find Time-->
<!--E-mail-->
<div class="element-container" '.$idstatus.'>
	<div class="row">
		<div class="form-group">
			<div class="col-md-3">
				<label class="control-label" for="email">'. _("E-mail:") .'</label>
				<i class="fa fa-question-circle fpbx-help-icon" data-for="email"></i>
			</div>
			<div class="col-md-9">
				<input type="text" class="form-control" id="email" name="email" value="'.$ids['fail2ban_email'].'" placeholder="email">
			</div>
		</div>
	</div>
	<div class="row">
		<div class="col-md-12">
			<span id="email-help" class="help-block fpbx-help-block">'. _("Email Address to send Notifications to.").' '._("The 'From' address that emails appear to come from is configured in 'Notification Settings'").'</span>
		</div>
	</div>
</div>
<!--END E-mail:-->
<!-- Sync -->
<div class="element-container" '.$legacy.' '.$idstatus.' >
	<div class="row">
		<div class="form-group">
			<div class="col-md-3">
				<label class="control-label" for="import">'. _("Import:") .'</label>
				<i class="fa fa-question-circle fpbx-help-icon" data-for="import"></i>
			</div>
			<div class="col-md-9">
				<div class="btn-group btn-group-md" role="group">
					<button id="idrefresh" class="btn btn-info" type="button" >
						<i class="fa fa-refresh" title="'._("Updates the whitelist according to the options chosen.").'"></i>
					</button> 				 
					<button id="idregextip" class="btn btn-secondary" type="button" '.$idregextip.'>
						'. _("Registered Extension IPs").'
					</button> 
					<button id="idtrustedzone" class="btn btn-secondary" type="button" '.$trusted.'>
						'._("Trusted Zone").'
					</button> 
					<button id="idlocalzone" class="btn btn-secondary" type="button" '.$local.'>
						'._("Local Zone").'
					</button> 
					<button id="idotherzone" class="btn btn-secondary" type="button" '.$other.'>
						'._("Other Zone").'
					</button>
					<button id="clearall" class="btn btn-secondary" type="button">
						'._("Clear All").'
					</button>
				</div>
			</div>
		</div>
	</div>
	<div class="row">
		<div class="col-md-12">
			<span id="import-help" class="help-block fpbx-help-block">'. _("Import all ip address from different type of sources.").' '._("You can mixe Registered Extension IPs, Trusted, Local, and Other at once. Also, you can Clear all to remove all entries into the whitelist.'").'</span>
		</div>
	</div>
</div>
<!-- End of Sync -->
<div class="element-container" '.$idstatus.'>
</div>
<!--Whitelist-->
<div class="element-container" '.$idstatus.'>
	<div class="row">
		<div class="form-group">
			<div class="col-md-3">
				<label class="control-label" for="whitelist">'. _("Whitelist") .'</label>
				<i class="fa fa-question-circle fpbx-help-icon" data-for="whitelist"></i>
			</div>
			<div class="col-md-9">
				<textarea class="form-control" id="whitelist" name="whitelist" rows="'.(count($ids['fail2ban_whitelist']) + 3).'"">'.$ids['fail2ban_whitelist'].'</textarea>
			</div>
		</div>
	</div>
	<p></p>
	<div class="row">
		<div class="col-md-12">
			<span id="whitelist-help" class="help-block fpbx-help-block">'. _("IP's that can never be banned.").'</span>
		</div>
	</div>
</div>
<!--END Whitelist-->
<div class="panel panel-default" '.$idstatus.'>
  <div class="panel-heading">
    <h3 class="panel-title">'._("IP's that are currently banned.").'</h3>
  </div>
  <div class="panel-body">
    '.(!empty($banned)?implode(", ", (array)$banned):_("No Banned IP's")).'
  </div>
</div>
';

//only show the rest of the options if we have fail2ban installed
if ($i_d_conf) {
	echo $ftbhtml;
}
?>

