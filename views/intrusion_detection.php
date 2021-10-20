<?php
echo '<script type="text/javascript" src="modules/sysadmin/assets/js/views/intrusion_detection.js"></script>';
if($from_sysadmin){
	echo '<script>window.from_sysadmin = true;</script>';
	echo '<script type="text/javascript" src="modules/firewall/assets/js/views/main.js"></script>';
	echo '<script type="text/javascript" src="modules/firewall/assets/js/views/advanced.js"></script>';	
	?>
	<div class="alert alert-dismissable alert-warning">				 
		<button type="button" class="close" data-dismiss="alert" aria-hidden="true"> × </button>
		<h4> <?php echo _("Warning!") ?> </h4> 
		<?php echo _("Note: The Intrusion Detection handling method has been updated recently. Please clear your browser cache and refresh if you are having issues seeing the Intrusion Detection Start/Restart/Stop button.") ?>
	</div>
	<?php	
}
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
<div class="element-container">
	<div class="row">
		<div class="form-group">
			<div class="col-md-6">
				<h1><?php echo _("Intrusion Detection")?></h1>
			</div>
			<div class="col-md-6 text-right">
				<?php if($from_sysadmin){ ?>
					<!-- Modal -->
					<i class="fa fa-2x fa-cogs adv-settings" title="Advanced Settings" data-toggle="modal" data-target="#advanced-settings"></i>
					<div class="modal fade" id="advanced-settings" tabindex="-1" role="dialog" aria-labelledby="advanced-settingsLabel" aria-hidden="true">
						<div class="modal-dialog" role="document">
							<div class="modal-content">
								<div class="modal-header">
									<h5 class="modal-title text-left" id="advanced-settingsLabel"><?php echo _("Advanced Settings") ?></h5>
									<button type="button" class="close" data-dismiss="modal" aria-label="Close">
									<span aria-hidden="true">&times;</span>
									</button>
								</div>
								<div class="modal-body text-left">
									<div class="fpbx-container">
										<div class="element-container">	
											<div class="row">
												<div class="form-group">
													<div class="col-md-7">
														<label class="control-label" for="INTRUSION_DETECTION_SERVICE"><?php echo _("Intrusion Detection Service") ?></label>
														<i class="fa fa-question-circle fpbx-help-icon" data-for="INTRUSION_DETECTION_SERVICE"></i>&nbsp;
														<a href="#" data-for="INTRUSION_DETECTION_SERVICE" data-type="bool" data-defval="1" class="hidden defset"><i class="fa fa-refresh"></i></a>
													</div>
													<div class="col-md-5 radioset text-right">
														<input type="hidden" id="INTRUSION_DETECTION_SERVICEdefault" value="1">
														<input type="radio" class="advsetting" id="INTRUSION_DETECTION_SERVICEtrue" name="id_service" value="enabled" <?php  echo $id_service_enabled ?>>
														<label for="INTRUSION_DETECTION_SERVICEtrue"><?php echo _("Enabled") ?></label>
														<input type="radio" class="advsetting" id="INTRUSION_DETECTION_SERVICEfalse" name="id_service" value="diabled" <?php  echo $id_service_disabled ?>>
														<label for="INTRUSION_DETECTION_SERVICEfalse"><?php echo _("Disabled") ?></label>
													</div>		
												</div>
												<div class="row">
													<div class="col-md-12">
														<span id="INTRUSION_DETECTION_SERVICE-help" class="help-block fpbx-help-block">
														<?php 
														echo "<strong>"._("Enable / Disable").":</strong> "._("Intrusion Detection service on boot.")."<br>";
														echo "<strong>"._("Enabled").":</strong> "._("This service will be started on boot.")."<br>";
														echo "<strong>"._("Disabled").":</strong> "._("This service will be stopped and Intrusion Detection will not run on boot. Intrusion Detection will be stopped as well.")."<br>";
														?>
														<br>
														<br>
														</span>
													</div>
												</div>
											</div>
										</div>
										<div class="element-container">	
										<div class="row">
												<div class="form-group">
													<div class="col-md-7">
														<label class="control-label" for="IDSF"><?php echo _("Intrusion Detection Sync Firewall") ?></label>
														<i class="fa fa-question-circle fpbx-help-icon" data-for="IDSF"></i>&nbsp;
														<a href="#" data-for="IDSF" data-type="bool" data-defval="1" class="hidden defset"><i class="fa fa-refresh"></i></a>
													</div>
													<div class="col-md-5 radioset text-right">
														<input type="hidden" id="IDSFdefault" value="1">
														<input type="radio" class="advsetting" id="IDSFtrue" name="id_sync_fw" value="enabled" <?php  echo $id_sync_fw_enabled ?>>
														<label for="IDSFtrue"><?php echo _("Enabled") ?></label>
														<input type="radio" class="advsetting" id="IDSFfalse" name="id_sync_fw" value="legacy" <?php  echo $id_sync_fw_legacy ?>>
														<label for="IDSFfalse"><?php echo _("Legacy") ?></label>
													</div>		
												</div>
												<div class="row">
													<div class="col-md-12">
														<span id="IDSF-help" class="help-block fpbx-help-block">
														<?php 
														echo "<strong>"._("Enabled").":</strong> "._("Automatically synchronize IPs from specific firewall zones to the whitelist. E.g: When you add to a trusted zone, local or otherwise, they will be added to the Intrusion Detection whitelist")."<br>";
														echo "<strong>"._("Legacy").":</strong> "._("Intrusion Detection whitelist will work like in the past with no automated synchronization to the whitelist).")."<br>";
														?>
														</span>
													</div>
												</div>
											</div>
										</div>									
									</div>
								</div>
							</div>
						</div>
					</div>
				<?php } ?>
			</div>
		</div>
	</div>
</div>
<div class="well">
	<?php echo $info ?>
</div>

<form class="fpbx-submit" method="post" action="">
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
						'. _("Registered Ext. IPs").'
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
			<span id="import-help" class="help-block fpbx-help-block">'. _("Import all IP addresses from all source types.").' '._("You can select Registered Extension IPs, and various zones at once. Also, you can select Clear All to remove all entries from the whitelist.'").'</span>
		</div>
	</div>
</div>
<!-- End of Sync -->
<div class="element-container" '.$idstatus.'>
</div>';
if($legacy != ""){
	$ftbhtml.='
	<!--Whitelist-->
	<div class="element-container" '.$idstatus.'>
		<div class="row">
			<div class="form-group">
				<div class="col-md-3">
					<label class="control-label" for="whitelist">'. _("Whitelist") .'</label>
					<i class="fa fa-question-circle fpbx-help-icon" data-for="whitelist"></i>
				</div>
				<div class="col-md-9">
					<textarea class="form-control" pattern="'.$wl_filter.'" id="whitelist" name="whitelist" rows="'.(count($ids['fail2ban_whitelist']) + 3).'"">'.$ids['fail2ban_whitelist'].'</textarea>
				</div>
			</div>
		</div>
		<p></p>
		<div class="row">
			<div class="col-md-12">
				<span id="whitelist-help" class="help-block fpbx-help-block">'. _("List of IPv4/6 addresses that will never be banned by Intrusion Detection. One address per line with no separators.").'</span>
			</div>
		</div>
	</div>
	<!--END Whitelist-->	
	<div class="panel panel-default" '.$idstatus.'>
	<div class="panel-heading">
		<h3 class="panel-title">'._("IPs that are currently banned.").'</h3>
	</div>
	<div class="panel-body" id="banned-area">
		'.(!empty($banned)?implode(", ", (array)$banned):_("No Banned IP's")).'
	</div>
	</div>
	';	
}
else{

	$ftbhtml.='
	<!--Whitelist-->
	<div class="element-container" '.$idstatus.'>
		<div class="row">
			<div class="form-group">
				<div class="col-md-3">
					<label class="control-label" for="whitelist">'. _("Custom Whitelist") .'</label>
					<i class="fa fa-question-circle fpbx-help-icon" data-for="whitelist"></i>
				</div>
				<div class="col-md-9">
					<textarea class="form-control" pattern="'.$wl_filter.'" id="whitelist" name="whitelist" rows="'.(count($ids['whitelist']) + 1).'"">'.$ids['whitelist'].'</textarea>
				</div>
			</div>
		</div>
		<p></p>
		<div class="row">
			<div class="col-md-12">
				<span id="whitelist-help" class="help-block fpbx-help-block">'. _("Custom IP's that can never be banned.").'<br> '._("Enter one IP or one Host per line. No comma allowed for multiple entries.").'</span>
			</div>
		</div>
	</div>
	<br>
	<div class="alert alert-warning alert-dismissible" id="needApply" style="display: none">
		<a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
		<strong>Warning!</strong> '._("The changes are not yet applied. They will be applied during the next synchronization. However, you can apply them immediately by clicking the Save button.").'.
  	</div>
	<div class="container-fuild">
		<div class="panel panel-default" '.$idstatus.' >
			<div class="panel-heading">
				<h3 class="panel-title">'._("IP's that are currently trusted.").'</h3>
			</div>
			<br>
			<div id="toolbarwl">
				&nbsp;&nbsp;&nbsp;<button class="btn btn-default" type="button" title="'._("Delete entire custom whitelist").' "id="delwl">'._("Delete Custom Whitelist").' <i class="fa fa-trash"></i></button>
				<div class="text-center" id="delwl-confirm" title="'._("Are you sure?").'" style="display:none"><h3>'._("Do you want to delete ALL custom whitelist entries?").'</h3></div>
			</div>
			<div align="justify" style="width: 100%; ">
				<table 
					id="whitelisttable" 
					data-cache="false" 
					data-escape="true"
					data-row-style="rowStyle"
					data-toolbar="#toolbarwl" 
					data-url="ajax.php?module=firewall&command=getwhitelist" 
					data-show-refresh="true" 
					data-maintain-selected="true" 
					data-show-columns="true" 
					data-show-export="true"
					data-export-types="[\'txt\']"
					data-show-toggle="true" 
					data-toggle="table" 
					data-pagination="true" 
					data-search="true" 
					class="table">
					<thead>
						<tr>
							<th data-formatter="actionwlFormatter" data-events="actionwlEvents" data-width="50px" data-field="action" class="text-center">'._("Action").'</th>
							<th data-width="200px" data-field="source" >'._("Source").'</th>
							<th data-field="type" >'._("Type").'</th>
						</tr>
					</thead>
				</table>
			</div>
		</div>
	</div>
	<!--END Whitelist-->
	<br>
	<div class="container-fuild">
		<div class="panel panel-default" '.$idstatus.' >
			<div class="panel-heading">
				<h3 class="panel-title">'._("IP's that are currently banned.").'</h3>
			</div>
			<br>
			<div id="toolbar">
				&nbsp;&nbsp;&nbsp;<button class="btn btn-default" type="button" id="unbanall">'._("Unban All").'</button>
			</div>
			<div align="justify" style="width: 100%; ">
				<table 
					id="banlisttable" 
					data-cache="false" 
					data-escape="true"
					data-url="ajax.php?module=firewall&command=getbannedlist" 
					data-show-refresh="true" 
					data-toolbar="#toolbar"
					data-row-style="rowStyleBan"
					data-maintain-selected="true" 
					data-show-columns="true" 
					data-show-toggle="true" 
					data-toggle="table" 
					data-pagination="true" 
					data-search="true" 
					class="table table-striped">
					<thead>
						<tr>
							<th data-formatter="actionFormatter" data-events="actionEvents" data-width="50px" data-field="action" class="text-center">'._("Action").'</th>
							<th data-width="200px" data-field="ip" >'._("IP Banned").'</th>
							<th data-field="type" >'._("Type").'</th>
						</tr>
					</thead>
				</table>
			</div>
		</div>
	</div>';
}

//only show the rest of the options if we have fail2ban installed
if ($i_d_conf) {
	echo $ftbhtml;
}
?>

<script>
  window.actionEvents = {
    'click .unban': function (e, value, row) {
		console.log("sdsds");
		var d = { command: 'unban', module: 'firewall', ip: row.ip};
		$.ajax({
			url: window.FreePBX.ajaxurl,
			data: d,
			async: false,
			success: function(data) {
				// Do something if necessary
			}
		});	 
		$('#banlisttable').bootstrapTable('refresh');
	},
	'click .move-to-whitelist': function (e, value, row) {
		var d = { command: 'move_to_whitelist', module: 'firewall', ip: row.ip};
		$.ajax({
			url: window.FreePBX.ajaxurl,
			data: d,
			async: false,
			success: function(data) {
				// Do something if necessary
			}
		});	 
		$('#banlisttable').bootstrapTable('refresh');
		$('#whitelisttable').bootstrapTable('refresh');
	},
  }

  window.actionwlEvents = {
	'click .del-custom': function (e, value, row) {
		var d = { command: 'del_custom', module: 'firewall', ip: row.source};
		$.ajax({
			url: window.FreePBX.ajaxurl,
			data: d,
			async: false,
			success: function(data) {
				// Do something if necessary
			}
		});	 
		$("#needApply").show();
		$('#whitelisttable').bootstrapTable('refresh');
	}
  }

  function actionFormatter(value, row, index) {
    return [
      '<i class="fa fa-trash unban" title="'+_("Remove this one.")+'" > <i class="fa fa-share move-to-whitelist" title="'+_("Move this one to the custom whitelist.")+'"></i>'
    ].join('')
  }

  function actionwlFormatter(value, row, index) {
	if(row.type == "Unresolved!!"){
		fpbxToast('Hostname "'+row.source+'", IP address not resolved.','Error','error');
		return [''].join('');
	}

	if(row.type == "Custom"){
		return [
		'<i class="fa fa-trash del-custom" title="'+_("Delete this one")+'">'
		].join('')
	}
    return [
      ''
    ].join('')
  }

    function rowStyleBan(row, index) {

	switch(row.type){
		case "(SIP)":
			return {
				css: {
						background: '#FCDBDB',
					}
			}
		case "(SSH)":
			return {
				css: {
						background: '#FFCECE',
					}
			}
		case "(apache-auth)":
			return {
				css: {
						background: '#FCB9BC',
					}
			}
		case "(FTP)":
			return {
				css: {
						background: '#FFA7AD',
					}
			}
		case "(BadBots)":
			return {
				css: {
						background: '#FF8B90',
					}
			}	
		default:
			return {
				css: {
					background: '#FCCACA'
				}
			}
	}

  }

  function rowStyle(row, index) {

	switch(row.type){
		case "Hosts":
		case "Trusted":
			return {
				css: {
						background: '#A2EDBF',
					}
			}
		case "Local":
			return {
				css: {
						background: '#B4F0C6',
					}
			}
		case "Other":
			return {
				css: {
						background: '#71F098',
					}
			}
		case "Custom":
			return {
				css: {
						background: '#3EE871',
					}
			}
		case "Ext. Registered":
			return {
				css: {
						background: '#BCF071',
					}
			}	
		default:
			return {
				css: {
					background: '#F08174'
				}
			}
	}

  }
</script>
<style>
:invalid, .error {
    background-color: #F2DEDE;
}
</style>
