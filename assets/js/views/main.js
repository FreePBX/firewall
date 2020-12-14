$(document).ready(function() {
	// Don't let enter accidentally submit the form, which ends up disabling
	// the firewall.
	$("form").on("keypress", function(e) {if (e.keyCode == 13 &&  (e.target.id != "whitelist" && e.target.id != "custom_whitelist")) e.preventDefault(); });

	// If we're not looking at the network or interface tab on page load, hide the action bar.
	// This needs work, as it's hacky.
	update_actionbar();
	if ($("#page_body li.active").data('name') !== "networks" && $("#page_body li.active").data('name') !== "interfaces" && $("#page_body li.active").data('name') !== "intrusion_detection") {
		$("#action-bar").hide();
	}

	if($("#page_body a.active").text() === "Intrusion Detection"){
		$("#action-bar").show();
		$("#idtrustedzone").hide();
		$("#idlocalzone").hide();
		$("#idotherzone").hide();
		$("#clearall").hide();	
		// fpbxToast(_('The Intrusion Detection handling method has been updated recently. Please clear your browser cache and refresh if you are having issues seeing the Intrusion Detection Start/Restart/Stop button.'),'Note','info');
	}
	
	// Update address bar when someone changes tabs
	$("#page_body a[data-toggle='tab']").on('shown.bs.tab', function(e) {
		var newuri = updateQuery("tab", e.target.getAttribute('aria-controls'));
		window.history.replaceState(null, document.title, newuri);
		update_actionbar();
	});

	/**** Responsive Firewall Tab ****/
	$(".rfw").click(update_rfw);
	$(".safemode").click(update_safemode);
	$(".rejmode").click(update_rejectmode);

	/**** Interfaces Tab ****/
	// Update row colour on change
	$("#interfacestable").on("change", "select", update_zone_attr);
	// When someone clicks on 'Update Interfaces', post the form.
	$("#saveints").on("click", save_interface_zones);

	/**** Networks Tab ****/
	// When someone changes a network select tab, update the zone attr
	// so the background-colour changes (defined in the CSS selectors)
	$("#networkstable").on("change", "select", update_zone_attr);

	// Have they clicked on 'add'?
	$(".addnetwork").on("click", add_new_network);
	// Or, have they pushed enter in the new box, or new description box?
	$(".newentry").on("keydown", function(e) { if (e.keyCode == 13) add_new_network(e) });

	// Clicked the top checkbox button? Toggle.
	$("#toggleall").on("click", function(e) { $("#page_body .checkbox").prop("checked", $(e.target).prop("checked")); });

	// Clicked on 'Update all'?
	$("#savenets").on("click", save_all_nets);
	// Pushed enter in a description box?
	$(".description").on("keydown", function(e) { if (e.keyCode == 13) save_all_nets(e) });

	// Clicked on 'Delete Selected'?
	$("#delsel").on("click", delete_all_selected);

	// Clicked on 'Save Intrusion Detection'?
	$("#saveids").on("click", save_ids);

	// Clicked on Registered Extension IPs
	$("#idregextip").on("click", function(){
		if(typeof $("#idregextip").attr("active") === "undefined"){
			$("#idregextip").attr("active", true);
		}
		else{
			$("#idregextip").removeAttr("active");
		}
		get_button_status();
		$("#whitelisttable").bootstrapTable('refresh', {url: window.FreePBX.ajaxurl+'?module=firewall&command=getNewWhitelist&idregextip='+window.idregextip+'&trusted='+window.trusted+'&local='+window.local+'&other='+window.other});
	});

	// Clicked on id_stop
	$("#id_stop").on("click", function(){
		stop_id();
	});

	// Clicked on id_start
	$("#id_start").on("click", function(){
		start_id();
	});

	// Clicked on id_restart
	$("#id_restart").on("click", function(){
		start_id();
	});

	// Clicked on Refresh
	$("#idrefresh").on("click", function(){
		//update_whitelist();
		get_button_status();
		$("#whitelisttable").bootstrapTable('refresh', {url: window.FreePBX.ajaxurl+'?module=firewall&command=getNewWhitelist&idregextip='+window.idregextip+'&trusted='+window.trusted+'&local='+window.local+'&other='+window.other});
	});

	// Clicked on Trusted zone
	$("#idtrustedzone").on("click", function(){
		if(typeof $("#idtrustedzone").attr("active") === "undefined"){	
			$("#idtrustedzone").attr("active" ,true);
		}
		else{
			$("#idtrustedzone").removeAttr("active");
		}
		//update_whitelist();
		get_button_status();
		$("#whitelisttable").bootstrapTable('refresh', {url: window.FreePBX.ajaxurl+'?module=firewall&command=getNewWhitelist&idregextip='+window.idregextip+'&trusted='+window.trusted+'&local='+window.local+'&other='+window.other});
	});
	
	// Clicked on Local zone
	$("#idlocalzone").on("click", function(){
		if(typeof $("#idlocalzone").attr("active") === "undefined"){
			$("#idlocalzone").attr("active", true);	
		}
		else{
			$("#idlocalzone").removeAttr("active");	
		}
		//update_whitelist();
		get_button_status();
		$("#whitelisttable").bootstrapTable('refresh', {url: window.FreePBX.ajaxurl+'?module=firewall&command=getNewWhitelist&idregextip='+window.idregextip+'&trusted='+window.trusted+'&local='+window.local+'&other='+window.other});
	});

	// Clicked on Other zone
	$("#idotherzone").on("click", function(){
		if(typeof $("#idotherzone").attr("active") === "undefined"){
			$("#idotherzone").attr("active" ,true);
		}
		else{
			$("#idotherzone").removeAttr("active");	
		}
		//update_whitelist();
		get_button_status();
		$("#whitelisttable").bootstrapTable('refresh', {url: window.FreePBX.ajaxurl+'?module=firewall&command=getNewWhitelist&idregextip='+window.idregextip+'&trusted='+window.trusted+'&local='+window.local+'&other='+window.other});
	});

	// Clicked on Clear All
	$("#clearall").on("click", function(){
		$("#whitelist").val(_(""));
		$("#idregextip").removeAttr("active");
		$("#idtrustedzone").removeAttr("active");
		$("#idlocalzone").removeAttr("active");
		$("#idotherzone").removeAttr("active");	
		$("#whitelisttable").bootstrapTable("removeAll");
	});

	$("#whitelist").keyup(validateTextarea);

	$("#unbanall").on("click", function(){
		unbanall();
	})

	$("#delwl").on("click", function(){
		$("#delwl-confirm").dialog({
			resizable: false,
			height: "auto",
			width: 400,
			modal: true,
			buttons: {
				"Yes": function(){
					del_entire_whitelist();
					$(this).dialog("close");
				},
				Cancel: function(){
					$(this).dialog("close");
				}
			}
		});
	});
});

/**** Intrusion Dectection Tab ****/
function validateTextarea() {
    var errorMsg = _("At least one entry has been set incorrectly in the list !!");
    var pattern = new RegExp('^' + $("#whitelist").attr('pattern') + '$');
    $.each($("#whitelist").val().split("\n"), function () {
		var hasError = !this.match(pattern);
        if (typeof $("#whitelist").setCustomValidity === 'function') {
            $("#whitelist").setCustomValidity(hasError ? errorMsg : '');
        } else {			
            $("#whitelist").toggleClass('error', !!hasError);
            $("#whitelist").toggleClass('ok', !hasError);
            if (hasError) {
				$("#saveids").prop('disabled', 'true');
            } else {
				$("#saveids").removeAttr('disabled');
            }
        }
        return !hasError;
    });
}

function del_entire_whitelist(){
	var d = { command: 'del_entire_whitelist', module: 'firewall'};
	$.ajax({
		url: window.FreePBX.ajaxurl,
		data: d,
		async: false,
		success: function(data) {
			$('#whitelisttable').bootstrapTable('refresh');
		}
	});	
}
function stop_id(){
	var d = { command: 'stop_id', module: 'firewall'};
	$("#doing").html('<i class="fa fa-spinner fa-spin"></i></i>'+' '+_("Please wait...."));
	window.result = "";
	$.ajax({
		url: window.FreePBX.ajaxurl,
		data: d,
		async: false,
		success: function(data) {
			console.debug(data);
		}
	});
	setTimeout("window.location = window.location.href;",5500);
	return true; 
}

function unbanall(){
	var d = { command: 'unbanall', module: 'firewall'};
	$.ajax({
		url: window.FreePBX.ajaxurl,
		data: d,
		async: false,
		success: function(data) {
			$('#banlisttable').bootstrapTable('refresh');
		}
	});	
}

function start_id(){
	var d = { command: 'start_id', module: 'firewall'};
	$("#doing").html('<i class="fa fa-spinner fa-spin"></i></i> '+' '+_("Please wait...."));
	window.result = "";
	$.ajax({
		url: window.FreePBX.ajaxurl,
		data: d,
		async: false,
		success: function(data) {
			// Do something if necessary
		}
	});
	setTimeout("window.location = window.location.href;",5500);
	return true; 
}

function save_ids(){
	get_button_status();
	var d = { command: 'saveids', 
			  module: 'firewall', 
			  ban_time: $("#ban_time").val(),
			  max_retry: $("#max_retry").val(),
			  find_time: $("#find_time").val(),
			  email: $("#email").val(),
			  whitelist: $("#whitelist").val(),
			  idregextip: window.idregextip,
			  trusted: window.trusted,
			  local: window.local,
			  other: window.other,
			  whitelist: $("#whitelist").val()
			};
	$.ajax({
		url: window.FreePBX.ajaxurl,
		data: d,
		success: function(){
			$("#needApply").hide();
		},
		complete: function(data) {
			
			window.location.href = window.location.href;
		}
	});
}

function get_button_status(){
	window.idregextip 	= (typeof $("#idregextip").attr("active") === "undefined")? "false": "true";
	window.trusted 		= (typeof $("#idtrustedzone").attr("active") === "undefined")? "false": "true";
	window.local 		= (typeof $("#idlocalzone").attr("active") === "undefined")? "false": "true";
	window.other 		= (typeof $("#idotherzone").attr("active") === "undefined")? "false": "true";
}

function update_whitelist(){
	whitelist	= "";
	get_button_status();

	if(window.idregextip){
		whitelist += gettrusted('extregips');
	}

	if(window.trusted){
		whitelist += gettrusted('trusted');
	}

	if(window.local){
		whitelist += gettrusted('local');
	}

	if(window.other){
		whitelist += gettrusted('other');
	}

	return whitelist;
}

function gettrusted(from){
	var d = { command: 'getIPsZone', module: 'firewall', from: from	};
	window.result = "";
	$.ajax({
		url: window.FreePBX.ajaxurl,
		data: d,
		async: false,
		success: function(data) {
			$.each(data, function(idx, ip){
				if(ip !== true){
					window.result += ip+'\n';	
				}					
			});
		}
	});
	
	return window.result.replace("\n\n","\n");
}

/**** Responsive Firewall Tab ****/
function update_rfw(event) {
	var target = event.target;
	var d = { command: 'updaterfw', module: 'firewall', proto: target.getAttribute('name'), value: target.getAttribute('value') };
	$("input[name="+target.getAttribute('name')+"]").prop('disabled', true);
	$.ajax({
		url: window.FreePBX.ajaxurl,
		data: d,
		complete: function(data) {
			window.location.href = window.location.href;
		}
	});
}

function update_safemode(event) {
	var target = event.target;
	var d = { command: 'setsafemode', module: 'firewall', value: target.getAttribute('value') };
	var n = target.getAttribute('name');
	$("input[name="+n+"]").prop('disabled', true);
	$.ajax({
		url: window.FreePBX.ajaxurl,
		data: d,
		success: function(data) {
			if (typeof data.message !== "undefined") {
				if (data.message == "enabled") {
					$("#safewarning").slideDown();
				} else {
					$("#safewarning").slideUp();
				}
			}
			$("input[name="+n+"]").prop('disabled', false);
		},
	});
}

function update_rejectmode(event) {
	var target = event.target;
	var d = { command: 'setrejectmode', module: 'firewall', value: target.getAttribute('value') };
	var n = target.getAttribute('name');
	$("input[name="+n+"]").prop('disabled', true);
	$.ajax({
		url: window.FreePBX.ajaxurl,
		data: d,
		success: function(data) {
			$("input[name="+n+"]").prop('disabled', false);
		},
	});
}

function update_zone_attr(event) {
	var target = $(event.target);
	// The parent id is in data('rowid')
	var parentid = target.data('rowid');
	// Is it a network or an interface?
	var type=target.data('type');
	// Get our divs to update.
	var divs = $("."+type+"-"+parentid);

	if (divs.length === 0) {
		// That shouldn't happen
		return;
	}
	divs.attr('zone', target.val());
	// Interfaces can be linked to parents. If there are any, update them, too.
	console.log("select[parent='"+target.data('intname')+"']");
	$("select[parent='"+target.data('intname')+"']").each(function() {
		// Duplcate the code up there, basically, but we also need to
		// update the val on the children
		$(this).val(target.val());
		var p = $(this).data('rowid');

		// Set the colours to match
		$("."+type+"-"+p).attr('zone', target.val());
	});
}

function add_new_network(event) {
	event.preventDefault();
	var target = $(event.target);
	var c = target.data('counter');
	if (typeof c == "undefined") {
		// Bug.
		console.log("Target doesn't have counter", target);
		return;
	}
	var netname = $("input[name='newentry']").val();
	var descr = $("input[name='netdescr-"+c+"']").val();
	var zone = $("select[data-rowid='"+c+"']").val();

	// IF there's no netname, error on it
	var pattern = new RegExp('^([a-zA-Z0-9.:_\/\-]+)$');
	if (typeof netname == "undefined" || netname.trim().length == 0 || !pattern.test(netname.trim())) {
		console.log("Netname invalid", netname);
		$("input[name='newentry']").addClass('pulsebg');
		window.setTimeout(function() { $("input[name='newentry']").removeClass('pulsebg') }, 2000);
		return;
	}
	// Send it to FreePBX for validation
	// If it errors, use the error handler.
	$.ajax({
		url: window.FreePBX.ajaxurl,
		data: { command: 'addnetworktozone', module: 'firewall', net: netname, zone: zone, description: descr },
		success: function(data) { window.location.href = window.location.href; },
	});
}

function save_all_nets(ignored) {
	var networks = {};

	var save_nets = function() {
		// Loop through our networks
		$(".netzone").each(function(i, v) {
			var c = $(v).data('counter');
			var netname = $("tt[counter='"+c+"']").text();
			if (netname.length === 0) {
				return;
			}
			var zone = $("select[name='zone-"+c+"']", "#networkstable").val();
			var descr = $("input[name='netdescr-"+c+"']", "#networkstable").val();
			networks[netname] = { zone: zone, description: descr };
		});

		// Now do an ajax post to update our networks
		$.ajax({
			method: 'POST',
			url: window.FreePBX.ajaxurl,
			data: { command: 'updatenetworks', module: 'firewall', json: JSON.stringify(networks) },
			success: function(data) { window.location.href = window.location.href; },
		});
	};

	if($("input[name=newentry]").val() !== "") {
		var target = $("input[name=newentry]");
		var c = target.data('counter');
		if (typeof c == "undefined") {
			// Bug.
			console.log("Target doesn't have counter", target);
			return;
		}
		var netname = $("input[name='newentry']").val();
		var descr = $("input[name='netdescr-"+c+"']").val();
		var zone = $("select[data-rowid='"+c+"']").val();

		// Send it to FreePBX for validation
		// If it errors, use the error handler.
		$.ajax({
			url: window.FreePBX.ajaxurl,
			data: { command: 'addnetworktozone', module: 'firewall', net: netname, zone: zone, description: descr },
			success: function(data) { save_nets(); },
		});
	} else {
		save_nets();
	}
}

function delete_all_selected(ignored) {
	var networks = [];
	// Get all the networks to delete
	$(".checkbox:checked").each(function(i, v) {
		var c = $(v).data('counter');
		networks.push($("tt[counter='"+c+"']").text());
	});
	if (Object.keys(networks).length === 0) {
		alert(_("No networks selected"));
		return;
	}
	// Now do an ajax post to update our networks
	$.ajax({
		method: 'POST',
		url: window.FreePBX.ajaxurl,
		data: { command: 'deletenetworks', module: 'firewall', json: JSON.stringify(networks) },
		success: function(data) { window.location.href = window.location.href; },
	});
}

function update_actionbar() {
	if($("#page_body a.active").text() === "Intrusion Detection"){
		$("#action-bar").show();
		$("#idtrustedzone").hide();
		$("#idlocalzone").hide();
		$("#idotherzone").hide();
		$("#clearall").hide();
		return;
	}

	// If we're not looking at networks or interfaces, hide it.
	if ($("#page_body li.active").data('name') !== "networks" && $("#page_body li.active").data('name') !== "interfaces" && $("#page_body li.active").data('name') !== "intrusion_detection") {
		$("#action-bar").hide();
		return;
	}

	// If we're looking at networks, we want 'save' and 'delete selected'
	if ($("#page_body li.active").data('name') === "networks") {
		$("#action-bar").show();
		$("#savenets,#delsel").show();
		$("#saveints,#saveids").hide();
		return;
	}

	// If we're looking at interfaces, we only want 'save interfaces'
	if ($("#page_body li.active").data('name') === "interfaces") {
		$("#action-bar").show();
		$("#saveints").show();
		$("#savenets,#delsel,#saveids").hide();
		
		return;
	}

	// If we're looking at intrusion detection, we only want 'save intrusion detection'
	if ($("#page_body li.active").data('name') === "intrusion_detection") {
		$("#action-bar").show();
		$("#savenets,#delsel").hide();
		$("#saveints").hide();
		$("#saveids").show();
		
		// if Intrusion Detection is stopped
		if (!$("#ban_time").is(":visible")){
			$("#action-bar").hide();
		}
		return;
	}

	// How did we get here?
	console.log("error?");
}

function save_interface_zones() {
	// Ajax setup
	var d = { command: 'updateinterfaces', module: 'firewall' };
	// Build our array of interfaces to be sent as JSON
	var ints = {};
	$(".intselect").each(function() {
		var intname = $(this).data('intname');
		var counter = $(this).data('rowid');
		var newzone = $(this).val();
		var desc = $("input", "#intdescription-"+counter).val();
		ints[intname] = { zone: newzone, description: desc };
	});

	d['ints'] = JSON.stringify(ints);
	$.ajax({
		method: 'POST',
		url: window.FreePBX.ajaxurl,
		data: d,
		success: function(data) { window.location.href = window.location.href; },
	});
}
