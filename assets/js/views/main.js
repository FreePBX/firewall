$(document).ready(function() {
	// Don't let enter accidentally submit the form, which ends up disabling
	// the firewall.
	$("form").on("keypress", function(e) { if (e.keyCode == 13) e.preventDefault(); });

	// If we're not looking at the network or interface tab on page load, hide the action bar.
	// This needs work, as it's hacky.
	update_actionbar();
	if ($("#page_body li.active").data('name') !== "networks" && $("#page_body li.active").data('name') !== "interfaces") {
		$("#action-bar").hide();
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
});

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
	if (typeof netname == "undefined" || netname.trim().length == 0) {
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
	// If we're not looking at networks or interfaces, hide it.
	if ($("#page_body li.active").data('name') !== "networks" && $("#page_body li.active").data('name') !== "interfaces") {
		$("#action-bar").hide();
		return;
	}

	// If we're looking at networks, we want 'save' and 'delete selected'
	if ($("#page_body li.active").data('name') === "networks") {
		$("#action-bar").show();
		$("#savenets,#delsel").show();
		$("#saveints").hide();
		return;
	}

	// If we're looking at interfaces, we only want 'save interfaces'
	if ($("#page_body li.active").data('name') === "interfaces") {
		$("#action-bar").show();
		$("#saveints").show();
		$("#savenets,#delsel").hide();
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
