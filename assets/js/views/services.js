$(document).ready(function() { 
	// This page has three buttons.
	// 1. Reset button is handled by script_legacy
	// 2. Defaults button 
	$("#btndefaults").click(function(e) { e.preventDefault(); console.log("reset to defaults"); });
	// 3. Save
	// $("#btnsave").click(function(e) { e.preventDefault(); console.log("save this page"); });

	// If someone clicks on 'reject', turn off the other buttons.
	$(".rejectbutton").click(function(e) {
		var svc = $(e.target).data('svc');
		$(".svcbutton.svc-"+svc).prop('checked', false);
	});

	// If someone clicks on a normal button, make sure reject isn't checked
	$(".svcbutton").click(function(e) {
		var svc = $(e.target).data('svc');
		$(".rejectbutton.svc-"+svc).prop('checked', false);
	});

	// Custom Services
	$(".csbutton").click(function(e) {
		var a = $(e.target).data('action');
		var id = $(e.target).data('svcid');
		console.log(a);
		if (a == "edit") {
			// Load the modal with the correct info.
			console.log("Editing svcid ",id);
			var o = $("#csvc-"+id);
			$("#mheader").text("Edit Service");
			$("#custmodal").data("action", "edit");
			$("#custmodal").data("editid", id);
			$("#cportname").val(o.data("name"));
			$("#cportrange").val(o.data("port"));
			$("#cprotocol").val(o.data("protocol"));
			$("#cssave").text("Save").prop("disabled", false);
			$("#custmodal").modal("show");
		} else if (a == "save") {
			// Does not need a reload
			console.log("Submitting changes");
			$("."+id).prop("disabled", true);
			var d = { module: "firewall", command: "updatecustomzones", id: id, zones: [] };
			$.each($("."+id+":checked"), function(i, z) {
				d.zones.push($(z).data('zone'));
			});
			$.ajax({
				url: window.ajaxurl,
				data: d,
				complete: function(data) { $("."+id).prop("disabled", false); },
			});
		} else if (a == "delete") {
			// TODO: Show a delete modal?
			$("."+id).prop("disabled", true);
			$.ajax({
				url: window.ajaxurl,
				data: { module: "firewall", command: "deletecustomrule", id: id, },
				complete: function(data) { 
					window.location.href = window.location.href;
				}
			});
		}
	});

	// When they click 'Save' on the modal..
	$("#cssave").click(function() {
		saveCust();
	});

	// Update address bar when someone changes tabs
	$("a[data-toggle='tab']").on('shown.bs.tab', function(e) { 
		// New target. Don't need jquery here...
		var newuri = updateQuery("tab", e.target.getAttribute('aria-controls'));
		window.history.replaceState(null, document.title, newuri);
		// If this is the 'Custom Services' tab, hide the action bar, as it's not
		// used here.
		if (e.target.getAttribute('aria-controls') == "customsvc") {
			$("#action-bar").hide();
		} else {
			$("#action-bar").show();
		}
	});

	// Focus on an input when we show the modal
	$('#custmodal').on('shown.bs.modal', function () {
		$(".autofocus", "#custmodal").focus();
	});
	
	// Create new service
	$("#newcust").click(function() {
		// Reset the modal
		$("#mheader").text("Create New Service");
		$("#custmodal").data("action", "create");
		$("#cportname,#cportrange").val("");
		$("#cprotocol").val('both');
		$("#cssave").text("Save").prop("disabled", false);
		// And show it
		$("#custmodal").modal('show');
	});

	// Make sure, that when the page IS loaded, that if we're on customsvc
	// the action bar isn't shown.
	if (window.location.search.search("tab=customsvc") !== -1) {
		$("#action-bar").hide();
	}

});

function updateQuery(key, value) {
	var re = new RegExp("([?&])" + key + "=.*?(&|#|$)(.*)", "gi"), hash;
	var url = window.location.href;

	if (re.test(url)) {
		if (typeof value !== 'undefined' && value !== null) {
			return url.replace(re, '$1' + key + "=" + value + '$2$3');
		} else {
			hash = url.split('#');
			url = hash[0].replace(re, '$1$3').replace(/(&|\?)$/, '');
			if (typeof hash[1] !== 'undefined' && hash[1] !== null) {
				url += '#' + hash[1];
			}
			return url;
		}
	} else {
		if (typeof value !== 'undefined' && value !== null) {
			var separator = url.indexOf('?') !== -1 ? '&' : '?';
			hash = url.split('#');
			url = hash[0] + separator + key + '=' + value;
			if (typeof hash[1] !== 'undefined' && hash[1] !== null) 
				url += '#' + hash[1];
			return url;
		} else {
			return url;
		}
	}
}

function saveCust() {
	var d = { module: 'firewall',
		name: $("#cportname").val(),
		proto: $("#cprotocol").val(),
		port: $("#cportrange").val(),
	};
	// What am I doing?
	if ($("#custmodal").data("action") === "edit") {
		d.id = $("#custmodal").data('editid');
		d.command = "editcustomrule";
	} else {
		// Adding a new one.
		d.command = "addcustomrule";
	}
	console.log("Saving");
	$("#cssave").text("Saving...").prop("disabled", true);
	$.ajax({
		url: window.ajaxurl,
		data: d,
		complete: function(data) { 
			window.location.href = window.location.href;
		}
	});
}
