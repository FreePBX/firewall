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
		console.log("CS button pushed", e);
		window.zzz = e;
		var a = $(e.target).data('action');
		var id = $(e.target).data('svcid');
		if (a == "edit") {
			// Load the modal with the correct info.
			console.log("Editing svcid ",id);
		} else if (a == "save") {
			console.log("Submitting changes");
		} else if (a == "delete") {
			console.log("Delete modal?");
		}
	});

	// Update address bar when someone changes tabs
	$("a[data-toggle='tab']").on('shown.bs.tab', function(e) { 
		// New target. Don't need jquery here...
		var newuri = updateQuery("tab", e.target.getAttribute('aria-controls'));
		window.history.replaceState(null, document.title, newuri);
	});

	// Focus on an input when we show the modal
	$('#custmodal').on('show.bs.modal', function () { console.log("Show"); });
	$('#custmodal').on('shown.bs.modal', function () { console.log("Shown"); });

	// Strange stuff is happening.
	var x = document.getElementById("custmodal");
	x.addEventListener("transitionend", function() { console.log("Hit"); }, false);
	// Focus on an input when we show the modal
	/* $('#custmodal').on('shown.bs.modal', function () {
		console.log("Shown");
		$(".autofocus", "#custmodal").focus();
	}); */
	
	// Create new service
	$("#newcust").click(function() {
		// Reset the modal
		$("#mheader").text("Create New Service");
		$("#cportname,#cportrange").val("");
		$("#cprotocol").val('both');
		// And show it
		$("#custmodal").modal('show');
		$("#cportname").focus();
	});


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
