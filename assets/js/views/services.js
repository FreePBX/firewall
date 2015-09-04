$(document).ready(function() { 
	// This page has three buttons.
	// 1. Reset button is handled by script_legacy
	// 2. Defaults button 
	$("#btndefaults").click(function(e) { e.preventDefault(); console.log("reset to defaults"); });
	// 3. Save
	$("#btnsave").click(function(e) { e.preventDefault(); console.log("save this page"); });

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

});

