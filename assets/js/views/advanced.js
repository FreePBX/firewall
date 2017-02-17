$(document).ready(function() { 
	// Add RFC1918 addresses
	$("#addrfc").click(function(e) { advancedAdd('addrfc', e.target); });

	// Add 'this host'
	$("#addhost").click(function(e) { advancedAdd('addthishost', e.target); });

	// Update address bar when someone changes tabs
	$("a[data-toggle='tab']").on('shown.bs.tab', function(e) { 
		var newuri = updateQuery("tab", e.target.getAttribute('aria-controls'));
		window.history.replaceState(null, document.title, newuri);
	});

});

function advancedAdd(cmd, target) {
	$(target).text(_("Updating...")).prop('disabled', true);
	$.ajax({
		url: window.FreePBX.ajaxurl,
		data: { command: cmd, module: 'firewall' },
		complete: function(data) { 
			$(target).text(_("Added"));
		}
	});
}

