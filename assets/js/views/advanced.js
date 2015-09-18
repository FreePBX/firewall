$(document).ready(function() { 
	// Add RFC1918 addresses
	$("#addrfc").click(function(e) { e.preventDefault(); advancedAdd('addrfc', e.target); });

	// Add 'this host'
	$("#addhost").click(function(e) { e.preventDefault(); advancedAdd('addthishost', e.target); });

	// Add 'this network'
	$("#addnetwork").click(function(e) { e.preventDefault(); advancedAdd('addthisnetwork', e.target); });

});

function advancedAdd(cmd, target) {
	var origtext = $(target).text();
	$(target).text("Updating...").prop('disabled', true);
	$.ajax({
		url: window.ajaxurl,
		data: { command: cmd, module: 'firewall' },
		complete: function(data) { 
			$(target).text(origtext).prop('disabled', false);
		}
	});
}

