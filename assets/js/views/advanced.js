$(document).ready(function() { 
	// Add RFC1918 addresses
	$("#addrfc").click(function(e) { e.preventDefault(); addRfc(); });
});

function addRfc() {
	$.ajax({
		url: window.ajaxurl,
		data: { command: 'addrfc', module: 'firewall' },
		complete: function(data) { console.log("Complete"); window.xxx = data; },
	});
}

