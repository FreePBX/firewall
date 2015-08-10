$(document).ready(function() { 
	// Register buttons being clicked
	$(".fwbutton").click(function(e) { e.preventDefault(); isClicked(this); });
	console.log("Ready");
});

function isClicked(o) {
	var counter, action, j;

	// jQuery the button.
	j = $(o);

	// Get the button counter..
	if (!j.data('counter')) {
		console.log("No counter attribue for button", o);
		return;
	}
	if (!j.data('action')) {
		console.log("No action attribue for button", o);
		return;
	}

	counter = j.data('counter');
	action = j.data('action');

	// Now, what do we do?
	switch(action) {
		case 'remove':
			removeNetwork(counter);
			return;
		case 'update':
			updateNetwork(counter);
			return;
		case 'create':
			createNetwork(counter);
			return;
		default:
			console.log("Unknown action");
			return;
	}
}

function opaqueRow(c) {
	$("#element-"+c).find('input,label,button').css({
		opacity: "0.33",
		cursor: "wait",
	}).click(function(e) { e.preventDefault(); });
}

function removeNetwork(c) {
	var net;

	console.log("Removing network "+c);
	opaqueRow(c);

	net = $("input[type=text]", "#element-"+c).val()
	$.ajax({
		url: window.ajaxurl,
		data: { command: 'removenetwork', module: 'firewall', net: net },
		complete: function(data) { console.log("Thing thing complete", data) },
	});

}

function updateNetwork(c) {
	console.log("Updating network "+c);
	opaqueRow(c);
}

function createNetwork(c) {
	console.log("Creating network "+c);
	opaqueRow(c);
}


