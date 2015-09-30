$(document).ready(function() { 
	// Update address bar when someone changes tabs
	$("a[data-toggle='tab']").on('shown.bs.tab', function(e) { 
		// New target. Don't need jquery here...
		var newuri = updateQuery("tab", e.target.getAttribute('aria-controls'));
		window.history.replaceState(null, document.title, newuri);
	});

	updateStatusPage();

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

function updateStatusPage() {

	$.each($(".loading"), function(i, v) {
		var o = $(v);
		o.html(o.data('loading'));
	});

	$.ajax({
		url: window.ajaxurl,
		data: { command: 'getattackers', module: 'firewall' },
		success: function(data) { processStatusUpdate(data); },
	});
}


function processStatusUpdate(d) {
	// Summary page.
	$("#blocked").text(Object.keys(d.ATTACKER).length);
	$("#rgd").text(d.summary.reged.length);
	$("#slowed").text(Object.keys(d.summary.clamped).length);
	window.zzz = d;
	console.log(d);
}
	
