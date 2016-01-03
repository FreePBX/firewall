$(document).ready(function() { 
	// Update address bar when someone changes tabs
	$("a[data-toggle='tab']").on('shown.bs.tab', function(e) { 
		// New target. Don't need jquery here...
		var newuri = updateQuery("tab", e.target.getAttribute('aria-controls'));
		window.history.replaceState(null, document.title, newuri);
	});

	// Grab del button clicks
	$("#attackersdiv").on("click", ".delbutton", function(e) {
		var t = $(e.target).data("ip");
		$.ajax({
			url: window.ajaxurl,
			data: { command: 'delattacker', module: 'firewall', target: t },
			success: function(data) { 
				triggerPageUpdate();
			},
		});
	});
	triggerPageUpdate();
});

function triggerPageUpdate() {
	if (typeof window.updatetrigger !== "undefined") {
		window.clearTimeout(window.updatetrigger);
	}
	updateStatusPage();
	window.updatetrigger = window.setTimeout(function() { triggerPageUpdate(); }, 15000);
}

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
	$(".notloading").hide();
	$(".loading").show();
	$.ajax({
		url: window.ajaxurl,
		data: { command: 'getattackers', module: 'firewall' },
		success: function(data) { 
			$(".notloading").text("").show();
			$(".loading").hide();
			processStatusUpdate(data); 
		},
	});
}


function processStatusUpdate(d) {
	// Summary page.
	$("#blocked").text(Object.keys(d.ATTACKER).length);
	$("#curblocked").text(d.summary.attackers.length);
	$("#rgd").text(d.summary.reged.length);
	$("#slowed").text(Object.keys(d.summary.clamped).length);
	$("#curslowed").text(d.summary.clamped.length);
	$("#totalremotes").text(d.summary.totalremotes);
	genRegHtml(d.summary.reged);
	genClampedHtml(d.summary.clamped);
	genBlockedHtml(d.summary.attackers, d);

	// Blocked only wants loading shown once.
	$(".onlyonce").removeClass("loading").removeClass("notloading");
}

function genRegHtml(registered) {
	if (registered.length == 0) {
		$("#noreged").show();
		return;
	}
	$("#noreged").hide();
	var h = "<ul>";
	$.each(registered, function (i, v) {
		h += "<li>"+v+"</li>";
	});
	h += "</ul>";
	$("#regul").html(h);
}

function genClampedHtml(clamped) {
	if (clamped.length == 0) {
		$("#noclamped").show();
		return;
	}
	$("#noclamped").hide();
	var h = "<ul>";
	$.each(clamped, function (i, v) {
		h += "<li>"+v+"</li>";
	});
	h += "</ul>";
	$("#clampeddiv").html(h);
}

function genBlockedHtml(attackers, d) {
	if (attackers.length == 0) {
		$("#noattackers").show();
		return;
	}
	$("#noattackers").hide();
	var h = "";
	$.each(attackers, function (i, v) {
		h += "<div class='element-container'><div class='row'><div class='col-sm-3'><h4>"+v+"</h4></div>";
		h += "<div class='col-sm-7'>Last 5 packets:<ul>"+formatTimestamps(v, d)+"</ul></div>";
		h += "<div class='col-sm-1'>";
		h += "<button type='button' class='btn x-btn btn-danger delbutton' data-ip='"+v+"' title='Unblock'><span data-ip='"+v+"' class='glyphicon glyphicon-remove'></span></button>"
		h += "</div></div>";
	});
	$("#attackersdiv").html(h);
}


function formatTimestamps(ip, data) {
	// data.summary.history.$ip contains a list of utimes.
	var resp = "";
	$.each(data.summary.history[ip], function(i, ut) {
		var d = new Date(ut.timestamp * 1000);
		resp += "<li>"+strDate(d)+" ("+ut.ago+"s ago)</li>\n";
	});
	return resp;
}

// This should probably override the Date object.. something like
// Date.prototype.getSaneDate = function () {
function strDate(d) {
	// Pad everything properly
	function pad(n){return n<10 ? '0'+n : n}
	var hh = pad(d.getHours());
	var mm = pad(d.getMinutes());
	var ss = pad(d.getSeconds());

	var dd = pad(d.getDate());
	var MM = pad(d.getMonth()+1); // Month is from 0-11, not 1-12.
	var yyyy = d.getFullYear();
	
	var ret = yyyy+"-"+MM+"-"+dd+" "+hh+":"+mm+":"+ss;
	return ret;
}
