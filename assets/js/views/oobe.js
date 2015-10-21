$(document).ready(function() { 
	$("#ssf1").click(function() {
		// Hide the s1 bits, show the s2 bits.
		$(".s1").slideUp();
		$(".s2").slideDown();
		$(".s1hide").hide();
		$(".s2show").show();
	});

	$("#ssf2").click(function() {
		// Hide the s2 bits, show the actual questions
		$(".hides3").slideUp();
		$(".s3").slideDown();
		getQuestion();
	});

});

function getQuestion() {
	$.ajax({
		url: window.ajaxurl,
		data: { command: 'getoobequestion', module: 'firewall' },
		success: function(data) { processQuestion(data); },
	});
}

function processQuestion(q) {
	if (typeof q.complete !== "undefined") {
		// No OOBE questions remain, so we can reload.
		window.location.reload();
		return;
	}
	var h = "<h3>"+q.desc+"</h3><div class='well'>";

	// helptext
	$.each(q.helptext, function(i, v) {
		h += "<p>"+v+"</p>";
	});

	h += "</div>";
	// Buttons.
	if (q.default === "yes") {
		h += "<div class='pull-right clearfix'><button type='button' class='btn btn-default' onClick='buttonNo()'>No</button><button type='button' class='btn btn-default' onclick='buttonYes()'>Yes</button></div>";
	} else {
		h += "<div class='pull-right clearfix'><button type='button' onClick='buttonYes()' class='btn btn-default'>Yes</button><button type='button' onClick='buttonNo()' class='btn btn-default'>No</button></div>";
	}
	$("#qdiv").html(h);
	$("#qdiv").data("currentquestion", q.question);
}


function buttonYes() {
	console.log("Yes clicked");
	submitAnswer($("#qdiv").data("currentquestion"), "yes");
}

function buttonNo() {
	console.log("No clicked");
	submitAnswer($("#qdiv").data("currentquestion"), "no");
}

function submitAnswer(q, ans) {
	$.ajax({
		url: window.ajaxurl,
		data: { command: 'answeroobequestion', module: 'firewall', question: q, answer: ans },
		success: function(data) { getQuestion(); },
	});
}

