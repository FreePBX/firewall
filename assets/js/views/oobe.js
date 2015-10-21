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
		$.ajax({
			url: window.ajaxurl,
			data: { command: 'getoobequestion', module: 'firewall' },
			success: function(data) { processQuestion(data); },
		});
	});

});

function processQuestions(q) {
	window.zzz = q;
	var h = "<h3>"+q.question+"</h3>";
	h =+ "<p class='help-block'>"+q.helptext+"</p>";
	h =+ q.html;
	$("#qdiv").html(h);
}

