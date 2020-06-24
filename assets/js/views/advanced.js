class control_module {

	constructor(module, autostart = true) {
		this._debug = true;
		this._module = module;

		this.onTabChange = null;
		this.onTimerRunEnd = null;

		this._reset();

		if (autostart == true) {
			this.start_update();
		}
	}

	_reset() {
		this._tab_active = '';
		this._timer_update = null;
		this._list_tabs = {};
		this._list_timer = {};
	}

	_isFunction(check_fun) {
		return (typeof check_fun === "function");
	}

	/* Propertys */
	get debug() {
        return this._debug;
    }

    set debug(x) {
        this._debug = x;
	}
	
	get module() {
		return this._module;
	}

	get tab_active() {
		return this._tab_active;
	}

	set tab_active(new_status) {
		if (new_status != this._tab_active) {
			var tab_old = this._tab_active;
			this._tab_active = new_status;
			this._tab_active_change(this, tab_old);
		}
	}


	/* Functions */
	start_update() {
		var self = this;
		this.stop_update();
		this._timer_update = setInterval( function() { self.refres_data(); }, 200);
	}

	stop_update() {
		clearInterval(this._timer_update);
	}

	refres_data() {
		var self = this;
		//console.log("Update data Module (" + this._module + ")");

		$("div[role='tabpanel']").each(function(e) {
			if ( $(this).hasClass('active') ) {
				self.tab_active = $(this).attr('id');
			}
		});
	}

	/**
	 * Check if tab specific is the active tab.
	 * @param {*} name tab name to check
	 */
	isTabActive(name) {
		return ( name == this._tab_active );
	}

	/**
	 * add the tab's in which we want a function to be executed when activated or deactivated. 
	 * @param {*} name name tab
	 * @param {*} call_set function called when tab is activated.
	 * @param {*} call_unset function called when tab is disabled.
	 */
	add_tab_control(name, call_set = null, call_unset = null) {
		this._list_tabs[name] = {
			"name": name,
			"call_set": call_set,
			"call_unset": call_unset
		};
	}

	_tab_active_change(e, tab_old) {
		var tab_name = e.tab_active;
		if ( (tab_name in this._list_tabs) ) {
			var tab_obj = $("#"+tab_name);
			if ( this._isFunction(this._list_tabs[tab_name]['call_set']) ) {
				this._list_tabs[tab_name]['call_set'](tab_obj);
			}
		}
		if ( (tab_old in this._list_tabs) ) {
			var tab_obj = $("#"+tab_old);
			if ( this._isFunction(this._list_tabs[tab_old]['call_unset']) ) {
				this._list_tabs[tab_old]['call_unset'](tab_obj);
			}
		}
		if ( this._isFunction(this.onTabChange) ) {
			this.onTabChange(e, tab_old);
		}
	}

	add_timer(name, interval, call_fun, call_arg, async = false, nostop = false, autostart = false) {
		if (this._isExistTimer(name)) {
			this.stop_timer(name);
		}
		this._list_timer[name] = {
			"name": name,
			"call_fun": call_fun,
			"call_arg": call_arg,
			"interval": interval,
			"async": async,
			"nostop": nostop,
			"idTimer": null,
			"status": "new",
			"count": 0
			
		}
		if (autostart) {
			this.start_timer(name);
		}
	}

	start_timer(name) {
		var self = this;
		if (name == null) {
			for(var key in this._list_timer) {
				this.start_timer(key);
			}
		} else {
			if ( this._isExistTimer(name) ) {
				switch (this._list_timer[name].status) {
					case "new":
					case "stop":
						this._list_timer[name].status = "waiting_run";
						this._list_timer[name].count = 0;
						this._run_timer(name);
						break;

					case "run_end":
						this._list_timer[name].status = "waiting_run";
						this._list_timer[name].count += 1;
						this._list_timer[name].idTimer = setTimeout( function(){ self._run_timer(name); } , this._list_timer[name].interval);
						break

					default:
						if ( this.debug ) {
							console.log(_("control_module > start_timer > name (%s) > status (%s) not valid!"), name, this._list_timer[name].status); 
						}
				}
			} 
			else { 
				if ( this.debug ) {
					console.log(_("control_module > start_timer > name (%s) not valid!"), name); 
				}
			}
		}
	}

	stop_timer(name) {
		if (name == null) {
			for(var key in this._list_timer) {
				if (this._list_timer[key].nostop) {
					continue;
				}
				this.stop_timer(key);
			}
		} else {
			if ( this._isExistTimer(name) ) {
				clearTimeout(this._list_timer[name].idTimer);
				this._list_timer[name].status = "stop";
			} 
			else { 
				if ( this.debug ) {
					console.log(_("control_module > stop_timer > name (%s) not valid!"), name);
				}
			}
		}
	}

	_run_timer(name) {
		var self = this;
		if ( this._isExistTimer(name) ) {
			switch (this._list_timer[name].status) {

				case "waiting_run":
					this._list_timer[name].status = "running";
					if (this._isFunction(this._list_timer[name].call_fun)) {
						this._list_timer[name].call_fun(this._list_timer[name], this._list_timer[name].call_arg);
						if ( this._list_timer[name].async ) {
							this._list_timer[name].status = "run_end";
						}
					} else {
						if ( this.debug ) {
							console.log(_("control_module > _run_timer > name (%s) > call_fun is not a function, timer stop!"), name);
						}
						this.stop_timer(name);
						break;
					}

				case "running":
					if (this._list_timer[name].status != "run_end") {
						this._list_timer[name].idTimer = setTimeout( function(){ self._run_timer(name); }, 100);
						break;
					}

				case "run_end":
					if ( this._isFunction(this.onTimerRunEnd) ) {
						this.onTimerRunEnd(this, name);
					}
					this.start_timer(name);
					break;
				
				case "run_error":
					if ( this.debug ) {
						console.log(_("control_module > _run_timer > name (%s) > status (%s), timer stop!"), name, this._list_timer[name].status);
					}
					this.stop_timer(name);
					break;

				default:
					if ( this.debug ) {
						console.log(_("control_module > _run_timer > name (%s) > status (%s) not valid!"), name, this._list_timer[name].status);
					}
			}
		}
		else { 
			if ( this.debug ) {
				console.log(_("control_module > _run_timer > name (%s) not valid!"), name);
			}
		}
	}

	_isExistTimer(name) {
		return (name in this._list_timer)
	}
	
}

var mod_firewall_control = new control_module("firewall", false);
mod_firewall_control.onTabChange = function (e, tab_old) {
};
mod_firewall_control.add_tab_control("advanced_customrules", advanced_custom_rules_setfocus, advanced_custom_rules_unsetfocus);


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

	// Advanced Settings Page
	$(".advsetting").on("click", advanced_button_click);


	// Advanced Custom Rules
	$(window).resize(function() {
		fix_codemirror_long_line();
	});

	$(".btn-reload-custom-rules").click(function(e) { advanced_custom_rules_read_file(e.target); });
	$(".btn-save-custom-rules").click(function(e) { advanced_custom_rules_save_file(e.target, "no"); });
	$(".btn-save-apply-custom-rules").click(function(e) { advanced_custom_rules_save_file(e.target, "yes"); });
	

	// Advanced Custom Rules - Detect Change Tab
	mod_firewall_control.start_update();
});


// TAB > INI > Advanced Custom Rules

function fix_codemirror_long_line(){
	/*
		Al añadir líneas muy largas la anchura limite no se controla y la pagina se estira horizontalmente.
		Se ha intentado usar “max-width” o “width” con un valor del 100% pero no funciona, se ha tenido que optar por añadir una anchura fija en pixels.
			1. Cambiamos el ancho 10px para que el div padre se ajuste al tamaño correctamente. Si hacemos esto el div padre no se redimensionará.
			2. Ajustamos la anchura con el valor del objeto padre.

		When adding very long lines the width limit is not controlled and the page stretches horizontally.
		An attempt has been made to use “max-width” or “width” with a value of 100% but it does not work, we have had to choose to add a fixed width in pixels.
			1. We change the width 10px so that the parent div fits correctly. If we do this the parent div will not be resized.
			2. We adjust the width with the value of the parent object.
	*/
	$('#advanced_customrules .CodeMirror').not(".CodeMirror-fullscreen").each(function() {
		$(this).css('width', "10px" );
	});
	$('#advanced_customrules .CodeMirror').not(".CodeMirror-fullscreen").each(function() {
		$(this).css('width', $(this).parent().width() );
	});
}

function advanced_custom_rules_setfocus(e) {
	$("textarea[name='text_rules']", $(e)).each(function() {
		if ( $(this).css('display') !== 'none' ) {
			var editor = CodeMirror.fromTextArea($(this)[0], {
				lineNumbers: true,
				indentWithTabs : true,
				smartIndent : true,
				lineWrapping : false,
				scrollbarStyle: "simple",
				//gutter: true,
				//lineWrapping: true,
				extraKeys: {
					"F11": function(cm) {
						cm.setOption("fullScreen", !cm.getOption("fullScreen"));
						if (! cm.getOption("fullScreen")) {
							fix_codemirror_long_line();
						}
					},
					"Esc": function(cm) {
						if (cm.getOption("fullScreen")) {
							cm.setOption("fullScreen", false);
							fix_codemirror_long_line();
						}
					}
				}
			});
			editor.on('change', editor => {
				//TODO: Codigo on Change
			});
			editor.setSize( $(this).parent().width(), 200);
		}
	});


	var ls_timers = {
		'advanced_custom_rules_status' : {
			"call_fun": advanced_custom_rules_status,
			"call_arg": e,
			"interval": 5000
		},
		'advanced_custom_rules_check_files_all' : {
			"call_fun": advanced_custom_rules_check_files_all,
			"call_arg": e,
			"interval": 5000
		}
	};
	for (const [key, value] of Object.entries(ls_timers)) {
		if (! mod_firewall_control._isExistTimer(key)) {
			mod_firewall_control.add_timer(key, value.interval, value.call_fun, value.call_arg);
		}
	}
	mod_firewall_control.start_timer(null);
}

function advanced_custom_rules_unsetfocus(e) {
	mod_firewall_control.stop_timer(null);
}

function advanced_custom_rules_status(c, e) {
	if (mod_firewall_control.isTabActive( e.attr('id') ) == true) {
		$.post(window.FreePBX.ajaxurl, { 'module': 'firewall',  'command': 'advanced_custom_rule_status'}, function(data){
			if (data.status == true) {
				if (data.message == "enabled") {
					$(".msg-warning-custom-rules-disabled:visible", e).hide("slow");
				}
				else {
					$(".msg-warning-custom-rules-disabled:hidden", e).show("slow");
				}
			}
		})
		.done(function() {
			c.interval = 5000;
		})
		.fail(function() {
			fpbxToast(_("Error Checking Status!"), '', 'error');
			c.interval = 1000;
		})
		.always(function() {
			c.status = "run_end";
		});
	} else {
		c.status = "run_error";
	}
}

function advanced_custom_rules_check_files_all(c, e) {
	if (mod_firewall_control.isTabActive( e.attr('id') ) == true) {
		c.interval = 5000;
		$("form", e).each(function() {
			var form = $(this);
			var protocol = $("input[name='protocol']", form).val();
			var json_data = advanced_custom_rules_check_file(protocol);
			var form_disable = null;

			if (json_data == null) {
				c.status = "run_error";
			}
			else {
				if (json_data.status == true) {
					if (json_data.message == "ok") {
						$(".msg-warning-check-file-error:visible", form).each(function() {
							$(this).hide("slow");
							form_disable = false;
						});
					}
					else {
						$(".msg-warning-check-file-error:hidden", form).each(function() {
							$(this).show("slow");
							form_disable = true;
						});
					}
				} else {
					fpbxToast(sprintf(_('Error checking protocol file (%s)!'), protocol), '', 'error');
					c.interval = 1000;
					form_disable = true;
				}
				if (form_disable != null) {
					advanced_custom_rules_form_disable(form, form_disable);
				}
				c.status = "run_end";
			}
		});
	} else {
		c.status = "run_error";
	}
}

function advanced_custom_rules_check_file(protocol) {
	var data_return = null;
	$.ajax({
		async: false,
		type: 'POST',
		url: window.FreePBX.ajaxurl,
		data: { command: 'advanced_custom_check_files', module: 'firewall', protocoltype: protocol }
	}).done(function(data) {
		data_return = data;
	});
	return data_return;

}

function advanced_custom_rules_read_file(e) {
	fpbxConfirm(
		_("Are you sure to reload the rules? changes will be lost."),
		_("Yes"),_("No"),
		function(){
			var form = e.form;
			var protocol = $("input[name='protocol']", form).val();
			var e_textarea = form.querySelector('.CodeMirror').CodeMirror;

			//Disable all element in the form
			advanced_custom_rules_form_disable(form, true);

			$.post(window.FreePBX.ajaxurl, { 'module': 'firewall',  'command': 'advanced_custom_rule_read_file', 'protocoltype': protocol}, function(data){
				if (data.status == true) {
					var strValue = '';
					data.data.forEach( function( line ) {
						strValue += line;
					});
					e_textarea.setValue(strValue);
				} else {
					e_textarea.setValue( sprintf(_('Error (%s): %s'), data.code, data.message) );
				}
			})
			.done(function(data) {
				if (data.status == true) {
					fpbxToast(sprintf(_('Protocol data (%s) loaded successfully.'), protocol), '', 'success');
					//Enabled all element in the form
					advanced_custom_rules_form_disable(form, false);
				}
				else {
					fpbxToast(data.message, '', 'error');
					//Enabled Only button Reload Rules
					$("button.btn-reload-custom-rules", form).prop('disabled', false);
				}
			})
			.fail(function(e) {
				var error = e.responseJSON.error;
				var str_error = "";
				str_error += sprintf(_('# %s: %s\n'), error.type, error.message);
				str_error += sprintf(_('# %s (%s)'), error.file, error.line);
				e_textarea.setValue( str_error );

				//Enabled Only button Reload Rules
				$("button.btn-reload-custom-rules", form).prop('disabled', false);
			})
			.always(function() {
				e_textarea.focus();
				e_textarea.markClean();
			});
		}
	);
}

function advanced_custom_rules_save_file(e, restart_firewall) {
	var form = e.form;
	var protocol = $("input[name='protocol']", form).val();
	var e_textarea = form.querySelector('.CodeMirror').CodeMirror;

	if (e_textarea.isClean() == true) {
		fpbxToast(sprintf(_('No hace falta guardar nada, los datos de (%s) son los cargados inicialmente.'), protocol), '', 'info');
	}
	else {
		fpbxConfirm(
			_("Are you sure to save the data?"),
			_("Yes"),_("No"),
			function(){
				//Disable all element in the form
				advanced_custom_rules_form_disable(form, true);

				var data_send = e_textarea.getValue();
				$.post(window.FreePBX.ajaxurl, { 'module': 'firewall', 'command': 'advanced_custom_rule_save', 'restart_firewall': restart_firewall, 'protocoltype': protocol, 'newrules': data_send})
				.done(function(data) {
					if (data.status == true) {
						fpbxToast(sprintf(_('Protocol data (%s) saved successfully.'), protocol), '', 'success');
						e_textarea.markClean();
					}
					else {
						fpbxToast(data.message, '', 'error');
					}
				})
				.always(function() {
					e_textarea.focus();

					//Enabled all element in the form
					advanced_custom_rules_form_disable(form, false);
				});
			}
		);

	}
}

function advanced_custom_rules_form_disable(form, newstatus) {
	advanced_custom_rules_textarea_readonly(form, newstatus);
	advanced_custom_rules_buttons_disabled(form, newstatus);
}

function advanced_custom_rules_textarea_readonly(form, newstatus) {
	$("textarea", form).each(function() {
		$(this).prop('readonly', newstatus);
	});
}

function advanced_custom_rules_buttons_disabled(form, newstatus) {
	$("button", form).each(function() {
		$(this).prop('disabled', newstatus);
	});
}

// TAB > END > Advanced Custom Rules


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

function advanced_button_click(e) {
	var t = e.currentTarget;
	var setting = t.getAttribute('name');
	// Set them to disabled while we ajax
	$(".advsetting[name='"+setting+"']").attr('disabled', true);
	$.ajax({
		url: window.FreePBX.ajaxurl,
		data: { command: "updateadvanced", module: 'firewall', option: setting, val: $(t).val() },
		complete: function() { 
			$(".advsetting[name='"+setting+"']").attr('disabled', false);
		}
	});
}

