<script type='text/javascript' src='modules/firewall/assets/js/views/logs.js'></script>

<div class='container-fluid'>
    <h3><?php echo _("Firewall Logs"); ?></h3>
    <div class="display no-border">
        <div class="row" id="logfiles_navbar">
            <div class="col-sm-12">
                <nav class="navbar navbar-default bg-primary">
                    <div class="container-fluid">
                        <button type="button" class="navbar-btn btn btn-default" id="btn_refresh_log"><i class="fa fa-refresh" aria-hidden="true"></i> <?php echo _("Refres Log"); ?></button>

                        <div class="nav navbar-form navbar-right" role="highlight" id="box_highlight">
                            <div class="btn-group" data-toggle="buttons">
                                <span class="radioset">
                                    <input type="radio" name="highlight_show_mode" id="highlight_show_mode_all" value="all" checked>
                                    <label class="btn btn-primary" data-for="highlight_show_mode" for="highlight_show_mode_all"><?php echo _("Show All"); ?></label>

                                    <input type="radio" name="highlight_show_mode" id="highlight_show_mode_only" value="only">
                                    <label class="btn btn-primary active" data-for="highlight_show_mode" for="highlight_show_mode_only"><?php echo _("Only Highlighted"); ?></label>
                                </span>
                            </div>
                            <div class="input-group">
                                <span class="input-group-addon"><span class="badge badge-default" id="highlight-results">···</span></span>
                                <input type="text" class="form-control" placeholder="<?php echo _("Highlight..."); ?>" aria-describedby="highlight-results" id="highlight_in_log">
                                <span class="input-group-btn">
                                    <button type="button" class="btn btn-secondary btn-info" id="btn_highlight_in_log"><i class="fa fa-search" aria-hidden="true"></i></button>
                                </span>
                            </div>
                        </div>
                    </div>
                </nav>
            </div>
        </div>
        <div class="row">
			<div class="col-sm-12">
                <div id="log_view" class="pre"><?php echo _("Loading...")?></div>
			</div>
		</div>
    </div>
</div>
