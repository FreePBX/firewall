<?php
    $customs_edit = array(
        'ipv4' => array(
            'title' => _('IPv4'),
            'desc' => _('Custom IPTables rules for IPv4 protocol.'),
        ),
        'ipv6' => array(
            'title' => _('IPv6'),
            'desc' => _('Custom IPTables rules for IPv6 protocol.'),
        )
    );

    $box_warning = array(
        "customrules_disable" => array (
            "title" => _("Warnging:"),
            "txt" => array (
                _("The application of custom rules is <b>DISABLED</b>. You can edit them, but they will not be applied."),
                _("To <b>ACTIVATE</b> go to the <b>Advanced Settings</b> tab and activate the <b>Custom Firewall Rules</b> option.")
            )
        ),
        "check_file_error" => array (
            "title" => _("Warnging:"),
            "txt" => array (
                _("The file where the custom rules are stored does not exist or does not have the proper permissions. Run the following command on a console with enough permissions to fix the problem:"),
                "[root@host]# fwconsole firewall fix_custom_rules"
            )
        )
    );
    
    if (! $fw->check_custom_rules_files() ) {
        $fw->fixCustomRules(2);
    }

?>

<div class='container-fluid'>
    <h3><?php echo _("Custom Rules"); ?></h3>
        <div class='alert alert-warning msg-warning-custom-rules-disabled hide-element'>
            <?php
            echo "<h3>".$box_warning['customrules_disable']['title']."</h3>";
            foreach ($box_warning['customrules_disable']['txt'] as $line) { echo "<p>".$line."</p>"; }
            ?>
        </div>
        <?php
        foreach ($customs_edit as $protocol => $config) {
            $file_read = $fw->read_file_custom_rules($protocol);

            echo "<form>";
            echo sprintf ("<input type='hidden' name='protocol' value='%s'>", $protocol);

            echo "  <div class='panel panel-default'>";
            echo "      <div class='panel-body'>";
            echo "          <h3>".$config['title']."</h4>";
            echo "          <p>".$config['desc']."</p>";
            
            echo "          <div class='alert alert-warning msg-warning-check-file-error hide-element'>";
            echo "              <h5>".$box_warning['check_file_error']['title']."</h5>";
            foreach ($box_warning['check_file_error']['txt'] as $line) { echo "<p>".$line."</p>"; }
            echo "          </div>";

            echo "<textarea name='text_rules' spellcheck='false'>";
            foreach ($file_read as $line) { echo $line; }
            echo "</textarea>";
            echo "          <p>"._("Press F11 when cursor is in the editor to toggle full screen editing. ESC can also be used to exit full screen editing.")."</p>";
            echo "      </div>";
            echo "      <div class='panel-footer clearfix'>";
            echo "          <div class='pull-right'>";
            echo "              <div class='btn-group' role='group'>";
            echo "                  <button type='button' class='btn btn-secondary btn-save-custom-rules'>"._("Save")."</button>";
            echo "                  <button type='button' class='btn btn-secondary btn-save-apply-custom-rules'>"._("Save and Apply")."</button>";
            echo "                  <button type='button' class='btn btn-danger btn-reload-custom-rules'>"._("Reload")."</button>";
            echo '              </div>';
            echo '          </div>';
            echo '      </div>';
            echo '  </div>';
            echo "</form>";
        }
        ?>
    </div>    
</div>