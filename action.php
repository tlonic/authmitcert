<?php
// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

/**
 * Authentication backend using generic SSO
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Etienne Meleard <etienne.meleard AT renater.fr> 
 **/

class action_plugin_genericsso extends DokuWiki_Action_Plugin {
    public function register(&$controller) {
        global $conf;
        
        if($conf['authtype'] != 'genericsso') return;
        
        $controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'handle_login_form', array());
    }
    
    public function handle_login_form(&$event, $param) {
        foreach($event->data->_content as $i => $field) {
            if(!is_array($field)) continue;
            if(!array_key_exists('name', $field)) continue;
            if(!in_array($field['name'], array('u', 'p', 'r'))) continue;
            unset($event->data->_content[$i]);
        }
    }
}
