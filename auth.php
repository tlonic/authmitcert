<?php
// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

/**
 * Authentication backend using generic SSO
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Dominique Launay <dominique.launay AT cru.fr>
 * @author     Olivier Salaun <olivier.salaun AT cru.fr>
 * @author     Yoann Lecuyer <yoann.lecuyer AT cru.fr> 
 * @author     Etienne Meleard <etienne.meleard AT renater.fr> 
 **/

class auth_plugin_genericsso extends DokuWiki_Auth_Plugin {
    private $users = array();
    
    public function __construct() {
        parent::__construct();
        
        $this->loadConfig();
        
        $this->cando['external'] = true;
        $this->cando['logout'] = true;
        $this->success = false;
        
        // check if the server configuration has correctly been done
        $missing_conf = array();
        foreach(array('emailAttribute', 'loginURL', 'logoutURL') as $k)
            if(!array_key_exists($k, $this->conf) || !$this->conf[$k])
                $missing_conf[] = $k;
        
        if($missing_conf) {
            msg('Your genericsso configuration is not fully set, missing parameters : '.implode(', ', $missing_conf), -1, '', '', MSG_ADMINS_ONLY);
            return;
        }
        
        if(!array_key_exists('alwaysCheck', $this->conf))
            $this->conf['alwaysCheck'] = false;
        
        $this->success = true;
    }
    
    // Required
    public function checkPass($user, $pass) {}
    
    /**
    * Return user info
    **/
    public function getUserData($user) {
        if(is_null($this->users)) $this->loadUsers();
        if(array_key_exists($user, $this->users)) return $this->users[$user]; // Cache
        $this->users[$user] = array('name' => $user, 'mail' => $user, 'grps' => array());
        return $this->users[$user];
    }
    
    /**
    * Do all authentication
    * @param   string  $user    Username
    * @param   string  $pass    Cleartext Password
    * @param   bool    $sticky  Cookie should not expire
    * @return  bool             true on successful auth
    */
    public function trustExternal($user, $pass, $sticky=false) {
        global $USERINFO;
        global $ACT;
        global $conf;
        
        $do = array_key_exists('do', $_REQUEST) ? $_REQUEST['do'] : null;
        $user = $this->getSSOEMail();
        
        //Got a session already ?
        if($this->hasSession()) {
            if($this->conf['alwaysCheck'] && !$user) {
                auth_logoff();
                return false;
            }
            if($do == 'logout') $this->logOff(false); // Logout request ?
            return true;
        }else{ // No session, do the stuff
            if($user) {
                if($do == 'logout') $this->logOff(false); // Logout request ?
                
                $data = $this->getUserData($user);
                $this->setSession($user, $data['grps'], $data['mail'], $data['name']);
                error_log('genericsso : authenticated user');
                return true;
            }else{
                if($do == 'login') $this->logIn();
                //error_log('genericsso : no email address to log in');
                auth_logoff();
                return false;
            }
        }
    }
    
    private function hasSession() {
        if(is_null($_SESSION[DOKU_COOKIE])) return false;
        if(!array_key_exists('auth', $_SESSION[DOKU_COOKIE]) || !$_SESSION[DOKU_COOKIE]['auth']) return false;
        if(!array_key_exists('user', $_SESSION[DOKU_COOKIE]['auth']) || !$_SESSION[DOKU_COOKIE]['auth']['user']) return false;
        global $USERINFO;
        $USERINFO = $_SESSION[DOKU_COOKIE]['auth']['info'];
        $_SERVER['REMOTE_USER'] = $_SESSION[DOKU_COOKIE]['auth']['user'];
        return true;
    }
    
    // Create user session
    private function setSession($user, $grps = null, $mail = null, $name = null) {
        global $USERINFO;
        $USERINFO['name'] = $name ? $name : $user;
        $USERINFO['mail'] = $mail ? $mail : (mail_isvalid($user) ? $user : null);
        $USERINFO['grps'] = is_array($grps) ? $grps : array();
        $_SESSION[DOKU_COOKIE]['auth']['user'] = $user;
        $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
        $_SERVER['REMOTE_USER'] = $user;
        return $_SESSION[DOKU_COOKIE];
    }
    
    // Get EMail from Shib env
    private function getSSOEMail() {
        if(!array_key_exists($this->conf['emailAttribute'], $_SERVER)) return null;
        $mail = $_SERVER[$this->conf['emailAttribute']];
        if(!$mail || !mail_isvalid($mail)) return null;
        return $mail;
    }
    
    // Redirect for login
    public function logIn() {
        error_log('genericsso : redirect user for login to '.$this->conf['loginURL']);
        header('Location: '.str_replace('{target}', wl(getId()), $this->conf['loginURL']));
        exit;
    }
    
    // Redirect for logout
    public function logOff($ignore = true) {
        if($ignore) return;
        auth_logoff();
        error_log('genericsso : authenticated user redirected for logout to '.$this->conf['logoutURL']);
        header('Location: '.str_replace('{target}', $_SERVER['HTTP_REFERER'], $this->conf['logoutURL']));
        exit;
    }
    
    /**
    * Load local user data
    */
    private function loadUsers(){
        $this->users = array();
        if(!@file_exists(DOKU_CONF.'users.auth.php')) return;
        foreach(file(DOKU_CONF.'users.auth.php') as $line){
            $line = trim(preg_replace('/#.*$/', '', $line)); //ignore comments
            if(!$line) continue;
            $row = split(':', $line,5);
            $this->users[$row[0]] = array(
                'pass' => $row[1],
                'name' => urldecode($row[2]),
                'mail' => $row[3],
                'grps' => split(',', $row[4])
            );
        }
    }
}
