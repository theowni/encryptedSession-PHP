<?php 
/**
 *  Class encryptedSession
 *  Manages and keeps safer session files. Increases prevention from popular attacks.
 * 
 * 
 *  Description
 *     - many customization options via __construct()
 *     - using fingerprint
 *     - passing session_id only via GET
 *     - regenerate_id() with 20% probability
 *     - data encryption using algorithm MCRYPT_RIJNDAEL_256
 *     - sessions can be used normally
 *
 *
 *  @version 	1.1
 *  @license 	https://opensource.org/licenses/MIT
 *  @copyright 	theownI
 *
 *  @contact kpranczk7@gmail.com
 *
 */

class encryptedSession implements SessionHandlerInterface
{
    private $secretKey, $name, $lifetime, $savePath, $cookie, $algo = MCRYPT_RIJNDAEL_256;                # the key should be random binary, recommended 32byte, only one for site
																										  # default crypt algorithm MCRYPT_RIJNDAEL_128
																										  # default path is system default (when $path = '')
																										  				 
	public function __CONSTRUCT($key, $name = 'PHP_SESSIONID', $lifetime = 10, $path = '', $cookie = [])       
	{	
		# You can set settings in php.ini (recommended) instead of using every time ini_set('setting', 'value')  
		
		if (!extension_loaded('mcrypt')) {
			throw new Exception("There is no mcrypt extension loaded. Encrypted Session class needs mcrypt to work properly.");
		}

		$this->secretKey = $key;
		$this->name = $name;
		$this->lifetime = $lifetime;
		$this->savePath = $path;
		
		$default_params = array(
			'lifetime' => 0,                                           # cookie exists until the browser is closed
			'path' => ini_get('session.cookie_path'),                  
			'domain' => ini_get('session.cookie_domain'),             
			'secure' => isset($_SERVER['HTTPS']),
			'httponly' => true
		);
		
		$this->cookie = $default_params;
		
		foreach($default_params as $var => $val)
			if(isset($cookie[$var])) $this->cookie[$var] = $cookie[$var];
		
		ini_set('session.use_cookies', 1);
        ini_set('session.use_only_cookies', 1);
		ini_set('session.save_handler', 'files');
		ini_set('session.gc_maxlifetime', $lifetime*60);          # Time after which the data will be seen as a junk | depends on probability
		ini_set('session.gc_probability', 1);              	  	  # Defines the probability that the gc (garbage collection) process is started on every session initialization
		ini_set('session.gc_divisor', 100);                       # The probability is calculated by using gc_probability/gc_divisor, e.g. 1/100 means there is a 1% chance that the GC process starts on each request. session.gc_divisor defaults to 100.
		                                                          
		
		ini_set('session.entropy_file', '/dev/urandom');          # better session entropy
		
		session_cache_limiter('nocache');
	
		session_name($name);

		if(!empty($path))
			session_save_path($_SERVER['DOCUMENT_ROOT'].$path);             
		
        session_set_cookie_params(
            $this->cookie['lifetime'], 
			$this->cookie['path'],
            $this->cookie['domain'], 
			$this->cookie['secure'],
            $this->cookie['httponly']
        );
	}
	
	public function start()
	{
		if(session_status() === 1)
		{
			if(!session_start()) return false;

			if(isset($_SESSION['fingerprint'])) 
			{
				if(!$this->isActive() || !$this->isFingerprintOk())
				{
					if(!$this->delete())
						return false; 
					
					return 'EXPIRED';
				}
			}
			else
			{
				$fingerprint = $_SERVER['HTTP_USER_AGENT'].$_SERVER['REMOTE_ADDR'];
				$_SESSION['fingerprint'] = hash('sha1', $fingerprint);
				$_SESSION['lastActivity'] = time();
				
				return 'LOGGED';
			}
			
			if(mt_rand(0,4) == 0) session_regenerate_id(true);            # 1 to 5 chance to regenerate_id()
			                                                              # if You have increased privileges, you can use it at each page
																	  
			$_SESSION['lastActivity'] = time();                 
			
			return 'CONTINUE';
		}
				
		return false;
	}
	
	public function delete()
	{
		if(session_status() === 1)
			return false;
		
		$_SESSION = [];
		
		setcookie(
			$this->name, 
			'', 
			time()-4200,
			$this->cookie['path'],
			$this->cookie['domain'],
			$this->cookie['secure'],
			$this->cookie['httponly']
		);
		
		return session_destroy();
	}
	
    public function open($savePath, $sessionName)
    {
        $this->savePath = $savePath;
        if (!is_dir($this->savePath)) {
            mkdir($this->savePath, 0700);
        }

        return true;
    }

    public function close()
    {
        return true;
    }

    public function read($id)
    {
		$data = (string)@file_get_contents("$this->savePath/sess_$id");
		
		if(!empty($data))
			$data = $this->decrypt($data);
		
        return $data;
    }

    public function write($id, $data)                                    # only suitable for encoded input that never ends with value 00h
	{                                                                    # (because of default zero padding)
		if(!empty($data))
			$data = $this->encrypt($data);

		
        return file_put_contents("$this->savePath/sess_$id", $data) === false ? false : true;
    }

    public function destroy($id)
    {
        $file = "$this->savePath/sess_$id";
        if (file_exists($file)) {
            unlink($file);
        }

        return true;
    }

    public function gc($maxlifetime)
    {
        foreach (glob("$this->savePath/sess_*") as $file) {
            if (filemtime($file) + $maxlifetime < time() && file_exists($file)) {
                unlink($file);
            }
        }

        return true;
    }
	
	// end core methods
	
	public function isActive()
	{		
		if(!isset($_SESSION['lastActivity']))
			return false;
		
		$lastActivity = $_SESSION['lastActivity'];
		
		if(time() - $lastActivity > $this->lifetime*60)
			return false;
		
		return true;
	}
	
	public function isFingerprintOk()
	{		
		if(!isset($_SESSION['fingerprint'])) 
			return false;
	
		$fingerprint = $_SERVER['HTTP_USER_AGENT'].$_SERVER['REMOTE_ADDR'];
		$fingerprint = hash('sha1', $fingerprint);                          # If You want You can use weaker = faster algorithm
		
		if($fingerprint != $_SESSION['fingerprint'] )
			return false;

		return true;
	}
	
	private function encrypt($data)
	{
			$ivSize = mcrypt_get_iv_size($this->algo, MCRYPT_MODE_CBC);
			$iv = mcrypt_create_iv($ivSize, MCRYPT_DEV_URANDOM);        							     # safer is MCRYPT_DEV_RANDOM but slower in many cases
			$data = $iv.mcrypt_encrypt($this->algo, $this->secretKey, $data, MCRYPT_MODE_CBC, $iv);
			
			$data = base64_encode($data);

			return $data;
	}
	
	private function decrypt($data)
	{
			$data = base64_decode($data);
			
            $ivSize = mcrypt_get_iv_size($this->algo, MCRYPT_MODE_CBC);

            $iv = substr($data, 0, $ivSize);
            $data = substr($data, $ivSize);
            $data = mcrypt_decrypt($this->algo, $this->secretKey, $data, MCRYPT_MODE_CBC, $iv);
             
			$data = rtrim($data, "\0");
			
			return $data;
	}
}
?>