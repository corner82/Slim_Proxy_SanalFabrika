<?php
/**
 * OSTİM TEKNOLOJİ Framework 
 *
 * @link      https://github.com/corner82/slim_test for the canonical source repository
 * @copyright Copyright (c) 2015 OSTİM TEKNOLOJİ (http://www.ostim.com.tr)
 * @license   
 */


namespace vendor\Slim;

class SlimHmacProxy extends \vendor\Proxy\Proxy {

    /**
     * a mapping array for related functions and proxy calls
     * to be executed
     * @var array()
     */
    protected $redirectMap = array('getReports_test' => 'restApiDefaultCall',
                                    'getDynamicForm_test' => 'restApiDefaultCall',

        //** leftnavigation ----------------------
                                    'pkDelete_leftnavigation' => 'restApiDefaultCall',
                                    'pkGetAll_leftnavigation' => 'restApiDefaultCall',
                                    'pkInsert_leftnavigation' => 'restApiDefaultCall',
                                    'pkUpdate_leftnavigation' => 'restApiDefaultCall',
                                    'pkFillGrid_leftnavigation' => 'restApiDefaultCall',
                                    'pkFillGridRowTotalCount_leftnavigation' => 'restApiDefaultCall',
                                    'pkGetLeftMenu_leftnavigation' => 'restApiDefaultCall',
      
       
        //**---- leftnavigation -------------------
        //** syssectors ----------------------
                                    'pkDelete_syssectors' => 'restApiDefaultCall',
                                    'pkGetAll_syssectors' => 'restApiDefaultCall',
                                    'pkInsert_syssectors' => 'restApiDefaultCall',
                                    'pkUpdate_syssectors' => 'restApiDefaultCall',
                                    'pkFillGrid_syssectors' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_syssectors' => 'restApiDefaultCall',                                    
                                    'fillComboBox_syssectors' => 'restApiDefaultCall',
                                    'pkInsertLanguageTemplate' => 'restApiDefaultCall',
                                    'pkFillTextLanguageTemplate' => 'restApiDefaultCall',
        
           
         //**---- syssectors -------------------
        
         //** infoUsers ----------------------
                                    'pkDelete_infoUsers' => 'restApiDefaultCall',
                                    'pkGetAll_infoUsers' => 'restApiDefaultCall',
                                    'pkInsert_infoUsers' => 'restApiDefaultCall',
                                    'pkUpdate_infoUsers' => 'restApiDefaultCall',
                                    'pkFillGrid_infoUsers' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_infoUsers' => 'restApiDefaultCall',
                                    'pkDeletedAct_infoUsers' => 'restApiDefaultCall',
                            
                                    
         //**---- infoUsers -------------------
                                        
         //** syscountrys ----------------------
                                    'pkDelete_syscountrys' => 'restApiDefaultCall',
                                    'pkGetAll_syscountrys' => 'restApiDefaultCall',
                                    'pkInsert_syscountrys' => 'restApiDefaultCall',
                                    'pkUpdate_syscountrys' => 'restApiDefaultCall',
                                    'pkFillGrid_syscountrys' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_syscountrys' => 'restApiDefaultCall',
                                    'fillComboBox_syscountrys' => 'restApiDefaultCall',
                                    'pkInsertLanguageTemplate_syscountrys' => 'restApiDefaultCall',
        
     
                                    
         //**---- syscountrys -------------------
        
        //** syscity ----------------------
                                    'pkDelete_syscity' => 'restApiDefaultCall',
                                    'pkGetAll_syscity' => 'restApiDefaultCall',
                                    'pkInsert_syscity' => 'restApiDefaultCall',
                                    'pkUpdate_syscity' => 'restApiDefaultCall',
                                    'pkFillGrid_syscity' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_syscity' => 'restApiDefaultCall',
                                    'fillComboBox_syscity' => 'restApiDefaultCall',   
                                    'pkInsertLanguageTemplate_syscity' => 'restApiDefaultCall',  
        
        
                                    
         //**---- syscity -------------------
         //** syslanguage ----------------------
                                    'pkDelete_syslanguage' => 'restApiDefaultCall',
                                    'pkGetAll_syslanguage' => 'restApiDefaultCall',
                                    'pkInsert_syslanguage' => 'restApiDefaultCall',
                                    'pkUpdate_syslanguage' => 'restApiDefaultCall',
                                    'pkFillGrid_syslanguage' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_syslanguage' => 'restApiDefaultCall',
                                    'fillComboBox_syslanguage' => 'restApiDefaultCall',    
                                    
         //**---- syslanguage -------------------
          //** sysborough ----------------------
                                    'pkDelete_sysborough' => 'restApiDefaultCall',
                                    'pkGetAll_sysborough' => 'restApiDefaultCall',
                                    'pkInsert_sysborough' => 'restApiDefaultCall',
                                    'pkUpdate_sysborough' => 'restApiDefaultCall',
                                    'pkFillGrid_sysborough' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_sysborough' => 'restApiDefaultCall',
                                    'fillComboBox_sysborough' => 'restApiDefaultCall',  
                                    'pkInsertLanguageTemplate_sysborough' => 'restApiDefaultCall',  
         //**---- sysborough -------------------       
        
           //** sysvillage ----------------------
                                    'pkDelete_sysvillage' => 'restApiDefaultCall',
                                    'pkGetAll_sysvillage' => 'restApiDefaultCall',
                                    'pkInsert_sysvillage' => 'restApiDefaultCall',
                                    'pkUpdate_sysvillage' => 'restApiDefaultCall',
                                    'pkFillGrid_sysvillage' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_sysvillage' => 'restApiDefaultCall',
                                    'fillComboBox_sysvillage' => 'restApiDefaultCall',  
                                    'pkInsertLanguageTemplate_sysvillage' => 'restApiDefaultCall',   
                        
         //**---- sysvillage -------------------   
        
         //** blLoginLogout ----------------------
                                    'pkDelete_blLoginLogout' => 'restApiDefaultCall',
                                    'pkGetAll_blLoginLogout' => 'restApiDefaultCall',
                                    'pkInsert_blLoginLogout' => 'restApiDefaultCall',
                                    'pkUpdate_blLoginLogout' => 'restApiDefaultCall',
                                    'pkControl_blLoginLogout' => 'restApiDefaultCall',
                                    'pkLoginControl_blLoginLogout' => 'restApiDefaultCall',
                                    'pkGetPK_blLoginLogout' => 'restApiDefaultCall',  
                                    'pkSessionControl_blLoginLogout' => 'restApiDefaultCall',   
                                    'pkIsThere_blLoginLogout' => 'restApiDefaultCall',   
                                    'pkAllPkGeneratedFromPrivate_blLoginLogout' => 'restApiDefaultCall',  
                        
        
         //**---- blLoginLogout -------------------   
         //** infoFirmProfile ----------------------
                                    'pkDelete_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkGetAll_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkInsert_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkUpdate_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkFillGrid_infoFirmProfile' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkDeletedAct_infoFirmProfile' => 'restApiDefaultCall',
                                    'fillComboBox_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkInsertLanguageTemplate_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkFillTextLanguageTemplate_infoFirmProfile' => 'restApiDefaultCall',
                            
                                    
         //**---- infoFirmProfile -------------------
         //** sysAclRoles ----------------------
                                    'pkDelete_sysAclRoles' => 'restApiDefaultCall',
                                    'pkGetAll_sysAclRoles' => 'restApiDefaultCall',
                                    'pkInsert_sysAclRoles' => 'restApiDefaultCall',
                                    'pkUpdate_sysAclRoles' => 'restApiDefaultCall',
                                    'pkUpdateChild_sysAclRoles' => 'restApiDefaultCall',
                                    'pkFillGrid_sysAclRoles' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_sysAclRoles' => 'restApiDefaultCall',
                                    'pkFillComboBoxMainRoles_sysAclRoles' => 'restApiDefaultCall',   
                                    'pkFillComboBoxFullRoles_sysAclRoles' => 'restApiDefaultCall',  
        
         //**---- sysAclRoles -------------------  
         //** sysAclResources ----------------------
                                    'pkDelete_sysAclResources' => 'restApiDefaultCall',
                                    'pkGetAll_sysAclResources' => 'restApiDefaultCall',
                                    'pkInsert_sysAclResources' => 'restApiDefaultCall',
                                    'pkUpdate_sysAclResources' => 'restApiDefaultCall',
                                    'pkFillGrid_sysAclResources' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_sysAclResources' => 'restApiDefaultCall',
                                    'pkFillComboBoxMainResources_sysAclResources' => 'restApiDefaultCall',   
                                    'pkFillComboBoxFullResources_sysAclResources' => 'restApiDefaultCall',  
     
         //**---- sysAclResources -------------------  
       //** sysAclPrivilege ----------------------
                                    'pkDelete_sysAclPrivilege' => 'restApiDefaultCall',
                                    'pkGetAll_sysAclPrivilege' => 'restApiDefaultCall',
                                    'pkInsert_sysAclPrivilege' => 'restApiDefaultCall',
                                    'pkUpdate_sysAclPrivilege' => 'restApiDefaultCall',
                                    'pkFillGrid_sysAclPrivilege' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_sysAclPrivilege' => 'restApiDefaultCall',                                  
                                    'pkFillComboBoxFullPrivilege_sysAclPrivilege' => 'restApiDefaultCall',  
     
         //**---- sysAclPrivilege ------------------- 
            //** SysAclRrpMap ----------------------
                                    'pkDelete_sysAclRrpMap' => 'restApiDefaultCall',
                                    'pkGetAll_sysAclRrpMap' => 'restApiDefaultCall',
                                    'pkInsert_sysAclRrpMap' => 'restApiDefaultCall',
                                    'pkUpdate_sysAclRrpMap' => 'restApiDefaultCall',
                                    'pkFillGrid_sysAclRrpMap' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_sysAclRrpMap' => 'restApiDefaultCall',                                  
                                    'pkFillRrpMap_sysAclRrpMap' => 'restApiDefaultCall',  
     
         //**---- SysAclRrpMap -------------------    
        
        
    );

    /**
     * hmac object
     * @var \vendor\hmac\Hmac
     */
    protected $hmacObj;
    
    /**
     * Dal object
     * @var \vendor\dal\Dal
     */
    protected $dalObject;

    public function __construct() {
        parent::__construct();
        $this->hmacObj = new \vendor\hmac\Hmac();
        $this->dalObject = new \vendor\dal\Dal();
    }

    public function redirect() {
        try {
            $execFunction = $this->resolveRedirectMap();
            $this->setEndPointByClosure();
            echo $this->$execFunction();
        } catch (\Exception $exc) {
            echo $exc->getTraceAsString();
        }
    }
    
     /**
      * 
      * @return boolean
      * @author Mustafa Zeynel Dağlı
      * @since version 0.3
      */
     public function servicePkRequired() {
         if($this->isServicePkRequired == null) {
             $params = $this->getRequestParams();
             if(substr(trim($params['url']),0,2) == 'pk') {
                $this->isServicePkRequired = true;
                return $this->isServicePkRequired ;
             }
             $this->isServicePkRequired = false;
             $this->isServicePkRequired;
         } else {
             return $this->isServicePkRequired;
         }
     }
     
     /**
     * public key not found process is being evaluated here
     * @author Mustafa Zeynel Dağlı
     * @since version 0.3
     */
    public function publicKeyNotFoundRedirect() {
        if($this->isServicePkRequired && $this->isPublicKeyNotFoundRedirect) {
             $forwarder = new \vendor\utill\forwarder\PublicNotFoundForwarder();
             $forwarder->redirect();  
         } else {
             return true;
         }
    }
    
    /**
     * private key not found process is being evaluated here
     * @author Mustafa Zeynel Dağlı
     * @since version 0.3
     */
    public function privateKeyNotFoundRedirect() {
        if($this->isServicePkRequired && $this->isPrivateKeyNotFoundRedirect) {
            $forwarder = new \vendor\utill\forwarder\PrivateNotFoundForwarder();
            $forwarder->redirect();
        } else {
            return true;
        }
    }
    
    /**
     * user not registered process is being evaluated here
     * inherit classes
     * @author Mustafa Zeynel Dağlı
     * @since version 0.3
     */
    public function userNotRegisteredRedirect() {
        if($this->isServicePkRequired && $this->isUserNotRegisteredRedirect) {
            $forwarder = new \vendor\utill\forwarder\UserNotRegisteredForwarder();
            $forwarder->redirect();
        } else {
            return true;
        }
    }

    /**
     * Rest api 'GET' call (Curl lib)
     * function overriden
     * @author Mustafa Zeynel Dağlı
     * @version 0.2
     * @todo conside check if request is ssl encypted (https)
     */
    public function restApiDefaultCall() {

        /* $encrypt = new \vendor\Encrypt\EncryptManual('test');
          $encryptValue = $encrypt->encrypt_times(4, 'kullanici:sifre');
          //print_r('--'.$encryptValue.'--');
          $decryptValue = $encrypt->decrypt_times(4, $encryptValue);
          //print_r('??'.$decryptValue.'??'); */
        $this->servicePkRequired();
        $this->setEncryptClass();
        $params = null;
        $params = $this->getRequestParams();
        
        /**
         * controlling public key if public key is necessary for this service and
         * public key not found forwarder is in effect then making forward
         * @since version 0.3 06/01/2016
         */
        if(!isset($params['pk']) || $params['pk']==null) $this->publicKeyNotFoundRedirect();
        
        /**
         * getting public key if user registered    
         * @author Mustafa Zeynel Dağlı
         * @since 06/01/2016 version 0.3
         */
        if(isset($params['pk']) &&  $this->isServicePkRequired) {
            $resultSet = $this->dalObject->pkIsThere(array('pk' => $params['pk']));
            if(!isset($resultSet['resultSet'][0]['?column?'])) $this->userNotRegisteredRedirect ();
        }
        
        
        /**
         * getting private key due to public key
         * @author Mustafa Zeynel Dağlı
         * @since 05/01/2016 version 0.3
         */
        if(isset($params['pk']) && $this->isServicePkRequired) $resultSet = $this->dalObject->getPrivateKey($params['pk']);
        
        /**
         * if not get private key due to public key
         * forward to private not found
         * @author Mustafa Zeynel Dağlı
         * @since 06/01/2016 version 0.3
         */
        if(empty($resultSet['resultSet'])) $this->privateKeyNotFoundRedirect();
        
        /**
         * if service has to be secure then prepare hash
         * @author Mustafa Zeynel Dağlı
         * @since version 0.3 06/01/2016
         */
        if($this->isServicePkRequired) {
            if(isset($params['pk'])) $this->hmacObj->setPublicKey($params['pk']);
            //$this->hmacObj->setPrivateKey('e249c439ed7697df2a4b045d97d4b9b7e1854c3ff8dd668c779013653913572e');
            $this->hmacObj->setPrivateKey($resultSet['resultSet'][0]['sf_private_key_value']);
            $this->hmacObj->setRequestParams($this->getRequestParamsWithoutPublicKey());
            $this->hmacObj->makeHmac();
            //print_r($this->hmacObj);
        }
        

        $preparedParams = $this->prepareGetParams();
        //$preparedParams = $this->prepareGetParams('', array('pk'));
        if (($ch = @curl_init()) == false) {
            header("HTTP/1.1 500", true, 500);
            die("Cannot initialize CURL session. Is CURL enabled for your PHP installation?");
        }
        //print_r($this->restApiFullPathUrl.'?'.$preparedParams);
        curl_setopt($ch, CURLOPT_URL, $this->restApiFullPathUrl . '?' . $preparedParams); //Url together with parameters
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); //Return data instead printing directly in Browser
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->getCallTimeOut()); //Timeout (Default 7 seconds)
        /**
         * if service has to be secure then prepare header for security
         * parameters
         * @author Mustafa Zeynel Dağlı
         * @since version 0.3 06/01/2016
         */
        if($this->isServicePkRequired) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, array(
                'X-Public: ' . $this->hmacObj->getPublicKey() . '',
                'X-Hash: ' . $this->hmacObj->getHash() . '',
                'X-Nonce:' . $this->hmacObj->getNonce(),
                //'X-IP:'.serialize($_SERVER),
                'X-TimeStamp:' . $this->hmacObj->setTimeStamp($this->encryptClass
                                ->encrypt('' . time() . ''))  /// replay attack lar için oki
            ));
        }
        
        /**
         * if request is ssl encrypted consider header options below
         * @author Mustafa Zeynel Dağlı
         * @since 23/12/2015
         */
        /*curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);*/
        curl_setopt($ch, CURLOPT_HEADER, 0); // we don’t want also to get the header information that we receive.
        //sleep(10);
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($response == false) {
            die("curl_exec() failed. Error: " . curl_error($ch));
        }

        return $response;
    }

    public function setEndPointByClosure(Array $EndPointClosure = null) {
        $endPointFunction = $this->getRestApiEndPointFunction();
        if (substr($endPointFunction, -5) == '_test') {
            //$this->setEndPointUrl("http://localhost/slim2_test/index.php/");
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -15) == '_leftnavigation') {
            $this->setRestApiEndPoint('leftnavigation.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -11) == '_syssectors') {
            $this->setRestApiEndPoint('syssectors.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -10) == '_infoUsers') {
            $this->setRestApiEndPoint('infousers.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -12) == '_syscountrys') {
            $this->setRestApiEndPoint('syscountrys.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }
      /*  else if (substr($endPointFunction, -21) == '_syscountryssilinecek') {
            $this->setRestApiEndPoint('syscountryssilinecek.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }        
       */
          else if (substr($endPointFunction, -8) == '_syscity') {
            $this->setRestApiEndPoint('syscity.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -12) == '_syslanguage') {
            $this->setRestApiEndPoint('syslanguage.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -11) == '_sysborough') {
            $this->setRestApiEndPoint('sysborough.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -11) == '_sysvillage') {
            $this->setRestApiEndPoint('sysvillage.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }
        else if (substr($endPointFunction, -14) == '_blLoginLogout') {
            $this->setRestApiEndPoint('blLoginLogout.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -16) == '_infoFirmProfile') {
            $this->setRestApiEndPoint('infoFirmProfile.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -12) == '_sysAclRoles') {
            $this->setRestApiEndPoint('sysaclroles.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -16) == '_sysAclResources') {
            $this->setRestApiEndPoint('sysaclresources.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -16) == '_sysAclPrivilege') {
            $this->setRestApiEndPoint('sysaclprivilege.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -13) == '_sysAclRrpMap') {
            $this->setRestApiEndPoint('sysAclRrpMap.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }
        
        
       
    }

   
    
    /**
     * set Hmac object for HMAC security
     * @param \vendor\hmac\Hmac $hmacObj
     * @version 0.2
     * @author Mustafa Zeynel Dağlı
     */
    public function setHmacObj(\vendor\hmac\Hmac $hmacObj) {
        $this->hmacObj = $hmacObj;
    }

    /**
     * get Hmac object for HMAC security
     * @return \vendor\hmac\Hmac $hmacObj
     * @version 0.2
     * @author Mustafa Zeynel Dağlı
     */
    public function getHmacObj() {
        return $this->hmacObj;
    }

}
