<?php

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
                                    'delete_leftnavigation' => 'restApiDefaultCall',
                                    'getAll_leftnavigation' => 'restApiDefaultCall',
                                    'insert_leftnavigation' => 'restApiDefaultCall',
                                    'update_leftnavigation' => 'restApiDefaultCall',
                                    'fillGrid_leftnavigation' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_leftnavigation' => 'restApiDefaultCall',
                                    'getLeftMenu_leftnavigation' => 'restApiDefaultCall',
                                    'getLeftMenuFull_leftnavigation' => 'restApiDefaultCall',
        
        
        
       
        //**---- leftnavigation -------------------
        //** syssectors ----------------------
                                    'delete_syssectors' => 'restApiDefaultCall',
                                    'getAll_syssectors' => 'restApiDefaultCall',
                                    'insert_syssectors' => 'restApiDefaultCall',
                                    'update_syssectors' => 'restApiDefaultCall',
                                    'fillGrid_syssectors' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_syssectors' => 'restApiDefaultCall',
                                    
         //**---- syssectors -------------------
        
         //** infoUsers ----------------------
                                    'delete_infoUsers' => 'restApiDefaultCall',
                                    'getAll_infoUsers' => 'restApiDefaultCall',
                                    'insert_infoUsers' => 'restApiDefaultCall',
                                    'update_infoUsers' => 'restApiDefaultCall',
                                    'fillGrid_infoUsers' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_infoUsers' => 'restApiDefaultCall',
                                    
         //**---- infoUsers -------------------
                                        
         //** syscountrys ----------------------
                                    'delete_syscountrys' => 'restApiDefaultCall',
                                    'getAll_syscountrys' => 'restApiDefaultCall',
                                    'insert_syscountrys' => 'restApiDefaultCall',
                                    'update_syscountrys' => 'restApiDefaultCall',
                                    'fillGrid_syscountrys' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_syscountrys' => 'restApiDefaultCall',
                                    'fillComboBox_syscountrys' => 'restApiDefaultCall',
      //  'fillComboBox_syscountryssilinecek' => 'restApiDefaultCall',
                                    
         //**---- syscountrys -------------------
        
        //** syscity ----------------------
                                    'delete_syscity' => 'restApiDefaultCall',
                                    'getAll_syscity' => 'restApiDefaultCall',
                                    'insert_syscity' => 'restApiDefaultCall',
                                    'update_syscity' => 'restApiDefaultCall',
                                    'fillGrid_syscity' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_syscity' => 'restApiDefaultCall',
                                    'fillComboBox_syscity' => 'restApiDefaultCall',    
                                    
         //**---- syscity -------------------
         //** syslanguage ----------------------
                                    'delete_syslanguage' => 'restApiDefaultCall',
                                    'getAll_syslanguage' => 'restApiDefaultCall',
                                    'insert_syslanguage' => 'restApiDefaultCall',
                                    'update_syslanguage' => 'restApiDefaultCall',
                                    'fillGrid_syslanguage' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_syslanguage' => 'restApiDefaultCall',
                                    'fillComboBox_syslanguage' => 'restApiDefaultCall',    
                                    
         //**---- syslanguage -------------------
          //** sysborough ----------------------
                                    'delete_sysborough' => 'restApiDefaultCall',
                                    'getAll_sysborough' => 'restApiDefaultCall',
                                    'insert_sysborough' => 'restApiDefaultCall',
                                    'update_sysborough' => 'restApiDefaultCall',
                                    'fillGrid_sysborough' => 'restApiDefaultCall',
                                    'fillGridRowTotalCount_sysborough' => 'restApiDefaultCall',
                                    'fillComboBox_sysborough' => 'restApiDefaultCall',    
                                    
         //**---- sysborough -------------------       
        
        
        
        
        
        
    );

    /**
     * hmac object
     * @var \vendor\hmac\Hmac
     */
    protected $hmacObj;

    public function __construct() {
        parent::__construct();
        $this->hmacObj = new \vendor\hmac\Hmac();
    }

    public function redirect() {
        $execFunction = $this->resolveRedirectMap();
        $this->setEndPointByClosure();
        echo $this->$execFunction();
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
        $this->setEncryptClass();
        $params = null;
        $params = $this->getRequestParams();
        if(isset($params['pk'])) $this->hmacObj->setPublicKey($params['pk']);
        $this->hmacObj->setPrivateKey('e249c439ed7697df2a4b045d97d4b9b7e1854c3ff8dd668c779013653913572e');
        $this->hmacObj->setRequestParams($this->getRequestParamsWithoutPublicKey());
        $this->hmacObj->makeHmac();
        //print_r($this->hmacObj);

        $preparedParams = $this->prepareGetParams();
        //$preparedParams = $this->prepareGetParams('', array('pk'));
        if (($ch = @curl_init()) == false) {
            header("HTTP/1.1 500", true, 500);
            die("Cannot initialize CURL session. Is CURL enabled for your PHP installation?");
        }
        //print_r($this->restApiFullPathUrl.'?'.$preparedParams);
        //print_r($this->endPointUrl.$this->getEndPointFunction().'?'.$preparedParams);
        curl_setopt($ch, CURLOPT_URL, $this->restApiFullPathUrl . '?' . $preparedParams); //Url together with parameters
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); //Return data instead printing directly in Browser
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->getCallTimeOut()); //Timeout (Default 7 seconds)
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'X-Public: ' . $this->hmacObj->getPublicKey() . '',
            'X-Hash: ' . $this->hmacObj->getHash() . '',
            'X-Nonce:' . $this->hmacObj->getNonce(),
            //'X-IP:'.serialize($_SERVER),
            'X-TimeStamp:' . $this->hmacObj->setTimeStamp($this->encryptClass
                            ->encrypt('' . time() . ''))  /// replay attack lar için oki
        ));
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
