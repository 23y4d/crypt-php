<?php

/*
 * @ package   securtiy/crypto
 * @ author    Zeyad Besiso <zeyad.besiso@gmail.com>
 * @link       https://github.com/23y4d/crypto-php
 */


namespace securtiy\crypto;

use Exception;

class crypto{


        const secretKey = "WkVZQURzSEFEMFdC"; // Cryptographic key of length 16, 24 or 32
        //  secretKey (16 chars)


         private function encodeB64($string){
        $data = base64_encode($string);
        $data = str_replace(array('+', '/', '='), array('!', '!!', ''), $data);
         if ($data) return  $data;
        }


        private function decodeB64($string){

                $data = str_replace(array('!', '!!'), array('+', '/'), $string);
                $mod4 = strlen($data) % 4;
        if ($mod4) $data .= substr('====',$mod4);
            return base64_decode($data);

        }

        public function setKey($key){
         return $key = self::secretKey;
         }



        public function enCrypt($text){

          if (!$text) throw new Exception('Missing initialization text');
              $code = $text;
                $size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256,MCRYPT_MODE_ECB);
                $iv = mcrypt_create_iv($size,MCRYPT_RAND);
                $encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_256,self::secretKey,$code,MCRYPT_MODE_ECB,$iv);
          return trim($this->encodeB64($encrypted));
        }



          public function deCrypt($text){
             if (!$text) throw new Exception('Missing initialization text');
             $ctext = $this->decodeB64($text);
              $size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
              $iv = mcrypt_create_iv($size,MCRYPT_RAND);
              $decrypted = trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256,self::secretKey,$ctext,MCRYPT_MODE_ECB,$iv));
            return $decrypted;
        }


           private function genSalt($w){
                $opSsl = openssl_random_pseudo_bytes(16);
                $salt  = '$1';
                $salt .= str_pad($w,2,'0',STR_PAD_LEFT);
                $salt .= '$';
                $salt .= strtr(base64_encode($opSsl), '+', '.');
            return $salt;
        }


          public function has($name){
                $salt = self::genSalt(25);
                $name = crypt($name,$salt);
            return $name;
        }


 }
