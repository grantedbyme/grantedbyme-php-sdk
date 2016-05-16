<?php
/**
 * Curl networking helper
 *
 * PHP version 5
 *
 * @category SDK
 * @package  GBM
 * @author   GrantedByMe <info@grantedby.me>
 * @access   private
 * @license  https://grantedby.me/licenses/php/license.md MIT
 * @version  Release: <release_id>
 * @link     https://grantedby.me
 */
namespace GBM {

    /**
     * Curl networking helper
     *
     * @category SDK
     * @package  GBM
     * @author   GrantedByMe <info@grantedby.me>
     * @access   private
     * @license  https://grantedby.me/licenses/php/license.md MIT
     * @version  Release: <release_id>
     * @link     https://grantedby.me
     */
    class CurlRequest
    {
        /**
         * @param $url
         *
         * @return mixed
         */
        public static function get($url)
        {
            return self::request($url);
        }

        /**
         * @param $url
         * @param $params
         *
         * @return mixed
         */
        public static function post($url, $params)
        {
            return self::request($url, $params);
        }

        /**
         * @param $url
         * @param null $params
         *
         * @return mixed
         */
        private static function request($url, $params = null)
        {
            if (!function_exists('curl_init')) {
                die('cURL is not installed!');
            }
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            //curl_setopt($ch, CURLOPT_REFERER, "http://www.grantedby.me/test");
            $ua = 'GrantedByMe/' . ApiSettings::$VERSION . '-' . ApiSettings::$BRANCH . ' (PHP)';
            curl_setopt($ch, CURLOPT_USERAGENT, $ua);
            curl_setopt($ch, CURLOPT_HEADER, 0);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
            if (substr($url, 0, strlen('https')) === 'https') {
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            } else {
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            }
            curl_setopt($ch, CURLOPT_ENCODING, 'UTF-8');
            if ($params != null) {
                $jsonParams = $params;
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
                curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonParams);
                $headers = array('Content-Type: application/json', 'Content-Length: ' . strlen($jsonParams));
                curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            }
            $output = curl_exec($ch);
            curl_close($ch);
            return $output;
        }
    }
}
