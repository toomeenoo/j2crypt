<?php
/**
 * j2crypt-php.php
 * 
 * @description J2crypt Library - 2Way 2D+ data crypting
 * @link https://github.com/toomeenoo/j2crypt
 * @version 1.3
 * @author Tomáš Molinari @toomeenoo <tomie.molinari@gmail.com>
 * @license MIT
 */
class J2crypt
{
	private $map;
	private $mapSize;
	private $dataSize;
	private $password;
	private $passwordSize;
	private $data;
	private $precomputed = false;
	private $precomp_bin7;
	
	public function __construct(){
		// For old php versions: 
		if(!function_exists("random_int")){
			function random_int($from, $to){
				return rand ( $from, $to );
			}
		}
		return $this;
	}
	
	/**
	 * Writes crypted output to file
	 * @param string $filename filesystem path and filename to be saved 
	 * @return J2crypt self object
	 */
  public function toFile($filename) {
		file_put_contents($filename, "");
		$output_real = $this->getCrypted("raw");
		$fil = fopen($filename,"w+");
		fwrite($fil, $output_real);
		return $this;
  }
	
	/**
	 * Downloads crypted output
	 * @param string $filename = "crypted.j2cd" filename to output
	 * @param boolean $die = false exit script on output
	 * @return J2crypt self object
	 */
	public function directDownload($filename = "crypted.j2cd", $die = false) {
		header('Content-Type: application/j2crypt-data');
		header('Content-Disposition: attachment; filename="'.$filename.'"');
		if($die){
			die($this->getCrypted("raw"));
		}else{
			echo $this->getCrypted("raw");
		}
		return $this;
  }
	
	/**
	 * Locks provided data
	 * set new data to precomputed
	 * set new data to precomputed_bin7
	 * 
	 * @param int|NULL $datalen = NULL length of data to be locked
	 * @return int[] crypted output
	 */
	private function lock($datalen = NULL){
		$this->lockmap = "";
		$data = $this->data;
		$magicUnknown = rand(0, 127);
		$width = $this->dataSize[0];
		$height = ord(substr($data,-1));
		$datalen = is_null($datalen) ? strlen($data) : $datalen;	
		$output = array($width, $height, $magicUnknown);
		$bin7 = sprintf("%'.07b%'.07b%'.07b", $width, $height%128, $magicUnknown);
        $i = 0;
		$r = 0;
		$c = 0;
		while($i < $datalen /* && $r < $height*/){
			$c = 0;
			while($i < $datalen && $c < $width){
				$mc = $c % $this->mapSize[0];//Map rows
				$mr = $r % $this->mapSize[1];//Map colums
				$mv = $this->map[$mc+$mr*$this->mapSize[0]];//Map value
				$ps = ord($this->password[($i+$magicUnknown)%$this->passwordSize]);//Password number
				$f = (ord($data[$i])+ord($mv)+$ps)%128; //final number
				$output[] = $f;
				$bin7 .= sprintf("%'.07b",$f);
				$c++;
				$i++;
			}
			$r ++;
		}
		$this->precomp_bin7 = $bin7;
		$this->precomputed = $output;
		return $output;
	}
	
	/**
	 * Getter for locked data
	 * @return int[] locked data
	 */
	private function locked(){
		return ($this->precomputed ? $this->precomputed : $this->lock());
	}

	/**
	 * Getter for locked and packed data
	 * Output format: binary(7bit) joined and packed to string
	 * @return string packed locked data
	 */
	private function getRaw(){
		$out = $this->locked();
		$output_real = $this->precomp_bin7;
		$remaining = strlen($output_real);
		$output_real .= "00000000";
		$output_raw = '' ;
		$i = 0;
		$ch8 = "";
		while($i < $remaining || strlen($ch8)){
			$ch8 .= $output_real[$i];
			if(strlen($ch8)==8){
				$output_raw .= pack("C",base_convert($ch8, 2, 10));
				$ch8 = "";
			}
			$i++;
		}
		return $output_raw;
	}

	/**
	 * Getter for locked and packed data
	 * Output format: binary(7bit) join to binary(8bit) to int
	 * @return int[] locked data
	 */
	private function getPacked(){
		$output_real = "";
		$out = $this->locked();
		foreach($out as $val){
			$output_real .= sprintf("%'.07b", $val);
		}
		$remaining = strlen($output_real);
		$output_real .= "00000000";
		$output_raw = array();
		$i = 0;
		$ch8 = "";
		while($i < $remaining || strlen($ch8)){
			$ch8 .= $output_real[$i];
			if(strlen($ch8)==8){
				$output_raw[] = base_convert($ch8, 2, 10);
				$ch8 = "";
			}
			$i++;
		}		
		return $output_raw;
	}
	
	/**
	 * Opens file and unlock contents
	 * @return string Unlocked data
	 */
	public function unlockFile($filename){
		$content = file_get_contents($filename);
		return $this->unlock($content);
	}

	/**
	 * Get locked data in different formats: <br>
	 * - 'raw' (default) = binary(7bit) joined and packed to string <br>
	 * - 'base64' = raw packed to base64 <br>
	 * - 'bin7' = string of binary(7bit) <br>
	 * - 'dec7' = string of numbers 0-127 delimited with spaces <br>
	 * - 'dec8' = string of numbers 0-255 delimited with spaces<br>
	 * 
	 * @param string $format
	 * @return string requested ouptut
	 */
	public function getCrypted($format = "raw"){
		$out = $this->locked();
		if($format == "raw" || $format == "base64"){
			$output_real = $this->getRaw();
			if($format == "base64"){
				$output_real = base64_encode($output_real);
			}
		}elseif($format == "bin7"){
			$output_real = "";
			foreach($out as $val){
				$output_real .= sprintf("%'.07b ", $val);
			}
		}elseif($format == "dec7"){
			$output_real = implode(" ",$out);
		}elseif($format == "dec8"){
			$output_real = implode(" ",$this->getPacked());
		}
		return $output_real;
	}
	
	/**
	 * Setter for data to be locked
	 * @param string $data input data
	 * @return \J2crypt this object
	 */
	public function setData($data) {
    $this->data = $data;
		$this->dataSize = $this->rectFrom(strlen($data));
		$this->precomputed = false;
		return $this;
  }

	/**
	 * Unlocks data wich are passed in argumetn
	 * @param string $content Input locked data
	 * @return string Unlocked, output data
	 */
	public function unlock($content){
		$i = 0;
		$len = strlen($content);
		$data = array();
		$binString = "";
		while($i < $len){
			$binString .= sprintf("%'.08b", ord($content[$i]));
			while(strlen($binString) >= 7){
				$data[] = base_convert(substr($binString, 0, 7), 2, 10);
				$binString = substr($binString, 7);
			}
			$i++;
		}
		$i = 0;
		$r = 0;
		$c = 0;
		$width = $data[0];
		$lastchar = $data[1];
		$magicUnknown = $data[2];
		$output = "";
		$datalen = count($data);
		while($i+3 < $datalen){
			$c = 0;
			while($i+3 < $datalen && $c < $width){
				$mc = $c % $this->mapSize[0];
				$mr = $r % $this->mapSize[1];
				$mv = $this->map[$mc+$mr*$this->mapSize[0]];
				$pk = ord($this->password[($i+$magicUnknown)%$this->passwordSize]);
				$f = (ord($mv)+$pk)%128;
				$max = 128;
				while(ord($mv)+$pk > $max){
					$max += 128;
				}
				$output .= chr((($max-(ord($mv)+$pk))+$data[$i+3])%128);
				$c++;
				$i++;
			}
			$r ++;
		}
		while($lastchar != ord(substr($output, -1)) && strlen($output)){
			$output = substr($output, 0, -1);
		}
		return $output;
	}

	/**
	 * Sets password to be used in this object
	 * @param string $pwd Password
	 * @return \J2crypt this object
	 */
	public function setPwd($pwd) {
		$this->password = $pwd;
		$this->passwordSize = strlen($pwd);
		$this->precomputed = false;
		return $this;
	}

	/**
	 * Set binary string and size as used map
	 * @param string $map_data Binary string of map values
	 * @param int $sizeX width of map (up to 127)
	 * @param int $sizeY height of map (unlimited)
	 * @return \J2crypt this object
	 */
	private function setMap($map_data, $sizeX, $sizeY) {
		$this->map = $map_data;
		$this->mapSize = array($sizeX, $sizeY);
		$this->precomputed = false;
		return $this;
	}
	
	/**
	 * Set json map as used map
	 * @param string $json_text Json map
	 * @return \J2crypt this object
	 */
	public function setMapJson($json_text) {
		$obj = json_decode ($json_text, true);
		$len = strlen($obj["dataHex"]);
		$raw_map_data = '';
		$i = 0;
		while($i < $len){
			$raw_map_data .= pack("C", intval(substr($obj["dataHex"],$i, 2),16));
			$i += 2;
		}
		return $this->setMap($raw_map_data, intval($obj["width"]), intval($obj["height"]));
	}
	

	/**
	 * Function to create "natural rectangle" from given square size
	 * @param int $int data size
	 * @param int $aLimit limit of width (still 127)
	 * @return array [width, height, totalSize]
	 */
	private function rectFrom($int, $aLimit = 127){
		$dataLen = $int;
		$b = $dataLen;
		$a = 1;
		$nums = array(2,3,5,7,11,13);
		$i = 0;
		while($i<6){
			$n = $nums[$i];
			while(!($b%$n) && (($a*$n)+($b/$n))<($a+$b) && ($a*$n)<$aLimit){
				$a *= $n;
				$b /= $n;
			}
			$i++;
		}
		if((($a*$n)<$aLimit) && $a < $b/3){
			return $this->rectFrom($int+1);
		}
		return array($a, $b,  $int);
	}
	
	/**
	 * Strictly generate new map from password
	 * @todo EXPERIMENTAL, not implemented on javascript side 
	 * @param int $width Map's width
	 * @param int $height Map's height
	 * @return \J2crypt this object
	 */
	private function generateMap($width = 6, $height = 6){
		$this->mapSize = array($width, $height);
		$this->map = sha1($this->password, true).md5($this->password, true);
		$this->precomputed = false;
		return $this;
	}

	/**
	 * Get current map in json format to be sent or stored
	 * @return string Json map
	 */
	public function getMap(){
		$ret = '{"width":'.$this->mapSize[0].',"height":'.$this->mapSize[1].',"dataHex":"';
		$i = 0;
		while($i<$this->mapSize[0]){
			$j = 0;
			while($j<$this->mapSize[1]){
				$ret .= sprintf("%'.02x", ord($this->map[$i*$this->mapSize[1] + $j]));
				$j++;
			}
			$i++;
		}
		return $ret.'"}';
	}

	/**
	 * Randomly generate new key map of given size
	 * @param int $x width (bigger than 127 is useless)
	 * @param int $y height (any size should be used)
	 * @return \J2crypt this object
	 */
	public function customMap($x, $y){
		$md = '';
		$i = 0;
		while($i < $y){
			$j = 0;
			while($j < $x){
				$md .= pack("C", random_int(0, 255));
				$j ++;
			}
			$i++;
		}
		return $this->setMap($md, $x, $y);
	}
	
}
?>