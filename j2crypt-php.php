<?php
/*
*
* j2crypt-php.php
* 
* @description J2crypt Library - 2Way 2D+ data crypting
* @version 1.3
* @author Tomáš Molinari @toomeenoo <tomie.molinari@gmail.com>
* @license MIT
*
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
	public $duration = 0;	
	
	public function __construct(){
		return $this;
	}

    public function toFile($filename) {
		file_put_contents($filename, "");
		$output_real = $this->geTcrypted("raw");
		$fil = fopen($filename,"w+");
		fwrite($fil, $output_real);
    }
	
	public function directDownload($filename = "crypted.tcd", $die = false) {
		header('Content-Type: application/j2crypt-data');
		header('Content-Disposition: attachment; filename="'.$filename.'"');
		if($die){
			die($this->getCrypted("raw"));
		}else{
			echo $this->getCrypted("raw");
		}
    }
	
	private function lock($datalen = NULL){
		$this->lockmap = "";
		$data = $this->data;
		$magicUnknown = rand(0, 127);
		$width = $this->dataSize[0];
		$height = $this->dataSize[1];
		$datalen = is_null($datalen) ? strlen($data) : $datalen;	
		$output = array($width, $height, $magicUnknown);
		$bin7 = sprintf("%'.07b%'.07b%'.07b", $width, $height%128, $magicUnknown);
        $i = 0;
		$r = 0;
		$c = 0;
		while($i < $datalen && $r < $height){
			$c = 0;
			while($i < $datalen && $c < $width){
				$mc = $c % $this->mapSize[0];
				$mr = $r % $this->mapSize[1];
				$mv = $this->map[$mc+$mr*$this->mapSize[0]];
				$ps = ord($this->password[($i+$magicUnknown)%$this->passwordSize]);
				$f = (ord($data[$i])+ord($mv)+$ps)%128;
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
	
	private function locked(){
		return ($this->precomputed ? $this->precomputed : $this->lock());
	}

	private function getRaw(){
		$start = microtime();
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
		$this->duration = microtime() - $start;
		return $output_raw;
	}
	private function getPacked(){
		$output_real = "";
		$out = $this->locked();
		foreach($out as $val){
			$output_real .= sprintf("%'.07b", $val);
		}
		$remaining = strlen($output_real);
		$output_real .= "00000000";
		$output_raw = [];
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
	
	public function unlockFile($filename){
		$content = file_get_contents($filename);
		return $this->unlock($content);
	}

	public function getCrypted($format){
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
	
	public function setData($data) {
        $this->data = $data;
		$this->dataSize = $this->rectFrom(strlen($data));
		$this->precomputed = false;
		return $this;
    }
	
	public function unlock($content){
		$i = 0;
		$len = strlen($content);
		$data = [];
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
		$height = $data[1];
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
		return $output;
	}
	
	public function setPwd($pwd, $reGenerateMap = true) {
		$this->password = $pwd;
		$this->passwordSize = strlen($pwd);
		$this->precomputed = false;
		if($reGenerateMap)
			$this->generateMap();
		return $this;
    }
	public function setMap($map_data, $sizeX, $sizeY) {
		$this->map = $map_data;
		$this->mapSize = array($sizeX, $sizeY);
		$this->precomputed = false;
		return $this;
    }
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
	
	private function rectFrom($int, $aLimit = 128){
		$dataLen = $int;
		$b = $dataLen;
		$a = 1;
		$nums = [2,3,5,7,11,13];
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
		return [$a, $b,  $int];
	}

	
	private function generateMap(){
		$this->mapSize = [6,6];
		$this->map = sha1($this->password, true).md5($this->password, true);
		$this->precomputed = false;
	}
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