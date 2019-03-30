/*
*
* j2crypt-js.js
* 
* @description J2crypt Library - 2Way 2D+ JSON data crypting
* @version 1.3
* @author Tomas Molinari @toomeenoo <tomie.molinari@gmail.com>
* @license MIT
* @required jquery.binarytransport.js form Henry Algus; jQuery
*
*/
function J2crypt(){
	this.map = {"width":1,"height":1,"data":[0]};
	this.password = "0";
	this.passwordSize = 1;
	return this;
}
J2crypt.prototype.setPwd = function(pwd){
	this.password = pwd;
	this.passwordSize = pwd.length;
	return this;
}
J2crypt.prototype.setMapJson = function(json_text){
	this.map = JSON.parse(json_text);
	this.map.data = [];
	var i = 0;
	while(i<this.map.dataHex.length){
		this.map.data.push(parseInt(this.map.dataHex.substr(i, 2),16));
		i += 2;
	}
	delete this.map.dataHex;
	return this;
}

J2crypt.prototype.post = function(a,b,c){
	var J2cryptInstance = this;
	return window.jQuery.post(a,b,function(d){
		J2cryptInstance.unlock(d, c);
	}, "binary");
}
J2crypt.prototype.get = function(a,b,c){
	var J2cryptInstance = this;
	return window.jQuery.get(a,b,function(d){
		J2cryptInstance.unlock(d, c);
	}, "binary");
}
J2crypt.prototype.cpost = function(a,b,c){
	var J2cryptInstance = this;
	return window.jQuery.post(a,{j2crypt: this.lock(typeof b == "object" ? JSON.stringify(b) : b )},function(d){
		J2cryptInstance.unlock(d, c);
	}, "binary");
}
J2crypt.prototype.cget = function(a,b,c){
	var J2cryptInstance = this;
	return window.jQuery.get(a,{j2crypt: this.lock(typeof b == "object" ? JSON.stringify(b) : b )},function(d){
		J2cryptInstance.unlock(d, c);
	}, "binary");
}

J2crypt.prototype.unlock = function(blob, callback){
	var J2cryptInstance = this;
	var fileReader = new FileReader();
	fileReader.onload = function(event) {
		var k = "";
		Array.prototype.map.call(new Uint8Array(event.target.result), function(x){
			k += ("00000000"+(parseInt(x).toString(2))).substr(-8);
		});
		//bin to 7bitArray
		var array7 = [];
		while(k.length >= 7){
				array7.push(parseInt("00"+k.substr(0, 7), 2));
				k = k.substr(7);
		}
		callback(J2cryptInstance.array7unlock(array7));
	};
	fileReader.readAsArrayBuffer(blob);
}
J2crypt.prototype.b64unlock = function(data){
	var byteCharacters = atob(data);
	var byteNumbers = new Array(byteCharacters.length);
	for (var i = 0; i < byteCharacters.length; i++) {
		byteNumbers[i] = byteCharacters.charCodeAt(i);
	}

	var k = "";
	Array.prototype.map.call(new Uint8Array(byteNumbers), function(x){
		k += ("00000000"+(parseInt(x).toString(2))).substr(-8);
	});

	var array7 = [];
	while(k.length >= 7){
			array7.push(parseInt("00"+k.substr(0, 7), 2));
			k = k.substr(7);
	}
	return this.array7unlock(array7);
}
J2crypt.prototype.array7unlock = function(data){
	//console.log("Unlocking ",data);
	if(!(data instanceof Array && typeof data[0] == "number"))
		return null;
	var i = 0;
	var r = 0;
	var c = 0;
	var width = data[0];
	var last = data[1];
	var magicUnknown = data[2];
	var output = "";
	var datalen = data.length;
	while(i+3 < datalen){
		c = 0;
		while(i+3 < datalen && c < width){
			var mc = c % this.map.width;
			var mr = r % this.map.height;
			var mv = this.map.data[mc+mr*this.map.width];
			var pk = this.password.charCodeAt((i+magicUnknown)%this.passwordSize);
			//var f = (mv+pk)%128;
			var mx = 128;
			while(mv+pk > mx){
				mx += 128;
			}
			output += String.fromCharCode(((mx-(mv+pk))+data[i+3])%128);
			c++;
			i++;
		}
		r ++;
	}
	while(last != output.charCodeAt(output.length-1) && output.length){
		output = output.substr(0, output.length-1);
	}
	console.log("Data stat: ", width, magicUnknown, last);
	return output;
}

J2crypt.prototype.lock = function(data){
	function toBin7n(x){
		return ("0000000"+(x.toString(2))).substr(-7);
	}

	function rectFrom(dataLen, aLimit){
		aLimit = aLimit || 128;
		b = dataLen;
		a = 1;
		nums = [2,3,5,7,11,13];
		i = 0;
		while(i<6){
			n = nums[i];
			while(!(b%n) && ((a*n)+(b/n))<(a+b) && (a*n)<aLimit){
				a *= n;
				b /= n;
			}
			i++;
		}
		if(((a*n)<aLimit) && a < b/3){
			return rectFrom(dataLen+1);
		}
		return [a, b,  dataLen];
	}

	var dataSize = rectFrom(data.length);

	var magicUnknown = Math.floor( Math.random() * 127);
	var width = dataSize[0];
	var height = data.charCodeAt(data.length-1);
	var datalen = data.length;	
	var output = [width, height, magicUnknown];
	var bin7 = ""+ toBin7n(width) + toBin7n(height%128) + toBin7n(magicUnknown);
	var hexadec = "";
	var i = 0;
	var r = 0;
	var c = 0;

	while(i < datalen && r < height){
		c = 0;
		while(i < datalen && c < width){
			var mc = c % this.map.width,
				mr = r % this.map.height;
			var mv = this.map.data[mc+mr*this.map.width];
			ps = this.password.charCodeAt((i+magicUnknown)%this.passwordSize);
			f = (data.charCodeAt(i)+mv+ps)%128;
			output.push(f);
			bin7 += ("0000000" + f.toString(2)).substr(-7);
			while(bin7.length >= 8){
				hexadec += ("00" + parseInt(bin7.substr(0,8), 2).toString(16)).substr(-2);
				bin7 = bin7.substr(8);
			}
			c++;
			i++;
		}
		r ++;
	}
	if(bin7.length){
		while(bin7.length % 8){
			bin7 += "0";
		}
		while(bin7.length > 0){
			hexadec += ("00" + parseInt(bin7.substr(0,8), 2).toString(16)).substr(-2);
			bin7 = bin7.substr(8);
		}
	}
	this.precomputed = output;
	this.hexadec = hexadec;
	
	return btoa(hexadec.match(/\w{2}/g).map(function(a){return String.fromCharCode(parseInt(a, 16));} ).join(""));
}