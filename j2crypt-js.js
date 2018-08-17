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
	this.precomputed = false;
	return this;
}
J2crypt.prototype.setMapJson = function(json_text){
	this.map = JSON.parse(crypto_map);
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
	window.jQuery.post(a,b,function(d){
		J2cryptInstance.unlock(d, c);
	}, "binary");
}
J2crypt.prototype.get = function(a,b,c,p){
	var J2cryptInstance = this;
	window.jQuery.get(a,b,function(d){
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
J2crypt.prototype.array7unlock = function(data){
		console.log("unlocking",data);
		var i = 0;
		var r = 0;
		var c = 0;
		var width = data[0];
		var height = data[1];
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
				var f = (mv+pk)%128;
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
		return output;
}