
/*!
* Base64 performs several functions: 
* Compress a string to base64, Diffie Hellman Merkle key exchange, 
* SHA256 hash, and generate high entropy random numbers.
* Generated public Keys are numeric and 300 digits in length (~1000 bit equivelent).
* 
* Last Modified: March 5, 2018
* Copyright (C) 2018 Graeme Goodkey github.com/ggoodkey
* All rights reserved
* 
* Released free of charge for inclusion in your own applications, as is or as modified by you.
* DISTRIBUTED "AS IS", WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.
* 
* Converting to Base 64 is based on Vassilis Petroulias' base64v1_0.js
* http://jsbase64.codeplex.com/
* 
* Compression is based on Sam Hocevar's lz-string-1.3.3.js 
* http://pieroxy.net/blog/pages/lz-string/index.html
* 
* Handling big integers is a subset of BigInteger.js by peterolson 
* https://www.npmjs.com/package/big-integer/
* 
*/


var Base64 = {};
(function () {

	Base64.Version = 1.1;

	/*base 64 charectors*/
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",

		hexAlf = '00,01,02,03,04,05,06,07,08,09,0a,0b,0c,0d,0e,0f,10,11,12,13,14,15,16,17,18,19,1a,1b,1c,1d,1e,1f,20,21,22,23,24,25,26,27,28,29,2a,2b,2c,2d,2e,2f,30,31,32,33,34,35,36,37,38,39,3a,3b,3c,3d,3e,3f,40,41,42,43,44,45,46,47,48,49,4a,4b,4c,4d,4e,4f,50,51,52,53,54,55,56,57,58,59,5a,5b,5c,5d,5e,5f,60,61,62,63,64,65,66,67,68,69,6a,6b,6c,6d,6e,6f,70,71,72,73,74,75,76,77,78,79,7a,7b,7c,7d,7e,7f,80,81,82,83,84,85,86,87,88,89,8a,8b,8c,8d,8e,8f,90,91,92,93,94,95,96,97,98,99,9a,9b,9c,9d,9e,9f,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,aa,ab,ac,ad,ae,af,b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,ba,bb,bc,bd,be,bf,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,ca,cb,cc,cd,ce,cf,d0,d1,d2,d3,d4,d5,d6,d7,d8,d9,da,db,dc,dd,de,df,e0,e1,e2,e3,e4,e5,e6,e7,e8,e9,ea,eb,ec,ed,ee,ef,f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,fa,fb,fc,fd,fe,ff'.split(','),

		//100 digit fast
		//prime = "6513516734600035718300327211250928237178281758494417357560086828416863929270451437126021949850746381";

		//300 digit
		prime = "319705304701141539155720137200974664666792526059405792539680974929469783512821793995613718943171723765238853752439032835985158829038528214925658918372196742089464683960239919950882355844766055365179937610326127675178857306260955550407044463370239890187189750909036833976197804646589380690779463976173";

		//644 digit slow
		//prime = "1475979915214180235084898622737381736312066145333169775147771216478570297878078949377407337049389289382748507531496480477281264838760259191814463365330269540496961201113430156902396093989090226259326935025281409614983499388222831448598601834318536230923772641390209490231836446899608210795482963763094236630945410832793769905399982457186322944729636418890623372171723742105636440368218459649632948538696905872650486914434637457507280441823676813517852099348660847172579408422316678097670224011990280170474894487426924742108823536808485072502240519452587542875349976558572670229633962575212637477897785501552646522609988869914013540483809865681250419497686697771007";

	function toHex(arr) {
		var hex = '';
		for (var i = 0, len = arr.length; i < len; i++) {
			hex += hexAlf[arr[i]];
		}
		return hex;
	}

	/*compress and convert text to Base64*/
	function convertTo(input) {
		if (input === null) return "";
		var output = "",
			orig = input;
		var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
		var i,
			value,
			context_dictionary = {},
			context_dictionaryToCreate = {},
			context_c = "",
			context_wc = "",
			context_w = "",
			context_enlargeIn = 2, // Compensate for the first entry which should not count
			context_dictSize = 3,
			context_numBits = 2,
			context_data_string = "",
			context_data_val = 0,
			context_data_position = 0,
			ii,
			f = String.fromCharCode;
		for (ii = 0; ii < input.length; ii += 1) {
			context_c = input.charAt(ii);
			if (!Object.prototype.hasOwnProperty.call(context_dictionary, context_c)) {
				context_dictionary[context_c] = context_dictSize++;
				context_dictionaryToCreate[context_c] = true;
			}
			context_wc = context_w + context_c;
			if (Object.prototype.hasOwnProperty.call(context_dictionary, context_wc)) {
				context_w = context_wc;
			} else {
				if (Object.prototype.hasOwnProperty.call(context_dictionaryToCreate, context_w)) {
					if (context_w.charCodeAt(0) < 256) {
						for (i = 0; i < context_numBits; i++) {
							context_data_val = context_data_val << 1;
							if (context_data_position === 15) {
								context_data_position = 0;
								context_data_string += f(context_data_val);
								context_data_val = 0;
							} else {
								context_data_position++;
							}
						}
						value = context_w.charCodeAt(0);
						for (i = 0; i < 8; i++) {
							context_data_val = context_data_val << 1 | value & 1;
							if (context_data_position === 15) {
								context_data_position = 0;
								context_data_string += f(context_data_val);
								context_data_val = 0;
							} else {
								context_data_position++;
							}
							value = value >> 1;
						}
					} else {
						value = 1;
						for (i = 0; i < context_numBits; i++) {
							context_data_val = context_data_val << 1 | value;
							if (context_data_position === 15) {
								context_data_position = 0;
								context_data_string += f(context_data_val);
								context_data_val = 0;
							} else {
								context_data_position++;
							}
							value = 0;
						}
						value = context_w.charCodeAt(0);
						for (i = 0; i < 16; i++) {
							context_data_val = context_data_val << 1 | value & 1;
							if (context_data_position === 15) {
								context_data_position = 0;
								context_data_string += f(context_data_val);
								context_data_val = 0;
							} else {
								context_data_position++;
							}
							value = value >> 1;
						}
					}
					context_enlargeIn--;
					if (context_enlargeIn === 0) {
						context_enlargeIn = Math.pow(2, context_numBits);
						context_numBits++;
					}
					delete context_dictionaryToCreate[context_w];
				} else {
					value = context_dictionary[context_w];
					for (i = 0; i < context_numBits; i++) {
						context_data_val = context_data_val << 1 | value & 1;
						if (context_data_position === 15) {
							context_data_position = 0;
							context_data_string += f(context_data_val);
							context_data_val = 0;
						} else {
							context_data_position++;
						}
						value = value >> 1;
					}
				}
				context_enlargeIn--;
				if (context_enlargeIn === 0) {
					context_enlargeIn = Math.pow(2, context_numBits);
					context_numBits++;
				}
				// Add wc to the dictionary.
				context_dictionary[context_wc] = context_dictSize++;
				context_w = String(context_c);
			}
		}
		// Output the code for w.
		if (context_w !== "") {
			if (Object.prototype.hasOwnProperty.call(context_dictionaryToCreate, context_w)) {
				if (context_w.charCodeAt(0) < 256) {
					for (i = 0; i < context_numBits; i++) {
						context_data_val = context_data_val << 1;
						if (context_data_position === 15) {
							context_data_position = 0;
							context_data_string += f(context_data_val);
							context_data_val = 0;
						} else {
							context_data_position++;
						}
					}
					value = context_w.charCodeAt(0);
					for (i = 0; i < 8; i++) {
						context_data_val = context_data_val << 1 | value & 1;
						if (context_data_position === 15) {
							context_data_position = 0;
							context_data_string += f(context_data_val);
							context_data_val = 0;
						} else {
							context_data_position++;
						}
						value = value >> 1;
					}
				} else {
					value = 1;
					for (i = 0; i < context_numBits; i++) {
						context_data_val = context_data_val << 1 | value;
						if (context_data_position === 15) {
							context_data_position = 0;
							context_data_string += f(context_data_val);
							context_data_val = 0;
						} else {
							context_data_position++;
						}
						value = 0;
					}
					value = context_w.charCodeAt(0);
					for (i = 0; i < 16; i++) {
						context_data_val = context_data_val << 1 | value & 1;
						if (context_data_position === 15) {
							context_data_position = 0;
							context_data_string += f(context_data_val);
							context_data_val = 0;
						} else {
							context_data_position++;
						}
						value = value >> 1;
					}
				}
				context_enlargeIn--;
				if (context_enlargeIn === 0) {
					context_enlargeIn = Math.pow(2, context_numBits);
					context_numBits++;
				}
				delete context_dictionaryToCreate[context_w];
			} else {
				value = context_dictionary[context_w];
				for (i = 0; i < context_numBits; i++) {
					context_data_val = context_data_val << 1 | value & 1;
					if (context_data_position === 15) {
						context_data_position = 0;
						context_data_string += f(context_data_val);
						context_data_val = 0;
					} else {
						context_data_position++;
					}
					value = value >> 1;
				}
			}
			context_enlargeIn--;
			if (context_enlargeIn === 0) {
				context_enlargeIn = Math.pow(2, context_numBits);
				context_numBits++;
			}
		}
		// Mark the end of the stream
		value = 2;
		for (i = 0; i < context_numBits; i++) {
			context_data_val = context_data_val << 1 | value & 1;
			if (context_data_position === 15) {
				context_data_position = 0;
				context_data_string += f(context_data_val);
				context_data_val = 0;
			} else {
				context_data_position++;
			}
			value = value >> 1;
		}
		// Flush the last char
		while (true) {
			context_data_val = context_data_val << 1;
			if (context_data_position === 15) {
				context_data_string += f(context_data_val);
				break;
			}
			else context_data_position++;
		}
		function toBase64(input) {
			var i = 0;
			while (i < input.length * 2) {
				if (i % 2 == 0) {
					chr1 = input.charCodeAt(i / 2) >> 8;
					chr2 = input.charCodeAt(i / 2) & 255;
					if (i / 2 + 1 < input.length)
						chr3 = input.charCodeAt(i / 2 + 1) >> 8;
					else
						chr3 = NaN;
				} else {
					chr1 = input.charCodeAt((i - 1) / 2) & 255;
					if ((i + 1) / 2 < input.length) {
						chr2 = input.charCodeAt((i + 1) / 2) >> 8;
						chr3 = input.charCodeAt((i + 1) / 2) & 255;
					} else
						chr2 = chr3 = NaN;
				}
				i += 3;
				enc1 = chr1 >> 2;
				enc2 = (chr1 & 3) << 4 | chr2 >> 4;
				enc3 = (chr2 & 15) << 2 | chr3 >> 6;
				enc4 = chr3 & 63;
				if (isNaN(chr2)) {
					enc3 = enc4 = 64;
				} else if (isNaN(chr3)) {
					enc4 = 64;
				}
				output = output +
				charset.charAt(enc1) + charset.charAt(enc2) +
				charset.charAt(enc3) + charset.charAt(enc4);
			}
			return output;
		}
		//constants represent the state of the data, whether or not 
		//it has been compressed so that the process can be reversed
		var compressed = toBase64("l" + context_data_string);
		orig = toBase64("n" + orig);
		//only use compressed version if it is indeed smaller,
		//as lzstring compression actually lengthens short, or already
		//highly compressed strings
		if (compressed.length > orig.length) compressed = orig;
		return "b" + compressed;
	}

	/*revert from compressed Base64 text to regular text*/
	function revertFrom(input) {
		if (input === null) {
			console.log("Decompression error1: Input is null");
			return "";
		}
		if (/^b/.test(input)) input = input.replace(/^b/, "");
		else {
			//console.log("Decompression error2: Input is not base64 compressed >>> " + input);
			return null;
		}
		var output = "",
		ol = 0,
		output_,
		chr1, chr2, chr3,
		enc1, enc2, enc3, enc4,
		i = 0, f = String.fromCharCode;
		input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");
		while (i < input.length) {
			enc1 = charset.indexOf(input.charAt(i++));
			enc2 = charset.indexOf(input.charAt(i++));
			enc3 = charset.indexOf(input.charAt(i++));
			enc4 = charset.indexOf(input.charAt(i++));
			chr1 = enc1 << 2 | enc2 >> 4;
			chr2 = (enc2 & 15) << 4 | enc3 >> 2;
			chr3 = (enc3 & 3) << 6 | enc4;
			if (ol % 2 == 0) {
				output_ = chr1 << 8;
				if (enc3 !== 64) {
					output += f(output_ | chr2);
				}
				if (enc4 !== 64) {
					output_ = chr3 << 8;
				}
			} else {
				output = output + f(output_ | chr1);
				if (enc3 !== 64) {
					output_ = chr2 << 8;
				}
				if (enc4 !== 64) {
					output += f(output_ | chr3);
				}
			}
			ol += 3;
		}
		//now decompress the data
		if (/^l/.test(output)) var compressed = output.replace(/^l/, "");
		else return output.replace(/^n/, "");
		if (compressed === null) {
			console.log("Decompression error2: Reverted from Base64 value is null");
			return null;
		}
		if (compressed === "") {
			console.log('Decompression error3: Reverted from Base64 value is "" (Empty string)');
			return null;
		}
		var dictionary = [],
			next,
			enlargeIn = 4,
			dictSize = 4,
			numBits = 3,
			entry = "",
			result = "",
			w,
			bits, resb, maxpower, power,
			c,
			data = { string: compressed, val: compressed.charCodeAt(0), position: 32768, index: 1 };
		f = String.fromCharCode;
		for (i = 0; i < 3; i += 1) dictionary[i] = i;
		bits = 0;
		maxpower = Math.pow(2, 2);
		power = 1;
		while (power != maxpower) {
			resb = data.val & data.position;
			data.position >>= 1;
			if (data.position === 0) {
				data.position = 32768;
				data.val = data.string.charCodeAt(data.index++);
			}
			bits |= (resb > 0 ? 1 : 0) * power;
			power <<= 1;
		}
		switch (next = bits) {
			case 0:
				bits = 0;
				maxpower = Math.pow(2, 8);
				power = 1;
				while (power != maxpower) {
					resb = data.val & data.position;
					data.position >>= 1;
					if (data.position === 0) {
						data.position = 32768;
						data.val = data.string.charCodeAt(data.index++);
					}
					bits |= (resb > 0 ? 1 : 0) * power;
					power <<= 1;
				}
				c = f(bits);
				break;
			case 1:
				bits = 0;
				maxpower = Math.pow(2, 16);
				power = 1;
				while (power != maxpower) {
					resb = data.val & data.position;
					data.position >>= 1;
					if (data.position === 0) {
						data.position = 32768;
						data.val = data.string.charCodeAt(data.index++);
					}
					bits |= (resb > 0 ? 1 : 0) * power;
					power <<= 1;
				}
				c = f(bits);
				break;
			case 2:
				return "";
		}
		dictionary[3] = c;
		w = result = c;
		while (true) {
			if (data.index > data.string.length) {
				console.log("Decompression error5");
				return "";
			}
			bits = 0;
			maxpower = Math.pow(2, numBits);
			power = 1;
			while (power != maxpower) {
				resb = data.val & data.position;
				data.position >>= 1;
				if (data.position === 0) {
					data.position = 32768;
					data.val = data.string.charCodeAt(data.index++);
				}
				bits |= (resb > 0 ? 1 : 0) * power;
				power <<= 1;
			}
			switch (c = bits) {
				case 0:
					bits = 0;
					maxpower = Math.pow(2, 8);
					power = 1;
					while (power != maxpower) {
						resb = data.val & data.position;
						data.position >>= 1;
						if (data.position === 0) {
							data.position = 32768;
							data.val = data.string.charCodeAt(data.index++);
						}
						bits |= (resb > 0 ? 1 : 0) * power;
						power <<= 1;
					}
					dictionary[dictSize++] = f(bits);
					c = dictSize - 1;
					enlargeIn--;
					break;
				case 1:
					bits = 0;
					maxpower = Math.pow(2, 16);
					power = 1;
					while (power != maxpower) {
						resb = data.val & data.position;
						data.position >>= 1;
						if (data.position === 0) {
							data.position = 32768;
							data.val = data.string.charCodeAt(data.index++);
						}
						bits |= (resb > 0 ? 1 : 0) * power;
						power <<= 1;
					}
					dictionary[dictSize++] = f(bits);
					c = dictSize - 1;
					enlargeIn--;
					break;
				case 2:
					return result;
			}
			if (enlargeIn === 0) {
				enlargeIn = Math.pow(2, numBits);
				numBits++;
			}
			if (dictionary[c]) {
				entry = dictionary[c];
			} else {
				if (c === dictSize && w) {
					entry = w + w.charAt(0);
				} else {
					return null;
				}
			}
			result += entry;
			// Add w+entry[0] to the dictionary.
			dictionary[dictSize++] = w + entry.charAt(0);
			enlargeIn--;
			w = entry;
			if (enlargeIn === 0) {
				enlargeIn = Math.pow(2, numBits);
				numBits++;
			}
		}
	}

	var bigInt = (function () {
		var base = 10000000, sign = { positive: false, negative: true };
		function BigInteger(value, sign) { this.value = value; this.sign = sign; }
		function trim(value) { while (value[value.length - 1] === 0 && value.length > 1) value.pop(); return value; }
		function fastMultiplyInternal(value, lambda) {
			var result = [], carry = 0;
			for (var i = 0; i < value.length; i++) {
				carry += lambda * value[i]; var q = Math.floor(carry / base); result[i] = carry - q * base | 0; carry = q;
			}
			result[value.length] = carry | 0; return result;
		}
		function fastDivModInternal(value, lambda) {
			var quotient = [], i; for (i = 0; i < value.length; i++) quotient[i] = 0; var remainder = 0;
			for (i = value.length - 1; i >= 0; i--) {
				var divisor = remainder * base + value[i], q = Math.floor(divisor / lambda); remainder = divisor - q * lambda; quotient[i] = q | 0;
			}
			return { quotient: quotient, remainder: remainder | 0 };
		}
		function isSmall(n) {
			return (typeof n === "number" || typeof n === "string") && +Math.abs(n) <= base || n instanceof BigInteger && n.value.length <= 1;
		}
		BigInteger.prototype.multiply = function (n) {
			var a, b, i, result;
			if (isSmall(n)) {
				a = this;
				b = +n;
				result = fastMultiplyInternal(a.value, b < 0 ? -b : b);
				return new BigInteger(trim(result), b < 0 ? !a.sign : a.sign);
			}
			n = parseInput(n);
			var sign = this.sign !== n.sign;
			a = this.value;
			b = n.value;
			result = [];
			for (i = a.length + b.length; i > 0; i--) result.push(0);
			for (i = 0; i < a.length; i++) {
				var x = a[i];
				for (var j = 0; j < b.length; j++) {
					var y = b[j], product = x * y + result[i + j], q = Math.floor(product / base);
					result[i + j] = product - q * base;
					result[i + j + 1] += q;
				}
			}
			return new BigInteger(trim(result), sign);
		};
		BigInteger.prototype.divmod = function (n) {
			var a, b, result, i;
			if (isSmall(n)) {
				a = this;
				b = +n;
				if (b === 0) throw new Error("Cannot divide by zero.");
				result = fastDivModInternal(a.value, b < 0 ? -b : b);
				return { quotient: new BigInteger(trim(result.quotient), b < 0 ? !a.sign : a.sign), remainder: new BigInteger([result.remainder], a.sign) };
			}
			n = parseInput(n);
			var quotientSign = this.sign !== n.sign;
			if (n.equals(ZERO)) throw new Error("Cannot divide by zero");
			if (this.equals(ZERO)) return { quotient: new BigInteger([0], sign.positive), remainder: new BigInteger([0], sign.positive) };
			a = this.value;
			b = n.value;
			result = [0];
			for (i = 0; i < b.length; i++) result[i] = 0;
			var divisorMostSignificantDigit = b[b.length - 1];
			// normalization
			var lambda = Math.ceil(base / 2 / divisorMostSignificantDigit);
			var remainder = fastMultiplyInternal(a, lambda);
			var divisor = fastMultiplyInternal(b, lambda);
			divisorMostSignificantDigit = divisor[b.length - 1];
			for (var shift = a.length - b.length; shift >= 0; shift--) {
				var quotientDigit = base - 1;
				if (remainder[shift + b.length] !== divisorMostSignificantDigit) {
					quotientDigit = Math.floor((remainder[shift + b.length] * base + remainder[shift + b.length - 1]) / divisorMostSignificantDigit);
				}
				var carry = 0;
				var borrow = 0;
				for (i = 0; i < divisor.length; i++) {
					carry += quotientDigit * divisor[i];
					var q = Math.floor(carry / base);
					borrow += remainder[shift + i] - (carry - q * base);
					carry = q;
					if (borrow < 0) {
						remainder[shift + i] = borrow + base | 0; borrow = -1;
					} else { remainder[shift + i] = borrow | 0; borrow = 0; }
				}
				while (borrow !== 0) {
					quotientDigit -= 1;
					carry = 0;
					for (i = 0; i < divisor.length; i++) {
						carry += remainder[shift + i] - base + divisor[i];
						if (carry < 0) {
							remainder[shift + i] = carry + base | 0; carry = 0;
						} else { remainder[shift + i] = carry | 0; carry = +1; }
					}
					borrow += carry;
				}
				result[shift] = quotientDigit | 0;
			}
			// denormalization
			remainder = fastDivModInternal(remainder, lambda).quotient;
			return { quotient: new BigInteger(trim(result), quotientSign), remainder: new BigInteger(trim(remainder), this.sign) };
		};
		BigInteger.prototype.modPow = function (exp, mod) {
			exp = parseInput(exp);
			mod = parseInput(mod);
			if (mod.equals(ZERO)) throw new Error("Cannot take modPow with modulus 0");
			var r = ONE, base = this.divmod(mod).remainder;
			if (base.equals(ZERO)) return ZERO;
			while (exp.compare(0) > 0) {
				if (exp.isOdd()) r = r.multiply(base).divmod(mod).remainder;
				exp = exp.divmod(2).quotient;
				base = base.multiply(base).divmod(mod).remainder;
			}
			return r;
		};
		BigInteger.prototype.compare = function (n) {
			var first = this, second = parseInput(n);
			if (first.value.length === 1 && second.value.length === 1 && first.value[0] === 0 && second.value[0] === 0) return 0;
			if (second.sign !== first.sign) return first.sign === sign.positive ? 1 : -1;
			var multiplier = first.sign === sign.positive ? 1 : -1, a = first.value, b = second.value, length = Math.max(a.length, b.length) - 1;
			for (var i = length; i >= 0; i--) {
				var ai = a[i] || 0, bi = b[i] || 0;
				if (ai > bi) return 1 * multiplier;
				if (bi > ai) return -1 * multiplier;
			}
			return 0;
		};
		BigInteger.prototype.equals = function (n) { return this.compare(n) === 0; };
		BigInteger.prototype.isOdd = function () { return this.value[0] % 2 === 1; };
		BigInteger.prototype.toString = function (radix) {
			if (radix === undefined) radix = 10;
			if (radix !== 10) return toBase(this, radix);
			var first = this, str = "", len = first.value.length;
			if (len === 0 || len === 1 && first.value[0] === 0) return "0";
			len -= 1;
			str = first.value[len].toString();
			while (--len >= 0) {
				var digit = first.value[len].toString();
				str += "0000000".slice(digit.length) + digit;
			}
			var s = first.sign === sign.positive ? "" : "-";
			return s + str;
		};
		var ZERO = new BigInteger([0], sign.positive);
		var ONE = new BigInteger([1], sign.positive);
		function parseInput(text) {
			if (text instanceof BigInteger) return text;
			if (Math.abs(+text) < base && +text === (+text | 0)) {
				var val = +text;
				return new BigInteger([Math.abs(val)], val < 0 || 1 / val === -Infinity);
			}
			text += "";
			var s = sign.positive, value = [];
			if (text[0] === "-") { s = sign.negative; text = text.slice(1); }
			text = text.split(/e/i);
			if (text.length > 2) throw new Error("Invalid integer: " + text.join("e"));
			if (text[1]) {
				var exp = text[1];
				if (exp[0] === "+") exp = exp.slice(1);
				exp = parseInput(exp);
				var decimalPlace = text[0].indexOf(".");
				if (decimalPlace >= 0) {
					exp = exp.minus(text[0].length - decimalPlace);
					text[0] = text[0].slice(0, decimalPlace) + text[0].slice(decimalPlace + 1);
				}
				if (exp.lesser(0)) throw new Error("Cannot include negative exponent part for integers");
				while (exp.notEquals(0)) { text[0] += "0"; exp = exp.prev(); }
			}
			text = text[0];
			if (text === "-0") text = "0";
			var isValid = /^([0-9][0-9]*)$/.test(text);
			if (!isValid) throw new Error("Invalid integer: " + text);
			while (text.length) {
				var divider = text.length > 7 ? text.length - 7 : 0;
				value.push(+text.slice(divider));
				text = text.slice(0, divider);
			}
			return new BigInteger(trim(value), s);
		}
		var fnReturn = function (a) {
			if (typeof a === "undefined") return ZERO;
			return parseInput(a);
		};
		return fnReturn;
	})();

	/*creates a Diffie Hellman Merkle session key from your own secret private key and someone elses public key*/
	function getSessionKey(privateKey, publicKey) {
		return bigInt(publicKey).modPow(Base64.number_hash(privateKey, 100), prime).toString();
	}

	/*converts any string to a positive integer of the requiredLength*/
	Base64.number_hash = function (str, requiredLength) {
		requiredLength = !isNaN(parseFloat(requiredLength)) && isFinite(requiredLength) && requiredLength > 0 ? parseInt(requiredLength) : 10;
		str = Base64.hash(str);
		var out = "";
		for (var a = 0; out.length < requiredLength; a++) {
			var h = 0, i, chr, len;
			if (str.length === 0) return h;
			for (i = 0, len = str.length; i < len; i++) {
				chr = str.charCodeAt(i);
				h = (h << 5) - h + chr;
				h |= 0; // Convert to 32bit integer
			}
			h = String(h + Math.pow(2, 31));
			while (h.length < 10) h = "0" + h;
			out += h.slice(2);
		}
		return out.slice(0, requiredLength);
	};

	/*	generate a random number of the "requiredLength" (input a Number from 1-1000), 
		based on timing, proccessor speed, and any "additionalEntropy" you want to provide (optional)*/
	Base64.rand = function (requiredLength, additionalEntropy) {
		var len = !isNaN(parseFloat(requiredLength)) && isFinite(requiredLength) && requiredLength > 0 ? parseInt(requiredLength, 10) : 8,
			ent = additionalEntropy ? String(additionalEntropy) : String(Math.random()),
			num = 0, out = "";
		if (len > 1000) len = 1000;//physical limit to save you from breaking your browser!
		while (out.length < len) {
			num = 0;
			for (var b = 0; b < 4300; b++) num += Number(String(new Date().getTime()).slice(7));//generate 32 bits of entropy
			num = String(num);
			while (num.charAt(0) === "0" && num.length > 1) num = num.slice(1);
			num = Base64.number_hash(ent + num, 8);//generate 32 bit number from 32 bits of entropy (plus additionalEntropy)
			out += num;//string all the numbers together to form required length
		}
		while (out.charAt(0) === "0" && out.length > 1) out = out.slice(1);
		//in some cases during the last round through the "while" statement a number starting with 3 or more 0's will be chosen which results in too short an output number
		if (out.length < len) return Base64.rand(len, ent + Math.random());//try again
		return out.slice(0, len);
	};

	//salted SHA256 hash
	//asArray (optional) set to true to return an array of 32 base 10 numbers instead of hexadecimal
	Base64.hash = function (message, asArray) {
		function Uint8Arr(length) {
			if (typeof Uint8Array !== 'undefined') {
				return new Uint8Array(length);
			} else {
				return new Array(length);
			}
		}
		function Int32Arr(length) {
			if (typeof Int32Array !== 'undefined') {
				return new Int32Array(length);
			} else {
				return new Array(length);
			}
		}
		var h0 = 0x6a09e667;
		var h1 = 0xbb67ae85;
		var h2 = 0x3c6ef372;
		var h3 = 0xa54ff53a;
		var h4 = 0x510e527f;
		var h5 = 0x9b05688c;
		var h6 = 0x1f83d9ab;
		var h7 = 0x5be0cd19;
		var K = [
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
			0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
			0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
			0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
			0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
			0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
			0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
			0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
			0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
			0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
			0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
			0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
		message = message ? message : "";
		message = String(message.length + 1231) + String(message);
		var s = unescape(encodeURIComponent(message)); // UTF-8
		message = Uint8Arr(s.length);
		for (var i = 0; i < s.length; i++) {
			message[i] = s.charCodeAt(i) & 0xff;
		}
		var length = message.length;
		var byteLength = Math.floor((length + 72) / 64) * 64;
		var wordLength = byteLength / 4;
		var bitLength = length * 8;
		var m = Uint8Arr(byteLength);
		if (typeof Uint8Array !== 'undefined') {
			m.set(message);
		} else {
			for (var i = 0; i < message.length; i++) {
				m[i] = message[i];
			}
			for (i = message.length; i < m.length; i++) {
				m[i] = 0;
			}
		}
		m[length] = 0x80;
		m[byteLength - 4] = bitLength >>> 24;
		m[byteLength - 3] = (bitLength >>> 16) & 0xff;
		m[byteLength - 2] = (bitLength >>> 8) & 0xff;
		m[byteLength - 1] = bitLength & 0xff;
		var words = Int32Arr(wordLength);
		var byteIndex = 0;
		for (i = 0; i < words.length; i++) {
			var word = m[byteIndex] << 24;
			word |= m[byteIndex + 1] << 16;
			word |= m[byteIndex + 2] << 8;
			word |= m[byteIndex + 3];
			words[i] = word;
			byteIndex += 4;
		}
		var w = Int32Arr(64);
		for (var j = 0; j < wordLength; j += 16) {
			for (i = 0; i < 16; i++) {
				w[i] = words[j + i];
			}
			for (i = 16; i < 64; i++) {
				var v = w[i - 15];
				var s0 = (v >>> 7) | (v << 25);
				s0 ^= (v >>> 18) | (v << 14);
				s0 ^= (v >>> 3);
				v = w[i - 2];
				var s1 = (v >>> 17) | (v << 15);
				s1 ^= (v >>> 19) | (v << 13);
				s1 ^= (v >>> 10);
				w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff;
			}
			var a = h0;
			var b = h1;
			var c = h2;
			var d = h3;
			var e = h4;
			var f = h5;
			var g = h6;
			var h = h7;
			for (i = 0; i < 64; i++) {
				s1 = (e >>> 6) | (e << 26);
				s1 ^= (e >>> 11) | (e << 21);
				s1 ^= (e >>> 25) | (e << 7);
				var ch = (e & f) ^ (~e & g);
				var temp1 = (h + s1 + ch + K[i] + w[i]) & 0xffffffff;
				s0 = (a >>> 2) | (a << 30);
				s0 ^= (a >>> 13) | (a << 19);
				s0 ^= (a >>> 22) | (a << 10);
				var maj = (a & b) ^ (a & c) ^ (b & c);
				var temp2 = (s0 + maj) & 0xffffffff;
				h = g;
				g = f;
				f = e;
				e = (d + temp1) & 0xffffffff;
				d = c;
				c = b;
				b = a;
				a = (temp1 + temp2) & 0xffffffff;
			}
			h0 = (h0 + a) & 0xffffffff;
			h1 = (h1 + b) & 0xffffffff;
			h2 = (h2 + c) & 0xffffffff;
			h3 = (h3 + d) & 0xffffffff;
			h4 = (h4 + e) & 0xffffffff;
			h5 = (h5 + f) & 0xffffffff;
			h6 = (h6 + g) & 0xffffffff;
			h7 = (h7 + h) & 0xffffffff;
		}
		var hash = Uint8Arr(32);
		for (i = 0; i < 4; i++) {
			hash[i] = (h0 >>> (8 * (3 - i))) & 0xff;
			hash[i + 4] = (h1 >>> (8 * (3 - i))) & 0xff;
			hash[i + 8] = (h2 >>> (8 * (3 - i))) & 0xff;
			hash[i + 12] = (h3 >>> (8 * (3 - i))) & 0xff;
			hash[i + 16] = (h4 >>> (8 * (3 - i))) & 0xff;
			hash[i + 20] = (h5 >>> (8 * (3 - i))) & 0xff;
			hash[i + 24] = (h6 >>> (8 * (3 - i))) & 0xff;
			hash[i + 28] = (h7 >>> (8 * (3 - i))) & 0xff;
		}

		if (asArray) return hash;
		else return toHex(hash);
	};

	Base64.hmac = function (message, key) {
		key = String(key);
		if (key.length > 32) key = Base64.hash(key, true);
		else {
			var s = unescape(encodeURIComponent(key)); // UTF-8
			key = new Uint8Array(32);
			for (var i = 0; i < s.length; i++) {
				key[i] = s.charCodeAt(i);
			}
		}
		for (var i = 0; i < key.length; i++) {
			key[i] ^= 0x36;
		}
		var inner = Base64.hash(toHex(key));
		for (var i = 0; i < key.length; i++) {
			key[i] ^= 0x36 ^ 0x5c;
		}
		return Base64.hash(toHex(key) + inner + String(message));
	};

	/*compress and convert any text to base64, with our without a key*/
	Base64.write = function (str, key) {
		if (str === null) return "";
		str = String(str);
		str = convertTo(str);
		if (key) {
			var a, b = [], c = charset, d = Base64.hash(key), e, f = c + c + c + c + c;
			for (a = 0, e = 0; a < str.length; a++, e = e === String(d).length - 1 ? 0 : e + 1) b[a] = f[parseInt(c.indexOf(str[a])) + parseInt(c.indexOf(String(d)[e])) * 4];
			str = "d" + b.join("");
			a = null; b = null; c = null; d = null; e = null; f = null; key = null;
		}
		return str;
	};

	/*revert from base64, and decompress*/
	Base64.read = function (str, key) {
		if (str === null) return "";
		str = String(str);
		if (key && /^d/.test(str)) {
			str = str.replace(/^d/, "");
			var a = str.length, b = [], c = charset, d = Base64.hash(key), e, f = c + c + c + c + c, g, h = String(d).length, i = c.length;
			for (g = 0, e = 0; g < a; g++, e = e === h - 1 ? 0 : e + 1) b[g] = f[c.indexOf(str[g]) + i * 4 - parseInt(c.indexOf(String(d)[e])) * 4];
			str = b.join("");
			key = null; a = null; b = null; c = null; d = null; e = null; f = null; g = null;
		}
		str = revertFrom(str);
		return str;
	};

	/*same as Base64.write, but does some error checking as well*/
	Base64.write_and_verify = function (str, key) {
		function locateTextDifferences(str1, str2) {
			diff = [], d = 1;
			if (str2 === null) return "Decompressing the string returned null. Possibly invalid key used??";
			var len1 = str1.length, len2 = str2.length;
			if (len1 !== len2) diff[0] = "Strings are not the same length. String 1: " + len1 + " characters. String 2: " + len2 + " characters.";
			else diff[0] = "Entire text length: " + len1 + " characters";
			for (var a = 0; a < len1 && a < len2; a++) {
				if (str1.charAt(a) !== str2.charAt(a)) {
					diff[d] = "Char " + (a + 1) + ": ASCII " + str1.charCodeAt(a) + " not equal to ";
					diff[d] = diff[d] + "ASCII " + str2.charCodeAt(a) + ".";
					diff[d] = diff[d] + "Surrounding text: " + str1.slice(a - 10, a + 10);
					d++;
				}
			}
			if (d === 1) return false;
			else return diff.join("<br />");
		}
		/*for debugging the write/read functions*/
		var orig = str;
		str = Base64.write(str, key);
		if (Base64.read(str, key) !== orig) return "Write error! Aborted operation. " + locateTextDifferences(orig, Base64.read(str, key));
		else return str;
	};

	/*creates a Diffie Hellman Merkle public key from any string (usually from a secret password)*/
	Base64.createPublicKey = function (myPrivateKey) {
		myPrivateKey = Base64.number_hash(myPrivateKey, 100);
		var ret = bigInt("32416178251").modPow(myPrivateKey, prime).toString();
		return ret;
	};

	/* create a secondary secret key to share with someone if you know their public key.
	 * You must also give them the secret key's corresponding public key. Similar to a session key
	 */
	Base64.createUserKey = function (userPublicKey, masterKey) { return Base64.write("key:" + masterKey, getSessionKey(masterKey, userPublicKey)); };

	/*same as Base64.createUserKey, but needs the user's private key to verify*/
	Base64.createUserKey_and_verify = function (userPrivateKey, masterKey) {
		//create public keys
		var mainPublicKey = Base64.createPublicKey(masterKey),
			userPublicKey = Base64.createPublicKey(userPrivateKey);
		//verify public keys work
		var usersSessionKey = getSessionKey(userPrivateKey, mainPublicKey),
			mainSessionKey = getSessionKey(masterKey, userPublicKey);
		if (usersSessionKey !== mainSessionKey) throw new Error("Public/Private key creation error");
		//create userKey from masterKey with common session key
		var userKey = Base64.write_and_verify("key:" + masterKey, mainSessionKey);
		//verify
		if (String(masterKey) === String(Base64.readUserKey(userPrivateKey, userKey, mainPublicKey))) return userKey;
		else throw new Error("Error creating user key for " + userPrivateKey);
	};

	/* read a secret key (userKey) that was shared with you, using your own secret key and the person who shared it
	 * with you's public key (the mainPublicKey is the public key that corresponds to the secret key)
	 */
	Base64.readUserKey = function (myPrivateKey, userKey, mainPublicKey) {
		var key = Base64.read(userKey, getSessionKey(myPrivateKey, mainPublicKey));
		if (/^key:/.test(key)) return key.replace(/^key:/, "");
		else return false;
	};

	/* share plaintext with someone if you know their public key (as generated by base64.js)
	 * expires = Number in months till data is no longer valid (optional, can be easily bypassed if source code is known)
	 */
	Base64.share = function (str, myPrivateKey, theirPublicKeys, expires) {
		var key = Base64.rand(prime.length),
			members = [Base64.createUserKey(Base64.createPublicKey(myPrivateKey), key)]; //add self to members in case uploading to network where you might need to access it as well
		expires = !isNaN(parseFloat(expires)) && isFinite(expires) ? new Date().getTime() + expires * 26298e5 : expires ? new Date().getTime() + 18 * 26298e5 : false;
		theirPublicKeys = theirPublicKeys && theirPublicKeys instanceof Array ? theirPublicKeys : null;
		str = Base64.write(str, key);
		if (theirPublicKeys) {
			for (var a = 0; a < theirPublicKeys.length; a++) {
				members[a + 1] = Base64.createUserKey(theirPublicKeys[a], key);
			}
		}
		return {
			"Version": Base64.Version,
			"Expires": expires,
			"Compressed": true,
			"Data": str,
			"PublicKey": Base64.createPublicKey(key),
			"UserKeys": Base64.write_and_verify(JSON.stringify(members)),
			"Signature": Base64.hmac(str + expires, key)
		};
	};
	/* returns data as an object {
		"message": a debug message if process failed
		"type": "results" if successful, "debug" if not
		"data": the shared file content
		"hash": the hash of the shared file contents
	}
	*/
	Base64.readShared = function (obj, myPrivateKey) {
		var key,
			type = "debug",
			message = "",
			data = null,
			hash = null;
		if (obj.Version === Base64.Version || obj.Version === 1.0) {//supported version numbers
			if (obj.UserKeys && obj.Compressed) {
				var members = JSON.parse(Base64.read(obj.UserKeys));
				for (var a = 0, len = members.length; a < len; a++) {
					if (Base64.readUserKey(myPrivateKey, members[a], obj.PublicKey))
						key = Base64.readUserKey(myPrivateKey, members[a], obj.PublicKey);
				}
				members = null;
			}
			if (obj.Expires !== false && new Date().getTime() > obj.Expires) message = "data expired";
			else if (key) {
				if (obj.Version === 1.0) { //version 1.0 uses hash, not hmac
					data = Base64.read(obj.Data, key);
					hash = Base64.hash(data + obj.Expires);
					if (obj.Signature === hash) {
						type = "results";
						message = "success";
					}
					else {
						data = null;
						message = "hash didn't match";
					}
				}
				else {
					hash = Base64.hmac(obj.Data + obj.Expires, key);
					if (obj.Signature === hash) {
						data = Base64.read(obj.Data, key);
						type = "results";
						message = "success";
					}
					else {
						data = null;
						message = "hmac didn't match";
					}
				}
			}
			else message = "no key match";
		}
		else message = "file version '" + obj.Version + "' not supported";
		return { "type": type, "message": message, "data": data, "hmac": hash };
	};
})();