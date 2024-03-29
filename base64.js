"use strict";
/*!
* Base64 performs several functions:
* Compress a string to base64, Diffie Hellman Merkle key exchange,
* SHA256 hash, and generate high entropy random numbers.
* Generated public Keys are numeric and 300 digits in length (~1000 bit equivelent).
*
* Last Modified: November 26, 2021
* Copyright (C) 2021 Graeme Goodkey github.com/ggoodkey
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
var Base64 = (function () {
    var b64 = {};
    /* eslint-disable */
    b64.Version = 1.2;
    /*base 64 charectors*/
    var charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", hexAlf = '00,01,02,03,04,05,06,07,08,09,0a,0b,0c,0d,0e,0f,10,11,12,13,14,15,16,17,18,19,1a,1b,1c,1d,1e,1f,20,21,22,23,24,25,26,27,28,29,2a,2b,2c,2d,2e,2f,30,31,32,33,34,35,36,37,38,39,3a,3b,3c,3d,3e,3f,40,41,42,43,44,45,46,47,48,49,4a,4b,4c,4d,4e,4f,50,51,52,53,54,55,56,57,58,59,5a,5b,5c,5d,5e,5f,60,61,62,63,64,65,66,67,68,69,6a,6b,6c,6d,6e,6f,70,71,72,73,74,75,76,77,78,79,7a,7b,7c,7d,7e,7f,80,81,82,83,84,85,86,87,88,89,8a,8b,8c,8d,8e,8f,90,91,92,93,94,95,96,97,98,99,9a,9b,9c,9d,9e,9f,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,aa,ab,ac,ad,ae,af,b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,ba,bb,bc,bd,be,bf,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,ca,cb,cc,cd,ce,cf,d0,d1,d2,d3,d4,d5,d6,d7,d8,d9,da,db,dc,dd,de,df,e0,e1,e2,e3,e4,e5,e6,e7,e8,e9,ea,eb,ec,ed,ee,ef,f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,fa,fb,fc,fd,fe,ff'.split(','), 
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
        if (input === null)
            return "";
        var output = "", orig = input;
        var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
        var i, value, context_dictionary = {}, context_dictionaryToCreate = {}, context_c = "", context_wc = "", context_w = "", context_enlargeIn = 2, // Compensate for the first entry which should not count
        context_dictSize = 3, context_numBits = 2, context_data_string = "", context_data_val = 0, context_data_position = 0, ii, f = String.fromCharCode;
        for (ii = 0; ii < input.length; ii += 1) {
            context_c = input.charAt(ii);
            if (!Object.prototype.hasOwnProperty.call(context_dictionary, context_c)) {
                context_dictionary[context_c] = context_dictSize++;
                context_dictionaryToCreate[context_c] = true;
            }
            context_wc = context_w + context_c;
            if (Object.prototype.hasOwnProperty.call(context_dictionary, context_wc)) {
                context_w = context_wc;
            }
            else {
                if (Object.prototype.hasOwnProperty.call(context_dictionaryToCreate, context_w)) {
                    if (context_w.charCodeAt(0) < 256) {
                        for (i = 0; i < context_numBits; i++) {
                            context_data_val = context_data_val << 1;
                            if (context_data_position === 15) {
                                context_data_position = 0;
                                context_data_string += f(context_data_val);
                                context_data_val = 0;
                            }
                            else {
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
                            }
                            else {
                                context_data_position++;
                            }
                            value = value >> 1;
                        }
                    }
                    else {
                        value = 1;
                        for (i = 0; i < context_numBits; i++) {
                            context_data_val = context_data_val << 1 | value;
                            if (context_data_position === 15) {
                                context_data_position = 0;
                                context_data_string += f(context_data_val);
                                context_data_val = 0;
                            }
                            else {
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
                            }
                            else {
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
                }
                else {
                    value = context_dictionary[context_w];
                    for (i = 0; i < context_numBits; i++) {
                        context_data_val = context_data_val << 1 | value & 1;
                        if (context_data_position === 15) {
                            context_data_position = 0;
                            context_data_string += f(context_data_val);
                            context_data_val = 0;
                        }
                        else {
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
                        }
                        else {
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
                        }
                        else {
                            context_data_position++;
                        }
                        value = value >> 1;
                    }
                }
                else {
                    value = 1;
                    for (i = 0; i < context_numBits; i++) {
                        context_data_val = context_data_val << 1 | value;
                        if (context_data_position === 15) {
                            context_data_position = 0;
                            context_data_string += f(context_data_val);
                            context_data_val = 0;
                        }
                        else {
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
                        }
                        else {
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
            }
            else {
                value = context_dictionary[context_w];
                for (i = 0; i < context_numBits; i++) {
                    context_data_val = context_data_val << 1 | value & 1;
                    if (context_data_position === 15) {
                        context_data_position = 0;
                        context_data_string += f(context_data_val);
                        context_data_val = 0;
                    }
                    else {
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
            }
            else {
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
            else
                context_data_position++;
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
                }
                else {
                    chr1 = input.charCodeAt((i - 1) / 2) & 255;
                    if ((i + 1) / 2 < input.length) {
                        chr2 = input.charCodeAt((i + 1) / 2) >> 8;
                        chr3 = input.charCodeAt((i + 1) / 2) & 255;
                    }
                    else
                        chr2 = chr3 = NaN;
                }
                i += 3;
                enc1 = chr1 >> 2;
                enc2 = (chr1 & 3) << 4 | chr2 >> 4;
                enc3 = (chr2 & 15) << 2 | chr3 >> 6;
                enc4 = chr3 & 63;
                if (isNaN(chr2)) {
                    enc3 = enc4 = 64;
                }
                else if (isNaN(chr3)) {
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
        if (compressed.length > orig.length)
            compressed = orig;
        return "b" + compressed;
    }
    /*revert from compressed Base64 text to regular text*/
    function revertFrom(input) {
        if (input === null) {
            console.log("Decompression error1: Input is null");
            return "";
        }
        if (/^b/.test(input))
            input = input.replace(/^b/, "");
        else {
            //console.log("Decompression error2: Input is not base64 compressed >>> " + input);
            return null;
        }
        var output = "", ol = 0, output_ = 0, chr1, chr2, chr3, enc1, enc2, enc3, enc4, i = 0, f = String.fromCharCode;
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
            }
            else {
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
        ol = null;
        output_ = null;
        chr1 = null;
        chr2 = null;
        chr3 = null;
        enc1 = null;
        enc2 = null;
        enc3 = null;
        enc4 = null;
        //now decompress the data
        if (/^l/.test(output))
            var compressed = output.replace(/^l/, "");
        else
            return output.replace(/^n/, "");
        output = null;
        if (compressed === null) {
            console.log("Decompression error2: Reverted from Base64 value is null");
            return null;
        }
        if (compressed === "") {
            console.log('Decompression error3: Reverted from Base64 value is "" (Empty string)');
            return null;
        }
        var dictionary = [0, 1, 2, 3], enlargeIn = 4, dictSize = 4, numBits = 3, entry = "", result = "", w, bits = 0, resb, maxpower = 4, power = 1, c, data = { string: compressed, val: compressed.charCodeAt(0), position: 32768, index: 1 };
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
        switch (bits) {
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
            }
            else {
                if (c === dictSize && w) {
                    entry = w + w.charAt(0);
                }
                else {
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
    var bigInt = (function (undefined) {
        var BASE = 1e7, LOG_BASE = 7, MAX_INT = 9007199254740992, MAX_INT_ARR = smallToArray(MAX_INT), DEFAULT_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz";
        function Integer(v, radix, alphabet, caseSensitive) {
            if (typeof v === "undefined")
                return Integer[0];
            if (typeof radix !== "undefined")
                return +radix === 10 && !alphabet ? parseValue(v) : parseBase(v, radix, alphabet, caseSensitive);
            return parseValue(v);
        }
        function BigInteger(value, sign) {
            this.value = value;
            this.sign = sign;
            this.isSmall = false;
        }
        BigInteger.prototype = Object.create(Integer.prototype);
        function SmallInteger(value) {
            this.value = value;
            this.sign = value < 0;
            this.isSmall = true;
        }
        SmallInteger.prototype = Object.create(Integer.prototype);
        function isPrecise(n) {
            return -MAX_INT < n && n < MAX_INT;
        }
        function smallToArray(n) {
            if (n < 1e7)
                return [n];
            if (n < 1e14)
                return [n % 1e7, Math.floor(n / 1e7)];
            return [n % 1e7, Math.floor(n / 1e7) % 1e7, Math.floor(n / 1e14)];
        }
        function arrayToSmall(arr) {
            trim(arr);
            var length = arr.length;
            if (length < 4 && compareAbs(arr, MAX_INT_ARR) < 0) {
                switch (length) {
                    case 0: return 0;
                    case 1: return arr[0];
                    case 2: return arr[0] + arr[1] * BASE;
                    default: return arr[0] + (arr[1] + arr[2] * BASE) * BASE;
                }
            }
            return arr;
        }
        function trim(v) {
            var i = v.length;
            while (v[--i] === 0)
                ;
            v.length = i + 1;
        }
        function createArray(length) {
            var x = new Array(length);
            var i = -1;
            while (++i < length) {
                x[i] = 0;
            }
            return x;
        }
        function truncate(n) {
            if (n > 0)
                return Math.floor(n);
            return Math.ceil(n);
        }
        function add(a, b) {
            var l_a = a.length, l_b = b.length, r = new Array(l_a), carry = 0, base = BASE, sum, i;
            for (i = 0; i < l_b; i++) {
                sum = a[i] + b[i] + carry;
                carry = sum >= base ? 1 : 0;
                r[i] = sum - carry * base;
            }
            while (i < l_a) {
                sum = a[i] + carry;
                carry = sum === base ? 1 : 0;
                r[i++] = sum - carry * base;
            }
            if (carry > 0)
                r.push(carry);
            return r;
        }
        function addAny(a, b) {
            if (a.length >= b.length)
                return add(a, b);
            return add(b, a);
        }
        function addSmall(a, carry) {
            var l = a.length, r = new Array(l), base = BASE, sum, i;
            for (i = 0; i < l; i++) {
                sum = a[i] - base + carry;
                carry = Math.floor(sum / base);
                r[i] = sum - carry * base;
                carry += 1;
            }
            while (carry > 0) {
                r[i++] = carry % base;
                carry = Math.floor(carry / base);
            }
            return r;
        }
        BigInteger.prototype.add = function (v) {
            var n = parseValue(v);
            if (this.sign !== n.sign) {
                return this.subtract(n.negate());
            }
            var a = this.value, b = n.value;
            if (n.isSmall) {
                return new BigInteger(addSmall(a, Math.abs(b)), this.sign);
            }
            return new BigInteger(addAny(a, b), this.sign);
        };
        BigInteger.prototype.plus = BigInteger.prototype.add;
        SmallInteger.prototype.add = function (v) {
            var n = parseValue(v);
            var a = this.value;
            if (a < 0 !== n.sign) {
                return this.subtract(n.negate());
            }
            var b = n.value;
            if (n.isSmall) {
                if (isPrecise(a + b))
                    return new SmallInteger(a + b);
                b = smallToArray(Math.abs(b));
            }
            return new BigInteger(addSmall(b, Math.abs(a)), a < 0);
        };
        SmallInteger.prototype.plus = SmallInteger.prototype.add;
        function subtract(a, b) {
            var a_l = a.length, b_l = b.length, r = new Array(a_l), borrow = 0, base = BASE, i, difference;
            for (i = 0; i < b_l; i++) {
                difference = a[i] - borrow - b[i];
                if (difference < 0) {
                    difference += base;
                    borrow = 1;
                }
                else
                    borrow = 0;
                r[i] = difference;
            }
            for (i = b_l; i < a_l; i++) {
                difference = a[i] - borrow;
                if (difference < 0)
                    difference += base;
                else {
                    r[i++] = difference;
                    break;
                }
                r[i] = difference;
            }
            for (; i < a_l; i++) {
                r[i] = a[i];
            }
            trim(r);
            return r;
        }
        function subtractAny(a, b, sign) {
            var value;
            if (compareAbs(a, b) >= 0) {
                value = subtract(a, b);
            }
            else {
                value = subtract(b, a);
                sign = !sign;
            }
            value = arrayToSmall(value);
            if (typeof value === "number") {
                if (sign)
                    value = -value;
                return new SmallInteger(value);
            }
            return new BigInteger(value, sign);
        }
        function subtractSmall(a, b, sign) {
            var l = a.length, r = new Array(l), carry = -b, base = BASE, i, difference;
            for (i = 0; i < l; i++) {
                difference = a[i] + carry;
                carry = Math.floor(difference / base);
                difference %= base;
                r[i] = difference < 0 ? difference + base : difference;
            }
            r = arrayToSmall(r);
            if (typeof r === "number") {
                if (sign)
                    r = -r;
                return new SmallInteger(r);
            }
            return new BigInteger(r, sign);
        }
        BigInteger.prototype.subtract = function (v) {
            var n = parseValue(v);
            if (this.sign !== n.sign) {
                return this.add(n.negate());
            }
            var a = this.value, b = n.value;
            if (n.isSmall)
                return subtractSmall(a, Math.abs(b), this.sign);
            return subtractAny(a, b, this.sign);
        };
        BigInteger.prototype.minus = BigInteger.prototype.subtract;
        SmallInteger.prototype.subtract = function (v) {
            var n = parseValue(v);
            var a = this.value;
            if (a < 0 !== n.sign) {
                return this.add(n.negate());
            }
            var b = n.value;
            if (n.isSmall) {
                return new SmallInteger(a - b);
            }
            return subtractSmall(b, Math.abs(a), a >= 0);
        };
        SmallInteger.prototype.minus = SmallInteger.prototype.subtract;
        BigInteger.prototype.negate = function () {
            return new BigInteger(this.value, !this.sign);
        };
        SmallInteger.prototype.negate = function () {
            var sign = this.sign;
            var small = new SmallInteger(-this.value);
            small.sign = !sign;
            return small;
        };
        BigInteger.prototype.abs = function () {
            return new BigInteger(this.value, false);
        };
        SmallInteger.prototype.abs = function () {
            return new SmallInteger(Math.abs(this.value));
        };
        function multiplyLong(a, b) {
            var a_l = a.length, b_l = b.length, l = a_l + b_l, r = createArray(l), base = BASE, product, carry, i, a_i, b_j;
            for (i = 0; i < a_l; ++i) {
                a_i = a[i];
                for (var j = 0; j < b_l; ++j) {
                    b_j = b[j];
                    product = a_i * b_j + r[i + j];
                    carry = Math.floor(product / base);
                    r[i + j] = product - carry * base;
                    r[i + j + 1] += carry;
                }
            }
            trim(r);
            return r;
        }
        function multiplySmall(a, b) {
            var l = a.length, r = new Array(l), base = BASE, carry = 0, product, i;
            for (i = 0; i < l; i++) {
                product = a[i] * b + carry;
                carry = Math.floor(product / base);
                r[i] = product - carry * base;
            }
            while (carry > 0) {
                r[i++] = carry % base;
                carry = Math.floor(carry / base);
            }
            return r;
        }
        function shiftLeft(x, n) {
            var r = [];
            while (n-- > 0)
                r.push(0);
            return r.concat(x);
        }
        function multiplyKaratsuba(x, y) {
            var n = Math.max(x.length, y.length);
            if (n <= 30)
                return multiplyLong(x, y);
            n = Math.ceil(n / 2);
            var b = x.slice(n), a = x.slice(0, n), d = y.slice(n), c = y.slice(0, n);
            var ac = multiplyKaratsuba(a, c), bd = multiplyKaratsuba(b, d), abcd = multiplyKaratsuba(addAny(a, b), addAny(c, d));
            var product = addAny(addAny(ac, shiftLeft(subtract(subtract(abcd, ac), bd), n)), shiftLeft(bd, 2 * n));
            trim(product);
            return product;
        }
        // The following function is derived from a surface fit of a graph plotting the performance difference
        // between long multiplication and karatsuba multiplication versus the lengths of the two arrays.
        function useKaratsuba(l1, l2) {
            return -0.012 * l1 - 0.012 * l2 + 0.000015 * l1 * l2 > 0;
        }
        BigInteger.prototype.multiply = function (v) {
            var n = parseValue(v), a = this.value, b = n.value, sign = this.sign !== n.sign, abs;
            if (n.isSmall) {
                if (b === 0)
                    return Integer[0];
                if (b === 1)
                    return this;
                if (b === -1)
                    return this.negate();
                abs = Math.abs(b);
                if (abs < BASE) {
                    return new BigInteger(multiplySmall(a, abs), sign);
                }
                b = smallToArray(abs);
            }
            if (useKaratsuba(a.length, b.length)) // Karatsuba is only faster for certain array sizes
                return new BigInteger(multiplyKaratsuba(a, b), sign);
            return new BigInteger(multiplyLong(a, b), sign);
        };
        BigInteger.prototype.times = BigInteger.prototype.multiply;
        function multiplySmallAndArray(a, b, sign) {
            if (a < BASE) {
                return new BigInteger(multiplySmall(b, a), sign);
            }
            return new BigInteger(multiplyLong(b, smallToArray(a)), sign);
        }
        SmallInteger.prototype._multiplyBySmall = function (a) {
            if (isPrecise(a.value * this.value)) {
                return new SmallInteger(a.value * this.value);
            }
            return multiplySmallAndArray(Math.abs(a.value), smallToArray(Math.abs(this.value)), this.sign !== a.sign);
        };
        BigInteger.prototype._multiplyBySmall = function (a) {
            if (a.value === 0)
                return Integer[0];
            if (a.value === 1)
                return this;
            if (a.value === -1)
                return this.negate();
            return multiplySmallAndArray(Math.abs(a.value), this.value, this.sign !== a.sign);
        };
        SmallInteger.prototype.multiply = function (v) {
            return parseValue(v)._multiplyBySmall(this);
        };
        SmallInteger.prototype.times = SmallInteger.prototype.multiply;
        function square(a) {
            //console.assert(2 * BASE * BASE < MAX_INT);
            var l = a.length, r = createArray(l + l), base = BASE, product, carry, i, a_i, a_j;
            for (i = 0; i < l; i++) {
                a_i = a[i];
                carry = 0 - a_i * a_i;
                for (var j = i; j < l; j++) {
                    a_j = a[j];
                    product = 2 * (a_i * a_j) + r[i + j] + carry;
                    carry = Math.floor(product / base);
                    r[i + j] = product - carry * base;
                }
                r[i + l] = carry;
            }
            trim(r);
            return r;
        }
        BigInteger.prototype.square = function () {
            return new BigInteger(square(this.value), false);
        };
        SmallInteger.prototype.square = function () {
            var value = this.value * this.value;
            if (isPrecise(value))
                return new SmallInteger(value);
            return new BigInteger(square(smallToArray(Math.abs(this.value))), false);
        };
        function divMod1(a, b) {
            var a_l = a.length, b_l = b.length, base = BASE, result = createArray(b.length), divisorMostSignificantDigit = b[b_l - 1], 
            // normalization
            lambda = Math.ceil(base / (2 * divisorMostSignificantDigit)), remainder = multiplySmall(a, lambda), divisor = multiplySmall(b, lambda), quotientDigit, shift, carry, borrow, i, l, q;
            if (remainder.length <= a_l)
                remainder.push(0);
            divisor.push(0);
            divisorMostSignificantDigit = divisor[b_l - 1];
            for (shift = a_l - b_l; shift >= 0; shift--) {
                quotientDigit = base - 1;
                if (remainder[shift + b_l] !== divisorMostSignificantDigit) {
                    quotientDigit = Math.floor((remainder[shift + b_l] * base + remainder[shift + b_l - 1]) / divisorMostSignificantDigit);
                }
                // quotientDigit <= base - 1
                carry = 0;
                borrow = 0;
                l = divisor.length;
                for (i = 0; i < l; i++) {
                    carry += quotientDigit * divisor[i];
                    q = Math.floor(carry / base);
                    borrow += remainder[shift + i] - (carry - q * base);
                    carry = q;
                    if (borrow < 0) {
                        remainder[shift + i] = borrow + base;
                        borrow = -1;
                    }
                    else {
                        remainder[shift + i] = borrow;
                        borrow = 0;
                    }
                }
                while (borrow !== 0) {
                    quotientDigit -= 1;
                    carry = 0;
                    for (i = 0; i < l; i++) {
                        carry += remainder[shift + i] - base + divisor[i];
                        if (carry < 0) {
                            remainder[shift + i] = carry + base;
                            carry = 0;
                        }
                        else {
                            remainder[shift + i] = carry;
                            carry = 1;
                        }
                    }
                    borrow += carry;
                }
                result[shift] = quotientDigit;
            }
            // denormalization
            remainder = divModSmall(remainder, lambda)[0];
            return [arrayToSmall(result), arrayToSmall(remainder)];
        }
        function divMod2(a, b) {
            // Performs faster than divMod1 on larger input sizes.
            var a_l = a.length, b_l = b.length, result = [], part = [], base = BASE, guess, xlen, highx, highy, check;
            while (a_l) {
                part.unshift(a[--a_l]);
                trim(part);
                if (compareAbs(part, b) < 0) {
                    result.push(0);
                    continue;
                }
                xlen = part.length;
                highx = part[xlen - 1] * base + part[xlen - 2];
                highy = b[b_l - 1] * base + b[b_l - 2];
                if (xlen > b_l) {
                    highx = (highx + 1) * base;
                }
                guess = Math.ceil(highx / highy);
                do {
                    check = multiplySmall(b, guess);
                    if (compareAbs(check, part) <= 0)
                        break;
                    guess--;
                } while (guess);
                result.push(guess);
                part = subtract(part, check);
            }
            result.reverse();
            return [arrayToSmall(result), arrayToSmall(part)];
        }
        function divModSmall(value, lambda) {
            var length = value.length, quotient = createArray(length), base = BASE, i, q, remainder, divisor;
            remainder = 0;
            for (i = length - 1; i >= 0; --i) {
                divisor = remainder * base + value[i];
                q = truncate(divisor / lambda);
                remainder = divisor - q * lambda;
                quotient[i] = q | 0;
            }
            return [quotient, remainder | 0];
        }
        function divModAny(self, v) {
            var value, n = parseValue(v);
            var a = self.value, b = n.value;
            var quotient;
            if (b === 0)
                throw new Error("Cannot divide by zero");
            if (self.isSmall) {
                if (n.isSmall) {
                    return [new SmallInteger(truncate(a / b)), new SmallInteger(a % b)];
                }
                return [Integer[0], self];
            }
            if (n.isSmall) {
                if (b === 1)
                    return [self, Integer[0]];
                if (b == -1)
                    return [self.negate(), Integer[0]];
                var abs = Math.abs(b);
                if (abs < BASE) {
                    value = divModSmall(a, abs);
                    quotient = arrayToSmall(value[0]);
                    var remainder = value[1];
                    if (self.sign)
                        remainder = -remainder;
                    if (typeof quotient === "number") {
                        if (self.sign !== n.sign)
                            quotient = -quotient;
                        return [new SmallInteger(quotient), new SmallInteger(remainder)];
                    }
                    return [new BigInteger(quotient, self.sign !== n.sign), new SmallInteger(remainder)];
                }
                b = smallToArray(abs);
            }
            var comparison = compareAbs(a, b);
            if (comparison === -1)
                return [Integer[0], self];
            if (comparison === 0)
                return [Integer[self.sign === n.sign ? 1 : -1], Integer[0]];
            // divMod1 is faster on smaller input sizes
            if (a.length + b.length <= 200)
                value = divMod1(a, b);
            else
                value = divMod2(a, b);
            quotient = value[0];
            var qSign = self.sign !== n.sign, mod = value[1], mSign = self.sign;
            if (typeof quotient === "number") {
                if (qSign)
                    quotient = -quotient;
                quotient = new SmallInteger(quotient);
            }
            else
                quotient = new BigInteger(quotient, qSign);
            if (typeof mod === "number") {
                if (mSign)
                    mod = -mod;
                mod = new SmallInteger(mod);
            }
            else
                mod = new BigInteger(mod, mSign);
            return [quotient, mod];
        }
        BigInteger.prototype.divmod = function (v) {
            var result = divModAny(this, v);
            return {
                quotient: result[0],
                remainder: result[1]
            };
        };
        SmallInteger.prototype.divmod = BigInteger.prototype.divmod;
        BigInteger.prototype.divide = function (v) {
            return divModAny(this, v)[0];
        };
        SmallInteger.prototype.over = SmallInteger.prototype.divide = BigInteger.prototype.over = BigInteger.prototype.divide;
        BigInteger.prototype.mod = function (v) {
            return divModAny(this, v)[1];
        };
        SmallInteger.prototype.remainder = SmallInteger.prototype.mod = BigInteger.prototype.remainder = BigInteger.prototype.mod;
        BigInteger.prototype.modPow = function (exp, mod) {
            exp = parseValue(exp);
            mod = parseValue(mod);
            if (mod.isZero())
                throw new Error("Cannot take modPow with modulus 0");
            var r = Integer[1], base = this.mod(mod);
            while (exp.isPositive()) {
                if (base.isZero())
                    return Integer[0];
                if (exp.isOdd())
                    r = r.multiply(base).mod(mod);
                exp = exp.divide(2);
                base = base.square().mod(mod);
            }
            return r;
        };
        SmallInteger.prototype.modPow = BigInteger.prototype.modPow;
        function compareAbs(a, b) {
            if (a.length !== b.length) {
                return a.length > b.length ? 1 : -1;
            }
            for (var i = a.length - 1; i >= 0; i--) {
                if (a[i] !== b[i])
                    return a[i] > b[i] ? 1 : -1;
            }
            return 0;
        }
        BigInteger.prototype.compareAbs = function (v) {
            var n = parseValue(v), a = this.value, b = n.value;
            if (n.isSmall)
                return 1;
            return compareAbs(a, b);
        };
        SmallInteger.prototype.compareAbs = function (v) {
            var n = parseValue(v), a = Math.abs(this.value), b = n.value;
            if (n.isSmall) {
                b = Math.abs(b);
                return a === b ? 0 : a > b ? 1 : -1;
            }
            return -1;
        };
        BigInteger.prototype.compare = function (v) {
            // See discussion about comparison with Infinity:
            // https://github.com/peterolson/BigInteger.js/issues/61
            if (v === Infinity) {
                return -1;
            }
            if (v === -Infinity) {
                return 1;
            }
            var n = parseValue(v), a = this.value, b = n.value;
            if (this.sign !== n.sign) {
                return n.sign ? 1 : -1;
            }
            if (n.isSmall) {
                return this.sign ? -1 : 1;
            }
            return compareAbs(a, b) * (this.sign ? -1 : 1);
        };
        BigInteger.prototype.compareTo = BigInteger.prototype.compare;
        SmallInteger.prototype.compare = function (v) {
            if (v === Infinity) {
                return -1;
            }
            if (v === -Infinity) {
                return 1;
            }
            var n = parseValue(v), a = this.value, b = n.value;
            if (n.isSmall) {
                return a == b ? 0 : a > b ? 1 : -1;
            }
            if (a < 0 !== n.sign) {
                return a < 0 ? -1 : 1;
            }
            return a < 0 ? 1 : -1;
        };
        SmallInteger.prototype.compareTo = SmallInteger.prototype.compare;
        BigInteger.prototype.equals = function (v) {
            return this.compare(v) === 0;
        };
        SmallInteger.prototype.eq = SmallInteger.prototype.equals = BigInteger.prototype.eq = BigInteger.prototype.equals;
        BigInteger.prototype.isOdd = function () {
            return (this.value[0] & 1) === 1;
        };
        SmallInteger.prototype.isOdd = function () {
            return (this.value & 1) === 1;
        };
        BigInteger.prototype.isPositive = function () {
            return !this.sign;
        };
        SmallInteger.prototype.isPositive = function () {
            return this.value > 0;
        };
        BigInteger.prototype.isNegative = function () {
            return this.sign;
        };
        SmallInteger.prototype.isNegative = function () {
            return this.value < 0;
        };
        BigInteger.prototype.isUnit = function () {
            return false;
        };
        SmallInteger.prototype.isUnit = function () {
            return Math.abs(this.value) === 1;
        };
        BigInteger.prototype.isZero = function () {
            return false;
        };
        SmallInteger.prototype.isZero = function () {
            return this.value === 0;
        };
        BigInteger.prototype.next = function () {
            var value = this.value;
            if (this.sign) {
                return subtractSmall(value, 1, this.sign);
            }
            return new BigInteger(addSmall(value, 1), this.sign);
        };
        SmallInteger.prototype.next = function () {
            var value = this.value;
            if (value + 1 < MAX_INT)
                return new SmallInteger(value + 1);
            return new BigInteger(MAX_INT_ARR, false);
        };
        var parseBase = function (text, base, alphabet, caseSensitive) {
            alphabet = alphabet || DEFAULT_ALPHABET;
            text = String(text);
            if (!caseSensitive) {
                text = text.toLowerCase();
                alphabet = alphabet.toLowerCase();
            }
            var length = text.length;
            var i;
            var absBase = Math.abs(base);
            var alphabetValues = {};
            for (i = 0; i < alphabet.length; i++) {
                alphabetValues[alphabet[i]] = i;
            }
            for (i = 0; i < length; i++) {
                var c = text[i];
                if (c === "-")
                    continue;
                if (c in alphabetValues) {
                    if (alphabetValues[c] >= absBase) {
                        if (c === "1" && absBase === 1)
                            continue;
                        throw new Error(c + " is not a valid digit in base " + base + ".");
                    }
                }
            }
            base = parseValue(base);
            var digits = [];
            var isNegative = text[0] === "-";
            for (i = isNegative ? 1 : 0; i < text.length; i++) {
                var c = text[i];
                if (c in alphabetValues)
                    digits.push(parseValue(alphabetValues[c]));
                else if (c === "<") {
                    var start = i;
                    do {
                        i++;
                    } while (text[i] !== ">" && i < text.length);
                    digits.push(parseValue(text.slice(start + 1, i)));
                }
                else
                    throw new Error(c + " is not a valid character");
            }
            return parseBaseFromArray(digits, base, isNegative);
        };
        function parseBaseFromArray(digits, base, isNegative) {
            var val = Integer[0], pow = Integer[1], i;
            for (i = digits.length - 1; i >= 0; i--) {
                val = val.add(digits[i].times(pow));
                pow = pow.times(base);
            }
            return isNegative ? val.negate() : val;
        }
        function stringify(digit, alphabet) {
            alphabet = alphabet || DEFAULT_ALPHABET;
            if (digit < alphabet.length) {
                return alphabet[digit];
            }
            return "<" + digit + ">";
        }
        function toBase(n, base) {
            base = bigInt(base);
            if (base.isZero()) {
                if (n.isZero())
                    return { value: [0], isNegative: false };
                throw new Error("Cannot convert nonzero numbers to base 0.");
            }
            if (base.equals(-1)) {
                if (n.isZero())
                    return { value: [0], isNegative: false };
                if (n.isNegative())
                    return {
                        value: [].concat.apply([], Array.apply(null, Array(-n.toJSNumber()))
                            .map(Array.prototype.valueOf, [1, 0])),
                        isNegative: false
                    };
                var arr = Array.apply(null, Array(n.toJSNumber() - 1))
                    .map(Array.prototype.valueOf, [0, 1]);
                arr.unshift([1]);
                return {
                    value: [].concat.apply([], arr),
                    isNegative: false
                };
            }
            var neg = false;
            if (n.isNegative() && base.isPositive()) {
                neg = true;
                n = n.abs();
            }
            if (base.isUnit()) {
                if (n.isZero())
                    return { value: [0], isNegative: false };
                return {
                    value: Array.apply(null, Array(n.toJSNumber()))
                        .map(Number.prototype.valueOf, 1),
                    isNegative: neg
                };
            }
            var out = [];
            var left = n, divmod;
            while (left.isNegative() || left.compareAbs(base) >= 0) {
                divmod = left.divmod(base);
                left = divmod.quotient;
                var digit = divmod.remainder;
                if (digit.isNegative()) {
                    digit = base.minus(digit).abs();
                    left = left.next();
                }
                out.push(digit.toJSNumber());
            }
            out.push(left.toJSNumber());
            return { value: out.reverse(), isNegative: neg };
        }
        function toBaseString(n, base, alphabet) {
            var arr = toBase(n, base);
            return (arr.isNegative ? "-" : "") + arr.value.map(function (x) {
                return stringify(x, alphabet);
            }).join('');
        }
        BigInteger.prototype.toString = function (radix, alphabet) {
            if (radix === undefined)
                radix = 10;
            if (radix !== 10)
                return toBaseString(this, radix, alphabet);
            var v = this.value, l = v.length, str = String(v[--l]), zeros = "0000000", digit;
            while (--l >= 0) {
                digit = String(v[l]);
                str += zeros.slice(digit.length) + digit;
            }
            var sign = this.sign ? "-" : "";
            return sign + str;
        };
        SmallInteger.prototype.toString = function (radix, alphabet) {
            if (radix === undefined)
                radix = 10;
            if (radix != 10)
                return toBaseString(this, radix, alphabet);
            return String(this.value);
        };
        BigInteger.prototype.valueOf = function () {
            return parseInt(this.toString(), 10);
        };
        BigInteger.prototype.toJSNumber = BigInteger.prototype.valueOf;
        SmallInteger.prototype.valueOf = function () {
            return this.value;
        };
        SmallInteger.prototype.toJSNumber = SmallInteger.prototype.valueOf;
        function parseStringValue(v) {
            if (isPrecise(+v)) {
                var x = +v;
                if (x === truncate(x))
                    return new SmallInteger(x);
                throw new Error("Invalid integer: " + v);
            }
            var sign = v[0] === "-";
            if (sign)
                v = v.slice(1);
            var split = v.split(/e/i);
            if (split.length > 2)
                throw new Error("Invalid integer: " + split.join("e"));
            if (split.length === 2) {
                var exp = split[1];
                if (exp[0] === "+")
                    exp = exp.slice(1);
                exp = +exp;
                if (exp !== truncate(exp) || !isPrecise(exp))
                    throw new Error("Invalid integer: " + exp + " is not a valid exponent.");
                var text = split[0];
                var decimalPlace = text.indexOf(".");
                if (decimalPlace >= 0) {
                    exp -= text.length - decimalPlace - 1;
                    text = text.slice(0, decimalPlace) + text.slice(decimalPlace + 1);
                }
                if (exp < 0)
                    throw new Error("Cannot include negative exponent part for integers");
                text += (new Array(exp + 1)).join("0");
                v = text;
            }
            var isValid = /^([0-9][0-9]*)$/.test(v);
            if (!isValid)
                throw new Error("Invalid integer: " + v);
            var r = [], max = v.length, l = LOG_BASE, min = max - l;
            while (max > 0) {
                r.push(+v.slice(min, max));
                min -= l;
                if (min < 0)
                    min = 0;
                max -= l;
            }
            trim(r);
            return new BigInteger(r, sign);
        }
        function parseNumberValue(v) {
            if (isPrecise(v)) {
                if (v !== truncate(v))
                    throw new Error(v + " is not an integer.");
                return new SmallInteger(v);
            }
            return parseStringValue(v.toString());
        }
        function parseValue(v) {
            if (typeof v === "number") {
                return parseNumberValue(v);
            }
            if (typeof v === "string") {
                return parseStringValue(v);
            }
            return v;
        }
        // Pre-define numbers in range [-999,999]
        for (var i = 0; i < 1000; i++) {
            Integer[i] = parseValue(i);
            if (i > 0)
                Integer[-i] = parseValue(-i);
        }
        return Integer;
    })();
    function sha256(str) {
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
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ];
        var s = unescape(encodeURIComponent(str)); // UTF-8
        var i;
        var arr = new Uint8Array(s.length);
        for (i = 0; i < s.length; i++) {
            arr[i] = s.charCodeAt(i) & 0xff;
        }
        var length = arr.length;
        var byteLength = Math.floor((length + 72) / 64) * 64;
        var wordLength = byteLength / 4;
        var bitLength = length * 8;
        var m = new Uint8Array(byteLength);
        if (typeof Uint8Array !== 'undefined' && !Array.isArray(m)) {
            m.set(arr);
        }
        else {
            for (i = 0; i < arr.length; i++) {
                m[i] = arr[i];
            }
            for (i = arr.length; i < m.length; i++) {
                m[i] = 0;
            }
        }
        m[length] = 0x80;
        m[byteLength - 4] = bitLength >>> 24;
        m[byteLength - 3] = (bitLength >>> 16) & 0xff;
        m[byteLength - 2] = (bitLength >>> 8) & 0xff;
        m[byteLength - 1] = bitLength & 0xff;
        var words = new Int32Array(wordLength);
        var byteIndex = 0;
        var word;
        for (i = 0; i < words.length; i++) {
            word = m[byteIndex] << 24;
            word |= m[byteIndex + 1] << 16;
            word |= m[byteIndex + 2] << 8;
            word |= m[byteIndex + 3];
            words[i] = word;
            byteIndex += 4;
        }
        word = null;
        byteIndex = null;
        var w = new Int32Array(64);
        var v;
        var s0;
        var s1;
        var a;
        var b;
        var c;
        var d;
        var e;
        var f;
        var g;
        var h;
        var ch;
        var temp1;
        var temp2;
        var maj;
        for (var j = 0; j < wordLength; j += 16) {
            for (i = 0; i < 16; i++) {
                w[i] = words[j + i];
            }
            for (i = 16; i < 64; i++) {
                v = w[i - 15];
                s0 = (v >>> 7) | (v << 25);
                s0 ^= (v >>> 18) | (v << 14);
                s0 ^= (v >>> 3);
                v = w[i - 2];
                s1 = (v >>> 17) | (v << 15);
                s1 ^= (v >>> 19) | (v << 13);
                s1 ^= (v >>> 10);
                w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff;
            }
            a = h0;
            b = h1;
            c = h2;
            d = h3;
            e = h4;
            f = h5;
            g = h6;
            h = h7;
            for (i = 0; i < 64; i++) {
                s1 = (e >>> 6) | (e << 26);
                s1 ^= (e >>> 11) | (e << 21);
                s1 ^= (e >>> 25) | (e << 7);
                ch = (e & f) ^ (~e & g);
                temp1 = (h + s1 + ch + K[i] + w[i]) & 0xffffffff;
                s0 = (a >>> 2) | (a << 30);
                s0 ^= (a >>> 13) | (a << 19);
                s0 ^= (a >>> 22) | (a << 10);
                maj = (a & b) ^ (a & c) ^ (b & c);
                temp2 = (s0 + maj) & 0xffffffff;
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
        var hash = new Uint8Array(32);
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
        return hash;
    }
    /*creates a Diffie Hellman Merkle session key from your own secret private key and someone elses public key*/
    function getSessionKey(privateKey, publicKey) {
        return bigInt(publicKey).modPow(b64.number_hash(privateKey, 100), prime).toString();
    }
    b64.atob = function (str) {
        function fromUtf8(str) {
            var position = -1, len, buffer = [], enc = [0, 0, 0, 0];
            if (!lookup) {
                len = charset.length;
                lookup = {};
                while (++position < len)
                    lookup[charset.charAt(position)] = position;
                position = -1;
            }
            len = str.length;
            while (++position < len) {
                enc[0] = lookup[str.charAt(position)];
                enc[1] = lookup[str.charAt(++position)];
                buffer.push((enc[0] << 2) | (enc[1] >> 4));
                enc[2] = lookup[str.charAt(++position)];
                if (enc[2] === 64)
                    break;
                buffer.push(((enc[1] & 15) << 4) | (enc[2] >> 2));
                enc[3] = lookup[str.charAt(++position)];
                if (enc[3] === 64)
                    break;
                buffer.push(((enc[2] & 3) << 6) | enc[3]);
            }
            return buffer;
        }
        var lookup = null;
        if (str.length % 4)
            throw new Error("InvalidCharacterError: 'Base64.atob' failed: The string to be decoded is not correctly encoded.");
        var buffer = fromUtf8(str), position = 0, len = buffer.length;
        var result = '';
        while (position < len) {
            if (buffer[position] < 128)
                result += String.fromCharCode(buffer[position++]);
            else if (buffer[position] > 191 && buffer[position] < 224)
                result += String.fromCharCode(((buffer[position++] & 31) << 6) | (buffer[position++] & 63));
            else
                result += String.fromCharCode(((buffer[position++] & 15) << 12) | ((buffer[position++] & 63) << 6) | (buffer[position++] & 63));
        }
        return result;
    };
    b64.btoa = function (s) {
        function toUtf8(s) {
            var position = -1, len = s.length, chr, buffer = [];
            if (/^[\x00-\x7f]*$/.test(s))
                while (++position < len)
                    buffer.push(s.charCodeAt(position));
            else
                while (++position < len) {
                    chr = s.charCodeAt(position);
                    if (chr < 128)
                        buffer.push(chr);
                    else if (chr < 2048)
                        buffer.push((chr >> 6) | 192, (chr & 63) | 128);
                    else
                        buffer.push((chr >> 12) | 224, ((chr >> 6) & 63) | 128, (chr & 63) | 128);
                }
            return buffer;
        }
        var buffer = toUtf8(s), position = -1, len = buffer.length, nan0, nan1, nan2, enc = [0, 0, 0, 0];
        var result = '';
        while (++position < len) {
            nan0 = buffer[position];
            nan1 = buffer[++position];
            enc[0] = nan0 >> 2;
            enc[1] = ((nan0 & 3) << 4) | (nan1 >> 4);
            if (isNaN(nan1))
                enc[2] = enc[3] = 64;
            else {
                nan2 = buffer[++position];
                enc[2] = ((nan1 & 15) << 2) | (nan2 >> 6);
                enc[3] = (isNaN(nan2)) ? 64 : nan2 & 63;
            }
            result += charset[enc[0]] + charset[enc[1]] + charset[enc[2]] + charset[enc[3]];
        }
        return result;
    };
    b64.number_hash = function (str, requiredLength) {
        requiredLength = requiredLength && !isNaN(requiredLength) && isFinite(requiredLength) && requiredLength > 0 ? requiredLength : 10;
        var out = "";
        for (var a = 0, h = 0, s = "", i = void 0, chr = void 0, len = void 0; out.length < requiredLength; a++) {
            for (i = 0, len = str.length; i < len; i++) {
                chr = str.charCodeAt(i);
                h = (h << 5) - h + chr;
                h |= 0; // Convert to 32bit integer
            }
            s = String(h + Math.pow(2, 31));
            while (s.length < 10)
                s = "0" + h;
            out += s.slice(2);
        }
        return out.slice(0, requiredLength);
    };
    b64.rand = function (requiredLength, additionalEntropy) {
        function random12Digit() {
            return String(Math.floor(Math.random() * (((Math.pow(10, 16)) - 1) - Math.pow(10, 15) + 1) + Math.pow(10, 15))).slice(3, 15);
        }
        var len = requiredLength && !isNaN(requiredLength) && isFinite(requiredLength) && requiredLength > 0 ? requiredLength : 8, ent = additionalEntropy ? String(additionalEntropy) : random12Digit(), num = 0, str = "", out = "";
        if (len > 300)
            len = 300; //physical limit
        while (out.length < len) {
            num = Number(random12Digit());
            for (var b = 0; b < 4300; b++)
                num += Number(String(new Date().getTime()).slice(7)); //generate 32 bits of entropy
            str = String(num);
            while (str.charAt(0) === "0" && str.length > 1)
                str = str.slice(1);
            str = b64.number_hash(ent + str, 8); //generate 32 bit number from 32 bits of entropy (plus additionalEntropy)
            out += str; //string all the numbers together to form required length
        }
        while (out.charAt(0) === "0" && out.length > 1)
            out = out.slice(1);
        //in some cases during the last round through the "while" statement a number starting with 3 or more 0's will be chosen which results in too short an output number
        if (out.length < len)
            return b64.rand(len, ent + random12Digit()); //try again
        return out.slice(0, len);
    };
    b64.hash = function (message, salt) {
        message = message ? message : "";
        if (salt)
            message = String(salt) + String(message);
        else
            message = String(message.length + 1231) + String(message);
        return toHex(sha256(message));
    };
    b64.hmac = function (message, key) {
        key = String(key);
        var k;
        if (key.length > 32)
            k = sha256(key);
        else {
            var s = unescape(encodeURIComponent(key)); // UTF-8
            k = new Uint8Array(32);
            for (var i = 0; i < s.length; i++) {
                k[i] = s.charCodeAt(i);
            }
        }
        for (var i = 0; i < k.length; i++) {
            k[i] ^= 0x36;
        }
        var inner = toHex(sha256(toHex(k)));
        for (var i = 0; i < k.length; i++) {
            k[i] ^= 0x36 ^ 0x5c;
        }
        return b64.hash(String(message), toHex(k) + inner);
    };
    b64.write = function (str, key) {
        if (str == null)
            return "";
        str = String(str);
        str = convertTo(str);
        if (key) {
            var a, b = [], c = charset, d = b64.hash(key), e, f = c + c + c + c + c;
            for (a = 0, e = 0; a < str.length; a++, e = e === String(d).length - 1 ? 0 : e + 1)
                b[a] = f[c.indexOf(str[a]) + c.indexOf(String(d)[e]) * 4];
            str = "d" + b.join("");
            a = null;
            b = null;
            c = null;
            d = null;
            e = null;
            f = null;
            key = null;
        }
        return str;
    };
    b64.read = function (str, key) {
        if (str == null)
            return "";
        str = String(str);
        if (key && /^d/.test(str)) {
            str = str.replace(/^d/, "");
            var a = str.length, b = [], c = charset, d = b64.hash(key), e, f = c + c + c + c + c, g, h = String(d).length, i = c.length;
            for (g = 0, e = 0; g < a; g++, e = e === h - 1 ? 0 : e + 1)
                b[g] = f[c.indexOf(str[g]) + i * 4 - c.indexOf(String(d)[e]) * 4];
            str = b.join("");
            key = null;
            a = null;
            b = null;
            c = null;
            d = null;
            e = null;
            f = null;
            g = null;
        }
        return revertFrom(str);
    };
    b64.write_and_verify = function (str, key) {
        function locateTextDifferences(str1, str2) {
            var diff = [], d = 1;
            if (str2 === null)
                return "Decompressing the string returned null. Possibly invalid key used??";
            var len1 = str1.length, len2 = str2.length;
            if (len1 !== len2)
                diff[0] = "Strings are not the same length. String 1: " + len1 + " characters. String 2: " + len2 + " characters.";
            else
                diff[0] = "Entire text length: " + len1 + " characters";
            for (var a = 0; a < len1 && a < len2; a++) {
                if (str1.charAt(a) !== str2.charAt(a)) {
                    diff[d] = "Char " + (a + 1) + ": ASCII " + str1.charCodeAt(a) + " not equal to ";
                    diff[d] = diff[d] + "ASCII " + str2.charCodeAt(a) + ".";
                    diff[d] = diff[d] + "Surrounding text: " + str1.slice(a - 10, a + 10);
                    d++;
                }
            }
            if (d === 1)
                return false;
            else
                return diff.join("<br />");
        }
        /*for debugging the write/read functions*/
        var orig = str;
        str = b64.write(str, key);
        if (b64.read(str, key) !== orig)
            return "Write error! Aborted operation. " + locateTextDifferences(orig, b64.read(str, key));
        else
            return str;
    };
    b64.createPublicKey = function (myPrivateKey) {
        myPrivateKey = b64.number_hash(myPrivateKey, 100);
        var ret = bigInt("32416178251").modPow(myPrivateKey, prime).toString();
        return ret;
    };
    b64.createUserKey = function (userPublicKey, masterKey) { return b64.write("key:" + masterKey, getSessionKey(masterKey, userPublicKey)); };
    b64.createUserKey_and_verify = function (userPrivateKey, masterKey) {
        //create public keys
        var mainPublicKey = b64.createPublicKey(masterKey), userPublicKey = b64.createPublicKey(userPrivateKey);
        //verify public keys work
        var usersSessionKey = getSessionKey(userPrivateKey, mainPublicKey), mainSessionKey = getSessionKey(masterKey, userPublicKey);
        if (usersSessionKey !== mainSessionKey)
            throw new Error("Public/Private key creation error");
        //create userKey from masterKey with common session key
        var userKey = b64.write_and_verify("key:" + masterKey, mainSessionKey);
        //verify
        if (String(masterKey) === String(b64.readUserKey(userPrivateKey, userKey, mainPublicKey)))
            return userKey;
        else
            throw new Error("Error creating user key for " + userPrivateKey);
    };
    b64.readUserKey = function (myPrivateKey, userKey, mainPublicKey) {
        var key = b64.read(userKey, getSessionKey(myPrivateKey, mainPublicKey));
        if (/^key:/.test(key))
            return key.replace(/^key:/, "");
        else
            return false;
    };
    b64.share = function (str, myPrivateKey, theirPublicKeys, expires) {
        var key = b64.rand(prime.length), members = [b64.createUserKey(b64.createPublicKey(myPrivateKey), key)]; //add self to members in case uploading to network where you might need to access it as well
        expires = expires && !isNaN(expires) && isFinite(expires) ? new Date().getTime() + expires * 26298e5 : expires ? new Date().getTime() + 18 * 26298e5 : false;
        str = b64.write(str, key);
        if (theirPublicKeys && theirPublicKeys instanceof Array) {
            for (var a = 0; a < theirPublicKeys.length; a++) {
                members[a + 1] = b64.createUserKey(theirPublicKeys[a], key);
            }
        }
        return {
            "Version": b64.Version,
            "Expires": expires,
            "Compressed": true,
            "Data": str,
            "PublicKey": b64.createPublicKey(key),
            "UserKeys": b64.write_and_verify(JSON.stringify(members)),
            "Signature": b64.hmac(str + expires, key)
        };
    };
    b64.readShared = function (obj, myPrivateKey) {
        var key, type = "error", message = "", data, hash;
        if (obj.Version === b64.Version || obj.Version === 1.0) { //supported version numbers
            if (obj.UserKeys && obj.Compressed) {
                var members = JSON.parse(b64.read(obj.UserKeys));
                for (var a = 0, len = members.length; a < len; a++) {
                    if (b64.readUserKey(myPrivateKey, members[a], obj.PublicKey))
                        key = b64.readUserKey(myPrivateKey, members[a], obj.PublicKey);
                }
                members = null;
            }
            if (obj.Expires !== false && new Date().getTime() > obj.Expires)
                message = "data expired";
            else if (key) {
                if (obj.Version === 1.0) { //version 1.0 uses hash, not hmac
                    data = b64.read(obj.Data, key);
                    hash = b64.hash(data + obj.Expires);
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
                    hash = b64.hmac(obj.Data + obj.Expires, key);
                    if (obj.Signature === hash) {
                        data = b64.read(obj.Data, key);
                        type = "results";
                        message = "success";
                    }
                    else {
                        data = null;
                        message = "hmac didn't match";
                    }
                }
            }
            else
                message = "no key match";
        }
        else
            message = "file version '" + obj.Version + "' not supported";
        return { "type": type, "message": message, "data": data, "hmac": hash };
    };
    return b64;
})();
//# sourceMappingURL=base64.js.map