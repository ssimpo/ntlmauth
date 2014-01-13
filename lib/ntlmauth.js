var os = require('os');
var crypto = require('crypto');
var BigInteger = require('bignumber').BigInteger;

var NTLMAuth = (function(config) { 

		if ( typeof config != "undefined" ) {
		
			if (typeof config.debug != undefined ) {
				this.debug = config.debug;
			}
			
			if (this.debug) {
				console.log(JSON.stringify(config, undefined, 4));
			}
			
		}


 });
 


	NTLMAuth.prototype.createSSPIRequest = function(domainName, clientName) {
  
		var encoding = 'utf8';
		
		if (typeof clientName == "undefined" ) {
			clientName = os.hostname();
		}
		
		var domainLen = Buffer.byteLength(domainName, encoding);
		var clientLen = Buffer.byteLength(clientName, encoding);
	
		var pktSize = 
			  8  // Header 
			+ 4  // Sequence Number
			+ 4  // Flags
			+ 8  // Domain Name Size and Position
			+ 8  // Client Name Size and Position
			+ 8  // Empty Value
			+ 8  // Empty Value
			+ clientLen
			+ domainLen;
	
		var ntlmPacket = new Buffer(pktSize);
		
		ntlmPacket.write('NTLMSSP\0', 0, 8, 'utf8');
	
		// Sequence
		ntlmPacket.writeInt32LE(0x01, 8);
	
		// Flags - NTLMv2
		//ntlmPacket.writeInt32LE(0x08b205, 12);
		ntlmPacket.writeInt32LE(0xb201, 12);

	
		// Domain Name Length and Position
		// Allocated
		ntlmPacket.writeInt16LE(domainLen, 16);
		// Used
		ntlmPacket.writeInt16LE(domainLen, 18);
		// Offset
		ntlmPacket.writeInt32LE(48 + clientLen, 20);
	
		// Client Name Length and Position
		// Allocated
		ntlmPacket.writeInt16LE(clientLen, 24);
		// Used
		ntlmPacket.writeInt16LE(clientLen, 26);
		// Offset
		ntlmPacket.writeInt32LE(48, 28);

		// Username - null
		ntlmPacket.writeInt16LE(0, 32);
		ntlmPacket.writeInt16LE(0, 34);
		ntlmPacket.writeInt32LE(0, 36);

		// Password - null
		ntlmPacket.writeInt16LE(0, 40);
		ntlmPacket.writeInt16LE(0, 42);
		ntlmPacket.writeInt32LE(0, 44);
	
	// Write the client name
	ntlmPacket.write(clientName
		,48 // Offset
		,clientLen //Length
		,encoding // Encoding 
	);
	
	// Finally the UTF-8 of the Domain Name
	ntlmPacket.write(domainName
		,48 + clientLen // Offset
		,domainLen //Length
		,encoding // Encoding 
	);
		
	return ntlmPacket;
	
  };	
  
  	NTLMAuth.prototype.parseChallenge = function(challenge) {
	
		if (this.debug) {
			console.log("Parsing NTLM challenge");
		}
		
		var interfaceNumber, interfaceType, length, progName, progVersion, tdsVersion, tdsVersionNumber;

		length = challenge.readUInt16LE();
		var hdrLength = 40;
 
		if ( length < hdrLength ) {
			throw new Error("NTLM Challenge malformed - Length: " + length + " when header length alone is " + hdrLength);
		}
  
		var magic = challenge.readString(8, 'ascii');
		if ( magic != "NTLMSSP\0" ) {
			throw new Error("NTLM Challenge malformed - Got Magic: " + magic );
		}


		var seqNum = challenge.readInt32LE();
		if ( seqNum != 2 ) {
			throw new Error("NTLM Challenge malformed - Out of sequence: " + seqNum );
		}

		var domainLen = challenge.readInt16LE();
		var domainMax = challenge.readInt16LE();
		var domainOff = challenge.readInt32LE();
	
		var flags = challenge.readInt32LE();
		var nonce = challenge.readBuffer(8);
		var zeroes = challenge.readBuffer(8);
	
		var addDataLen = challenge.readInt16LE();
		var addDataMax = challenge.readInt16LE();
		var addDataOffset = challenge.readInt32LE();
  
		var oddData = challenge.readBuffer(8);

		var domainName = challenge.readString(domainLen, "ucs2");
		var addData = challenge.readBuffer(addDataLen);
	
		this.server_nonce = nonce;
		this.server_data = addData;
		this.initialized = true;
		
	}
	
	
	NTLMAuth.prototype.createResponse = function(domain, username, password) {
	
		if ( typeof this.initialized == "undefined" || !this.initialized ) {
			throw new Error("NTLM Response can't be created - no server challenge was parsed.");
		}
		
	    var data, fixed, length, lengthLength, variable;
	
		// Generate nonce
		this.client_nonce = this.createClientNonce();

		var lmv2len = 24;	
		var ntlmv2len = 16 + 8 /* ?? */ + 8 /* TS */ + 8 /* CNonce */ + 4 /* 0000 */ + this.server_data.length + 4 /* 0000 */;

		var packetLength = 
			64 + // Header Length
			lmv2len +
			ntlmv2len +
			4 + // Flags 1 
			4 + // Flags 2
			8 + // Timestamp
			8 + // Client Nonce
			4 + // NULL
			this.server_data.length + // Server Data
			4 // NULL
			
		data = new Buffer(packetLength);
		var dataIdx = 0;
		
		data.write("NTLMSSP\0", dataIdx, 8, "utf8");
		dataIdx += 8;
		
		data.writeUInt32LE(0x03, dataIdx);
		dataIdx += 4;
	
		var baseIdx = 64;
		var dnIdx = baseIdx;
		var unIdx = dnIdx + domain.length * 2;
		var l2Idx = unIdx + username.length * 2;
		var ntIdx = l2Idx + lmv2len;

		data.writeUInt16LE(lmv2len, dataIdx);
		dataIdx+=2;
		data.writeUInt16LE(lmv2len, dataIdx);
		dataIdx+=2;
		data.writeUInt32LE(l2Idx, dataIdx);
		dataIdx+=2;
	
		data.writeUInt16LE(ntlmv2len, dataIdx);
		dataIdx+=2;
		data.writeUInt16LE(ntlmv2len, dataIdx);
		dataIdx+=2;
		data.writeUInt32LE(ntIdx, dataIdx);
		dataIdx+=4;

		data.writeUInt16LE(domain.length * 2, dataIdx);
		dataIdx+=2;
		data.writeUInt16LE(domain.length * 2, dataIdx);
		dataIdx+=2;
		data.writeUInt32LE(dnIdx, dataIdx);
		dataIdx+=4;
	
		data.writeUInt16LE(username.length * 2, dataIdx);
		dataIdx+=2;
		data.writeUInt16LE(username.length * 2, dataIdx);
		dataIdx+=2;
		data.writeUInt32LE(unIdx, dataIdx);
		dataIdx+=4;

		data.writeUInt16LE(0,dataIdx);
		dataIdx+=2;
		data.writeUInt16LE(0,dataIdx);
		dataIdx+=2;
		data.writeUInt32LE(baseIdx,dataIdx);
		dataIdx+=4;
	
		data.writeUInt16LE(0,dataIdx);
		dataIdx+=2;
		data.writeUInt16LE(0,dataIdx);
		dataIdx+=2;
		data.writeUInt32LE(baseIdx,dataIdx);
		dataIdx+=4;
	
		data.writeUInt16LE(0x8201,dataIdx);
		dataIdx+=2;
		data.writeUInt16LE(0x08,dataIdx);
		dataIdx+=2;
	
		data.write(domain,dataIdx,domain.length,"ucs2");
		dataIdx+=domain.length * 2;
		
		data.write(username,dataIdx,username.length,"ucs2");
		dataIdx+=username.length * 2;
	
		var lmv2Data = this.lmv2Response(domain, username, password, this.server_nonce, this.server_data);
		lmv2Data.copy(data,dataIdx);
		dataIdx+=lmv2Data.length;
	
		var genTime = (new Date).getTime();
		var ntlmData = this.ntlmv2Response(domain, username, password, this.server_nonce, this.server_data, this.client_nonce, genTime);
		ntlmData.copy(data,dataIdx);
		dataIdx+=ntlmData.length;

		data.writeUInt32LE(0x0101,dataIdx);
		dataIdx+=4;
		data.writeUInt32LE(0x0000,dataIdx);
		dataIdx+=4;
		
		var timestamp = this.createTimestamp(genTime);
		timestamp.copy(data,dataIdx);
		dataIdx+=8;
		
		this.client_nonce.copy(data,dataIdx);
		dataIdx+=8;
		
		data.writeUInt32LE(0x0000,dataIdx);
		dataIdx+=4;
		
		this.server_data.copy(data,dataIdx);
		dataIdx+=this.server_data.length;
		
		data.writeUInt32LE(0x0000,dataIdx);
		
		return data;
	}
	
	
	NTLMAuth.prototype.createClientNonce = function() {
	
		var client_nonce = new Buffer(8);
		for ( var nidx=0; nidx<8; nidx++ ) {
			client_nonce.writeUInt8(Math.ceil(Math.random()*255), nidx)
		}
		if (this.debug) {
			console.log("Generated Nonce: " + JSON.stringify(client_nonce));
		}
	};
  
	NTLMAuth.prototype.ntlmv2Response = function(domain, user, password, serverNonce, targetInfo, clientNonce, mytime) {
		if ( this.debug ) {
			console.log("NTLM V2 Response");
			console.log("================");
		};
		var timestamp = this.createTimestamp(mytime);
		var hash = this.ntv2Hash(domain, user, password);
		var dataLength = 40 + targetInfo.length;
		var data = new Buffer(dataLength);
		serverNonce.copy(data, 0, 0, 8);
		data.writeUInt32LE(0x101, 8);
		data.writeUInt32LE(0x0, 12);
		timestamp.copy(data, 16, 0, 8);
		clientNonce.copy(data, 24, 0, 8);
		data.writeUInt32LE(0x0, 32);
		targetInfo.copy(data, 36, 0, targetInfo.copy);
		data.writeUInt32LE(0x0, 36 + targetInfo.length);
		var newHash = this.hmacMD5(data, hash);
		if ( this.debug ) {
			console.log("Data: ");
			this.hexDump(data);
			console.log("Hash: ");
			this.hexDump(hash);
			console.log("Response: ");
			this.hexDump(newHash);
		}
		return newHash;
	};

	NTLMAuth.prototype.createTimestamp = function(time) {

		var bigTime = new BigInteger(""+time);
		var timestamp = bigTime.add(new BigInteger(""+11644473600000)).multiply(new BigInteger(""+10000)).toString(16);
		var padded = "00000000" + timestamp;
		timestamp = padded.substr(padded-16);

		var result = new Buffer(8);
		for ( var idx = 8; idx>0 ;  idx--) {
		 	result[idx-1] = parseInt(timestamp.substr(timestamp.length-(2*idx), 2), 16);
		}

		if ( this.debug ) {
			console.log("Timestamp: " + time);
			console.log("Timestamp Array");
			this.hexDump(result);
		}

		return result;
	};
	
    NTLMAuth.prototype.lmv2Response = function(domain, user, password, serverNonce, clientNonce) {
		var hash = this.ntv2Hash(domain, user, password);
		var data = new Buffer(serverNonce.length + clientNonce.length);
		serverNonce.copy(data, 0, 0, serverNonce.length);
		clientNonce.copy(data, serverNonce.length, 0, clientNonce.length);
		var newhash = this.hmacMD5(data, hash);
		var response = new Buffer(newhash.length + clientNonce.length);
		newhash.copy(response, 0, 0, newhash.length);
		clientNonce.copy(response, newhash.length, 0, clientNonce.length);
		if ( this.debug ) {
			console.log("LM V2 Response");
			console.log("Data:  ");
			this.hexDump(data);
			console.log("Hash: " );
			this.hexDump(hash);
			console.log("New hash:" );
			this.hexDump(newhash);
			console.log("Response:" );
			this.hexDump(response);		
		}
		return response;
	};
	
	NTLMAuth.prototype.ntv2Hash = function(domain, user, password) {
		var hash = this.ntHash(password);
		var identity = new Buffer(user.toUpperCase() + domain.toUpperCase(), "ucs2");
		var result = this.hmacMD5(identity, hash);
		return result;
	};
	
	NTLMAuth.prototype.ntHash = function(text) {

		var result = new Buffer(21);
		result.fill(0);
		
		var unicodeString = new Buffer(text, "ucs2");
		
		var md4 = crypto.createHash('md4').update(unicodeString).digest(); 
		
		md4.copy(result, 0, 0, md4.length);
				
		return result;
	};
	
	NTLMAuth.prototype.hmacMD5 = function(data, key) {
		var hmac = crypto.createHmac("MD5", key);
		hmac.update(data);
		return hmac.digest();
	};
	
	NTLMAuth.prototype.hexDump = function(data) {
		var outputString = new String();
		var addressPadding = "0000000";
		var line = 0;
		var countForCurrentLine = 0;
	   
		outputString +=
				"Address   0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f \n" +
				"---------------------------------------------------------\n" +
				"00000000  ";
	   
		for (var i=0; i < data.length; i++) {
				countForCurrentLine++
				var byteData = data.readInt8(i);
				var number = data.readInt8(i) & 0xff;
				var byteHex = (number < 16) ? "0" + number.toString(16) : number.toString(16);;

				outputString += byteHex + " ";
				if (countForCurrentLine == 16) {
						countForCurrentLine = 0;
						line++;
						outputString += "\n" + addressPadding.substr(0, 7 - line.toString(16).length) + line.toString(16) + "0  ";
				}
		}
		console.log(outputString);
	}

module.exports = NTLMAuth;
