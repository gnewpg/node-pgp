var BufferedStream = require("./bufferedStream");

/**
 * Reads a 1, 2 or 5 octet number from an OpenPGP packet as specified in RFC 4880 section 4.2.2
 * 
 * @param data {BufferedStream|Reading Stream|Buffer|String}
 * @param callback {Function} function(error, number, binary) If the number represents a partial body length, it
 *                            is multiplied with -1. The binary parameter is the binary representation of the number.
*/
function read125OctetNumber(data, callback)
{
	if(!(data instanceof BufferedStream))
		data = new BufferedStream(data);

	data.read(1, function(err, data1) {
		if(err)
		{
			err.NOFIRSTBYTE = true;
			callback(err);
		}
		else
		{
			binary = data1;
			
			var byte1 = data1.readUInt8(0);
			if(byte1 < 192)
				callback(null, byte1, binary);
			else if(byte1 < 224)
			{
				data.read(1, function(err, data2) {
					if(err)
						callback(err);
					else
					{
						binary = Buffer.concat([ binary, data2 ]);
						callback(null, ((byte1 - 192) << 8) + data2.readUInt8(0) + 192, binary);
					}
				});
			}
			else if(byte1 < 255)
				callback(null, -(1 << (byte1 & 0x1F)));
			else if(byte1 == 255)
			{
				data.read(4, function(err, data2) {
					if(err)
						callback(err);
					else
					{
						binary = Buffer.concat([ binary, data2 ]);
						callback(null, data2.readUInt32BE(0), binary);
					}
				});
			}
		}
	});
}

function encode125OctetNumber(number)
{
	if(number < 192)
	{
		var ret = new Buffer(1)
		ret.writeUInt8(number, 0);
		return ret;
	}
	else if(number < 8384)
	{
		var ret = new Buffer(2);
		ret.writeUInt8(((number-192) >> 8) + 192, 0);
		ret.writeUInt8((number-192) & 0xFF, 1);
		return ret;
	}
	else
	{
		var ret = new Buffer(5);
		ret.writeUInt8(255, 0);
		ret.writeUInt32BE(number, 1);
		return ret;
	}
}

function splitMPIs(data, limit)
{
	var ret = [ ];
	var i = 0;
	while(i < data.length && (!limit || ret.length < limit))
	{
		var length = data.readUInt16BE(i);
		var bytes = Math.ceil(length/8);
		ret.push(new MPI(data.slice(2+i, 2+i+bytes), length));
		i += 2+bytes;
	}
	ret.bytes = i;
	return ret;
}

/**
 * A Multi-Precision Integer (MPI). `length` is the length in bits (not bytes!) and buffer is a buffer whose first
 * `length` bits represent the number in Big Endian.
*/
function MPI(buffer, length)
{
	this.buffer = buffer;
	this.length = length;
}

/**
 * Calculates the CRC24 hash of a data buffer as specified in http://tools.ietf.org/html/rfc4880#section-6.1.
 * 
 * You can use the previousValue and noFinal paramters if you want to calculate the checksum of a stream. You can
 * call the function multiple times, each time passing the return value of the previous function call as `previousValue`
 * and setting `noFinal` to true. On the last call, set noFinal to false.
 * 
 * Example:
 * 
 *     var crc = null;
 *     stream.on("data", function(data) {
 *         crc = crc24(data, crc, true);
 *     }
 *     stream.on("end", function() {
 *         crc = crc24(null, crc, false); // This is the final checksum
 *     }
 * 
 * @param data {Buffer}
 * @param previousValue {Number}
 * @param noFinal {Boolean}
 * @return {Number}
*/

function crc24(data, previousValue, noFinal) {
	var crc = (previousValue == null ? 0xB704CE : previousValue);

	if(data != null)
	{
		for(var i=0; i<data.length; i++)
		{
			crc ^= data.readUInt8(i) << 16;
			for(var j=0; j<8; j++)
			{
				crc <<= 1;
				if(crc & 0x1000000)
					crc ^= 0x1864CFB;
			}
		}
	}

	if(!noFinal)
		crc &= 0xFFFFFF;
	
	return crc;
}

function getBase64EncodingStream(input)
{
	if(!(input instanceof BufferedStream))
		input = new BufferedStream(input);
	
	var ret = new BufferedStream();
	var crc = null;
	
	var readon = function() {
		// The chunk size has to be dividable by 3, else we will produce padding = signs.
		// 48 bytes create are 64 bytes in base64, which is the size that gpg produces.
		// The maximum line length according to the OpenPGP standard would be 76.
		input.read(48, function(err, data) {
			if(err) { ret._endData(err); return; }
			
			if(data.length == 0)
			{
				crc = crc24(null, crc, false);
				var crcBuffer = new Buffer(3);
				crcBuffer.writeUInt8((crc & 0xFF0000) >> 16, 0);
				crcBuffer.writeUInt16BE(crc & 0xFFFF, 1);
				ret._sendData(new Buffer("="+crcBuffer.toString("base64")+"\r\n", "utf8"));
				ret._endData();
				return;
			}
			
			crc = crc24(data, crc, true);
			ret._sendData(new Buffer(data.toString("base64")+"\r\n", "utf8"));

			readon();
		}, false);
	};
	readon();

	return ret;
}

function getBase64DecodingStream(input)
{
	if(!(input instanceof BufferedStream))
		input = new BufferedStream(input);
	
	var ret = new BufferedStream();
	var crc = null;
	var leftover = "";
	
	var readon = function() {
		// Buffer size changeble for unit tests. Has to be dividable by 4.
		input.read(arguments[1] || 1000, function(err, data) {
			if(err) { ret._endData(err); return; }
			
			if(data.length == 0)
			{ // We can ignore the leftover here as it cannot be more than 3 bytes long anyways
				ret._endData(new Error("Premature end of base64 stream."));
				return;
			}
			
			var dataStr = leftover + data.toString("utf8");
			
			// The whitespace removal is a bit complicated. Inside the base64 stream, we have to remove all
			// whitespaces, but we do not want to damage the data that comes after it, so we cannot just remove
			// all whitespaces from data.

			var eq = dataStr.indexOf("=");
			if(eq != -1)
			{
				// After the base64 stream there comes an equal sign and then 4 bytes of a base64-encoded checksum.
				// Unfortunately, an equal sign is also used as padding at the end of the base64 stream. The only way
				// to distinguish is that the length of a base64 stream has to be dividable by 4, so an equal sign whose
				// position is dividable by 4 is the checksum sign, otherwise it is a padding sign.

				// It is safe to remove all whitespaces before the first equal sign. Then we can calculate where the
				// base64 stream ends (which is the first position from the equal sign on that is dividable by 4).
				dataStr = dataStr.substring(0, eq).replace(/\s/g, "") + dataStr.substring(eq);
				eq = dataStr.indexOf("=");

				var streamEnd = (eq % 4 ? eq + 4 - eq % 4 : eq);
				if(streamEnd > dataStr.length) // There are still some equal signs to come so we can wait until the next round
					eq = -1;
				else
				{
					// Now we remove all remaining whitespaces that are after the equal sign but still inside the base64 stream.
					// As the removing of whitespaces might bring new whitespaces from further right, we do this in a loop.
					// We also remove all whitespaces directly after the base64 stream (thus the +1)
					while(dataStr.substring(0, streamEnd+1).match(/\s/))
						dataStr = dataStr.substring(0, streamEnd+1).replace(/\s/g, "") + dataStr.substring(streamEnd+1);

					// We push the additional data back to the stream
					input._sendDataAtStart(new Buffer(dataStr.substring(streamEnd), "utf8"));
					dataStr = dataStr.substring(0, streamEnd);
				}
			}
			if(eq == -1) // Also if eq was set to -1 manually
				dataStr = dataStr.replace(/\s/g, "");
			
			if(dataStr.length % 4) // base64 chunk has to be dividable by 4. Note that
			{                      // it always is in case we detected an equal sign and eq != -1
				var end = dataStr.length - (dataStr.length % 4);
				leftover = dataStr.substring(end);
				dataStr = dataStr.substring(0, end);
			}
			else
				leftover = "";
			
			if(!dataStr.match(/^([a-zA-Z0-9+\/]*)(=*)$/))
			{
				ret._endData(new Error("Invalid characters in base64 stream."));
				return;
			}

			var decodedData = new Buffer(dataStr, "base64");
			crc = crc24(decodedData, crc, true);
			ret._sendData(decodedData);
			
			if(eq != -1)
			{ // Check CRC checksum and end
				crc = crc24(null, crc, false);
				
				input.read(5, function(err, data) {
					if(err) { ret._endData(err); return; }
					
					data = new Buffer(data.toString("utf8", 1), "base64");
					var crcInDoc = (data.readUInt8(0) << 16) | data.readUInt16BE(1);
					if(crcInDoc != crc)
						ret._endData(new Error("CRC checksum does not match."));
					else
						ret._endData();
				});
			}
			else
				readon();
		}, false);
	};
	readon();
	
	return ret;
}

exports.read125OctetNumber = read125OctetNumber;
exports.encode125OctetNumber = encode125OctetNumber;
exports.splitMPIs = splitMPIs;
exports.MPI = MPI;
exports.getBase64EncodingStream = getBase64EncodingStream;
exports.getBase64DecodingStream = getBase64DecodingStream;