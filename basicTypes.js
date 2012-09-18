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

function splitMPIs(data)
{
	var ret = [ ];
	var i = 0;
	while(i < data.length)
	{
		var length = Math.floor((data.readUInt16BE(i)+7) / 8);
		ret.push(data.slice(i, 2+i+length));
		i += 2+length;
	}
	return ret;
}

exports.read125OctetNumber = read125OctetNumber;
exports.encode125OctetNumber = encode125OctetNumber;
exports.splitMPIs = splitMPIs;