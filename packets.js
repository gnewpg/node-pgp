var BufferedStream = require("./bufferedStream");
var basicTypes = require("./basicTypes");
var Fifo = require("./fifo");

/**
 * Extracts the information of an OpenPGP packet header.
 * 
 * @param data {BufferedStream|Reading Stream|Buffer|String}
 * @param callback {Function} function(error, tag, packetLength, header), where tag is the packet type, packetLength
 *                            is the length of the packet and header is the binary data of the header. If packetLength
 *                            is null, the packet goes until EOF. If packetLength is negative, this is a partial body
 *                            length (RFC 4880 Section 4.2.2.4), and the number multiplied with -1 will be the length
 *                            of the first part.
*/
function getHeaderInfo(data, callback)
{
	if(!(data instanceof BufferedStream))
		data = new BufferedStream(data);

	data.read(1, function(err, data1) {
		if(err)
			callback(err);
		else if(data1.length == 0)
			callback(true);
		else
		{
			var header = data1;

			var byte1 = data1.readUInt8(0);
			if(byte1 & 0x80 == 0) // 0x80 == 10000000
				callback(new Error("This is not an OpenPGP packet."));
			else if(byte1 & 0x40)
			{ // New packet format
				var tag = (byte1 & 0x3F); // 0x3F == 00111111

				basicTypes.read125OctetNumber(data, function(err, number, binary) {
					if(err)
						callback(err);
					else
					{
						header = Buffer.concat([ header, binary ]);
						callback(null, tag, number, header, true);
					}
				});
			}
			else
			{
				var tag = (byte1 >> 2) & 0x0F; // 0x0F == 00001111
				var headerLength;
				switch(byte1 & 0x03) { // 0x03 == 00000011
					case 0: headerLength = 2; break;
					case 1: headerLength = 3; break;
					case 2: headerLength = 5; break;
					case 3: headerLength = 1; break;
				}
				if(headerLength == 1) // Packet length until EOF
					callback(null, tag, null, header, false);
				else
				{
					data.read(headerLength-1, function(err, data2) {
						if(err)
							callback(err)
						else
						{
							header = Buffer.concat([ header, data2 ]);

							var packetLength;
							switch(headerLength) {
								case 2: packetLength = data2.readUInt8(0); break;
								case 3: packetLength = data2.readUInt16BE(0); break;
								case 5: packetLength = data2.readUInt32BE(0); break;
							}
							callback(null, tag, packetLength, header, false);
						}
					});
				}
			}
		}
	}, false);
}

function generateHeader(tag, packetLength, newFormat)
{
	if(newFormat == null)
		newFormat = (tag >= 16);
		
	if(newFormat)
	{
		var number = basicTypes.encode125OctetNumber(packetLength);
		var ret = Buffer.concat([ new Buffer(1), number ]);
		ret.writeUInt8(0xC0 | tag, 0); // 0xc0 == 11000000
		return ret;
	}
	else
	{
		var buffer;
		var lengthTag;
		if(packetLength <= 0xFF)
		{
			buffer = new Buffer(2);
			buffer.writeUInt8(packetLength, 1);
			lengthTag = 0;
		}
		else if(packetLength <= 0xFFFF)
		{
			buffer = new Buffer(3);
			buffer.writeUInt16BE(packetLength, 1);
			lengthTag = 1;
		}
		else
		{
			buffer = new Buffer(5);
			buffer.writeUInt32BE(packetLength, 1);
			lengthTag = 2;
		}

		buffer.writeUInt8(0x80 | (tag << 2) | lengthTag, 0);
		return buffer;
	}
}

function generatePacket(tag, body, newHeaderFormat)
{
	var header = generateHeader(tag, body.length, newHeaderFormat);
	var ret = new Buffer(header.length+body.length);
	header.copy(ret);
	body.copy(ret, header.length);
	return ret;
}

/**
 * Splits an OpenPGP message into its packets. If any of the packets contains partial body length headers,
 * it will be converted to a package with a fixed length.
 * 
 * 
 * 
 * @param data {BufferedStream|Reading Stream|Buffer|String}
 * @return {Fifo} Returns a Fifo object. callback methods receiving data via Fifo.next() will receive the following arguments apart from the error:
 *                - The packet type (one of consts.PKT)
 *                - The packet header (as a Buffer object)
 *                - The packet body (as a Buffer object)
*/
function splitPackets(data) {
	if(!(data instanceof BufferedStream))
		data = new BufferedStream(data);
	
	var ret = new Fifo();
	readPacket();
	return ret;

	function readPacket() {
		getHeaderInfo(data, function(err, tag, packetLength, header, newFormat) {
			if(err === true)
				ret._end();
			else if(err)
				ret._end(err);
			else
			{
				if(packetLength < 0) // Partial body length
				{
					data.read(-packetLength, function(err, body) {
						var readon = function() {
							basicTypes.read125OctetNumber(data, function(err, length) {
								if(err)
									ret._end(err);
								else
								{
									data.read(Math.abs(length), function(err, part) {
										if(err)
											ret._end(err);
										else
										{
											body = Buffer.concat(body, part);
											if(length < 0)
												readon();
											else
											{
												header = generateHeader(tag, body.length, newFormat);
												ret._add(tag, header, body);
												setImmediate(readPacket);
											}
										}
									});
								}
							});
						};
						readon();
					});
				}
				else if(packetLength == null) // Body goes until EOF
				{
					data.readUntilEnd(function(err, body) {
						if(err)
							ret._end(err);
						else
						{
							ret._add(tag, generateHeader(tag, body.length, newFormat), body);
							setImmediate(readPacket);
						}
					});
				}
				else
				{
					data.read(packetLength === null ? -1 : packetLength, function(err, body) {
						if(err)
							ret._end(err);
						else
						{
							ret._add(tag, header, body);
							setImmediate(readPacket);
						}
					});
				}
			}
		});
	};
}

exports.getHeaderInfo = getHeaderInfo;
exports.generateHeader = generateHeader;
exports.generatePacket = generatePacket;
exports.splitPackets = splitPackets;