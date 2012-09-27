var package = require("./package.json");
var child_process = require("child_process");
var BufferedStream = require("./bufferedStream");
var basicTypes = require("./basicTypes");

/**
 * Decodes different key input formats.
 * @param input {BufferedStream|Buffer|Stream|Readable Stream} The input data
 * @return {BufferedStream}
*/
function decodeKeyFormat(input) {
	if(!(input instanceof BufferedStream))
		input = new BufferedStream(input);
	
	var ret = new BufferedStream();
	var input2 = null;
	
	input.readLine(function(err, data) {
		if(err) { ret._endData(err); return; }

		input._sendDataAtStart(data);

		if(data.toString("utf8").match(/^-----BEGIN PGP /))
			dearmor(input)._pipe(ret);
		else
			input._pipe(ret);
	});

	return ret;
}

function dearmor(input) {
	if(!(input instanceof BufferedStream))
		input = new BufferedStream(input);
	
	var ret = new BufferedStream();
	handleFirstLine();
	return ret;
	
	function handleFirstLine() {
		input.readLine(function(err, data) {
			if(data.length == 0)
			{
				ret._endData();
				return;
			}

			var line = data.toString("utf8").replace(/\s+$/, "");
			if(line.length == 0)
			{ // Skip empty line
				handleFirstLine();
				return;
			}

			var m = line.match(/^-----BEGIN PGP (.*)-----$/);
			if(!m)
			{
				ret._endData(new Error("This is not armored PGP data."));
				return;
			}
		
			handleHeaders(m[1]);
		});
	}
	
	function handleHeaders(type) {
		input.readLine(function(err, data) {
			var line = data.toString("utf8").replace(/\s+$/, "");
			if(line.length == 0)
				handleData(type, basicTypes.getBase64DecodingStream(input));
			else
			{
				var m = line.match(/([^:]+): (.*)$/);
				if(!m)
				{
					ret._endData(new Error("Invalid header line."));
					return;
				}
				
				// What shall we do with the headers?
				
				handleHeaders(type);
			}
		});
	}
	
	function handleData(type, decode) {
		decode.read(1000, function(err, data) {
			if(err) { ret._endData(err); return; }
			
			if(data.length == 0)
				handleLastLine(type);
			else
			{
				ret._sendData(data);
				handleData(type, decode);
			}
		}, false);
	}
	
	function handleLastLine(type) {
		// First read until the end of the line, as the base64 decoder does not do that, then read the actual last line
		input.readLine(function(err, data) {
			if(err) { ret._endData(err); return; }
			
			input.readLine(function(err, data) {
				if(err) { ret._endData(err); return; }

				var m = data.toString("utf8").match(/^-----END PGP (.*)-----\s*$/);
				if(!m || m[1] != type)
				{
					ret._endData(new Error("Invalid end of armored data."));
					return;
				}
				
				handleFirstLine();
			});
		});
	}
}

/**
 * Encodes the given data using PGP ASCII armor.
 * @param input {Buffer|Readable Stream|String|BufferedStream} The raw binary data to encode
 * @param messageType {String} One of consts.ARMOR_MESSAGE
 * @return {BufferedStream}
*/
function enarmor(input, messageType) {
	var ret = new BufferedStream();
	ret._sendData(new Buffer("-----BEGIN PGP "+messageType+"-----\r\nVersion: "+package.name+" v"+package.version+"\r\n\r\n", "utf8"));
	
	basicTypes.getBase64EncodingStream(input).whilst(function(data, cb) {
		ret._sendData(data);
		cb();
	}, function(err) {
		if(err)
			ret._endData(err);
		else
		{
			ret._sendData(new Buffer("-----END PGP "+messageType+"-----\r\n", "utf8"));
			ret._endData();
		}
	});
	
	return ret;
}

exports.decodeKeyFormat = decodeKeyFormat;
exports.dearmor = dearmor;
exports.enarmor = enarmor;