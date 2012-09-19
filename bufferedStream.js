var utils = require("./utils");

/**
 * Buffers the output of a readable stream and makes it readable in a predictable manner.
 * 
 * @param stream {Readable Stream|Buffer|String} The stream to read from
*/
module.exports = function(stream) {
	var buffer = new Buffer(0);
	var ended = false;
	var endError = null;
	var wantToRead = [ ];
	
	this._sendData = sendData;
	this._sendDataAtStart = sendDataAtStart;
	this._endData = endData;
	this.read = read;
	this.readUntilEnd = readUntilEnd;
	this.readLine = readLine;

	if(stream instanceof Buffer)
	{
		sendData(stream);
		endData();
	}
	else if(typeof stream == "string")
	{
		sendData(new Buffer(stream, "binary"));
		endData();
	}
	else if(stream != null)
	{
		stream.on("data", function(data) {
			sendData(data);
		});
		stream.on("end", function() {
			endData();
		});
	}

	function checkRead() {
		while(wantToRead.length > 0)
		{
			var it = wantToRead[0];
			var bufferBkp = buffer;
			var nlidx;
			if(it.bytes == -2 && (nlidx = utils.indexOf(buffer, 10)) != -1)
			{
				wantToRead.shift();
				buffer = buffer.slice(nlidx+1);
				it.callback(null, bufferBkp.slice(0, nlidx+1));
			}
			else if(it.bytes >= 0 && buffer.length >= it.bytes)
			{
				wantToRead.shift();
				buffer = buffer.slice(it.bytes);
				it.callback(null, bufferBkp.slice(0, it.bytes));
			}
			else if(ended)
			{
				wantToRead.shift();
				buffer = new Buffer(0);
				if(endError)
					it.callback(endError);
				else if(it.strict)
					it.callback(new Error("Stream has ended before the requested number of bytes was sent."));
				else
					it.callback(null, bufferBkp);
			}
			else
				break;
		}
	}
	
	function sendData(data) {
		buffer = Buffer.concat([ buffer, data ]);
		checkRead();
	}
	
	function sendDataAtStart(data) {
		buffer = Buffer.concat([ data, buffer ]);
		checkRead();
	}
	
	function endData(error) {
		ended = true;
		endError = error;
		
		checkRead();
	}
	
	/**
	 * The callback function is called as soon as the specified number of bytes is available, receiving a possible error
	 * message as first argument or a Buffer object with the exact specified amount of bytes as second argument. If the
	 * bytes parameter is set to -1, the callback function will only be called when the readable stream has reached its
	 * end, then passing the full content to the function.
	 * 
	 * If the stream ends before the requested number of bytes is available, the callback function will be called with an error
	 * message, except if the strict parameter is set to false, in which case the callback function will be called with the
	 * available amount of bytes.
	 * 
	 * @param bytes {Number}
	 * @param callback {Function}
	 * @param strict {Boolean} Optional, defaults to true.
	*/
	function read(bytes, callback, strict) {
		wantToRead.push({ bytes: bytes, callback: callback, strict: (strict === undefined || strict === null ? true : strict) });
		checkRead();
	};
	
	function readUntilEnd(callback) {
		read(-1, callback, false);
	};
	
	function readLine(callback) {
		read(-2, callback, false);
	};
}