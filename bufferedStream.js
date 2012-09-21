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
	this.readArbitrary = readArbitrary;
	this.pipe = pipe;

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
			if(it.bytes == -3 && buffer.length > 0)
			{
				wantToRead.shift();
				buffer = new Buffer(0);
				it.callback(null, bufferBkp);
			}
			else if(it.bytes == -2 && (nlidx = utils.indexOf(buffer, 10)) != -1)
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
	 * message as first argument or a Buffer object with the exact specified amount of bytes as second argument.
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
	
	/**
	 * Calls the callback function exactly once: When EOF is reached with the full content or in case of an error with the error object.
	*/
	function readUntilEnd(callback) {
		read(-1, callback, false);
	};
	
	/**
	 * Reads a line from the stream. The linebreak is also returned (except on the last line). When an empty Buffer is passed to the callback
	 * function, this indicates that the stream has ended.
	*/
	function readLine(callback) {
		read(-2, callback, false);
	};
	
	/**
	 * Calls the callback function with new data as soon as it is available. When an empty Buffer is passed, this means that the stream has ended.
	*/
	function readArbitrary(callback) {
		read(-3, callback, false);
	}
	
	/**
	 * Sends all data to the specified other BufferedStream.
	*/
	function pipe(otherStream) {
		readArbitrary(function(err, data) {
			if(err)
				otherStream._endData(err);
			else if(data.length == 0)
				otherStream._endData();
			else
			{
				otherStream._sendData(data);
				pipe(otherStream);
			}
		});
	}
}