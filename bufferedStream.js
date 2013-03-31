var utils = require("./utils");
var async = require("async");

/**
 * Buffers the output of a readable stream and makes it readable in a predictable manner.
 * 
 * @param stream {Readable Stream|Buffer|String} The stream to read from
*/
var BufferedStream = function(stream) {
	this.__buffer = new Buffer(0);
	this.__ended = false;
	this.__endError = null;
	this.__wantToRead = [ ];

	if(stream instanceof Buffer)
	{
		this._sendData(stream);
		this._endData();
	}
	else if(typeof stream == "string")
	{
		this._sendData(new Buffer(stream, "binary"));
		this._endData();
	}
	else if(stream != null)
	{
		stream.on("data", utils.proxy(this, function(data) {
			this._sendData(data);
		}));
		stream.on("end", utils.proxy(this, function() {
			this._endData();
		}));
		stream.on("error", utils.proxy(this, function(err) {
			this._endData(err);
		}));
	}
}

BufferedStream.prototype = {
	__checkRead : function() {
		while(this.__wantToRead.length > 0)
		{
			var it = this.__wantToRead[0];
			var bufferBkp = this.__buffer;
			var nlidx;
			if(it.bytes == -3 && this.__buffer.length > 0)
			{
				this.__wantToRead.shift();
				this.__buffer = new Buffer(0);
				it.callback(null, bufferBkp);
			}
			else if(it.bytes == -2 && (nlidx = utils.indexOf(this.__buffer, 10)) != -1)
			{
				this.__wantToRead.shift();
				this.__buffer = this.__buffer.slice(nlidx+1);
				it.callback(null, bufferBkp.slice(0, nlidx+1));
			}
			else if(it.bytes >= 0 && this.__buffer.length >= it.bytes)
			{
				this.__wantToRead.shift();
				this.__buffer = this.__buffer.slice(it.bytes);
				it.callback(null, bufferBkp.slice(0, it.bytes));
			}
			else if(this.__ended)
			{
				this.__wantToRead.shift();
				this.__buffer = new Buffer(0);
				if(this.__endError)
					it.callback(this.__endError);
				else if(it.strict)
					it.callback(new Error("Stream has ended before the requested number of bytes was sent."));
				else
					it.callback(null, bufferBkp);
			}
			else
				break;
		}
	},

	_sendData : function(data) {
		this.__buffer = Buffer.concat([ this.__buffer, data ]);
		setImmediate(utils.proxy(this, this.__checkRead));
	},

	_sendDataAtStart : function(data) {
		this.__buffer = Buffer.concat([ data, this.__buffer ]);
		setImmediate(utils.proxy(this, this.__checkRead));
	},

	_endData : function(error) {
		this.__ended = true;
		this.__endError = error;

		setImmediate(utils.proxy(this, this.__checkRead));
	},

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
	read : function(bytes, callback, strict) {
		this.__wantToRead.push({ bytes: bytes, callback: callback, strict: (strict === undefined || strict === null ? true : strict) });
		setImmediate(utils.proxy(this, this.__checkRead));
	},

	/**
	 * Calls the callback function exactly once: When EOF is reached with the full content or in case of an error with the error object.
	*/
	readUntilEnd : function(callback) {
		this.read(-1, callback, false);
	},

	/**
	 * Reads a line from the stream. The linebreak is also returned (except on the last line). When an empty Buffer is passed to the callback
	 * function, this indicates that the stream has ended.
	*/
	readLine : function(callback) {
		this.read(-2, callback, false);
	},

	/**
	 * Calls the callback function with new data as soon as it is available. When an empty Buffer is passed, this means that the stream has ended.
	*/
	readArbitrary : function(callback) {
		this.read(-3, callback, false);
	},

	/**
	 * Works like async.whilst. Reads an arbitrary amount of bytes from the stream and calls fn with it. When fn calls the callback(err) function
	 * that has been passed to it as second parameter, reads more bytes and calls fn again. When the stream has ended or fn has called
	 * the callback function with an error, the `callback` parameter is called.
	*/
	whilst : function(fn, callback) {
		readOn.call(this);

		function readOn() {
			this.readArbitrary(utils.proxy(this, function(err, data) {
				if(err)
					callback(err);
				else if(data.length == 0)
					callback();
				else
				{
					fn(data, utils.proxy(this, function(err) {
						if(err)
							callback(err);
						else
							readOn.call(this);
					}));
				}
			}));
		}
	},

	/**
	 * Sends all data to the specified other BufferedStream.
	*/
	_pipe : function(otherStream) {
		this.whilst(function(data, next) {
			otherStream._sendData(data);
			next();
		}, function(err) {
			otherStream._endData(err);
		});
	},

	/**
	 * Returns a new BufferedStream object that concatenates all the given other streams to this stream.
	 * @param otherStream {BufferedStream|Readable Stream|Buffer|String} The other stream to append
	 * @return {BufferedStream} A new BufferedStream
	 */
	concat : function(otherStream) {
		return concat([ this ].concat(utils.toProperArray(arguments)));
	}
};

function concat(streams) {
	var ret = new BufferedStream();
	async.forEachSeries(streams, function(it, next) {
		if(!it instanceof BufferedStream)
			it = new BufferedStream(it);

		it.whilst(function(data, next) {
			ret._sendData(data);
			next();
		}, next);
	}, function(err) {
		ret._endData(err);
	});
	return ret;
}

module.exports = BufferedStream;
module.exports.concat = concat;