/**
 * Buffers the output of a readable stream and makes it readable in a predictable manner.
 * 
 * @param stream {Readable Stream|Buffer|String} The stream to read from
*/
module.exports = function(stream) {
	if(stream instanceof String)
		stream = new Buffer(stream, "binary");

	var usingBuffer = (stream instanceof Buffer);
	var buffer = (usingBuffer ? stream : new Buffer(0));
	var ended = usingBuffer;
	var wantToRead = [ ];
	
	var checkRead = function() {
		while(wantToRead.length > 0)
		{
			var it = wantToRead[0];
			var bufferBkp = buffer;
			if(it.bytes == -1 && ended)
			{
				wantToRead.shift();      // We need to do this first as the callback
				buffer = new Buffer(0);  // function might call checkRead()
				it.callback(null, bufferBkp);
			}
			else if(it.bytes != -1 && buffer.length >= it.bytes)
			{
				wantToRead.shift();
				buffer = buffer.slice(it.bytes);
				it.callback(null, bufferBkp.slice(0, it.bytes));
			}
			else if(ended)
			{
				wantToRead.shift();
				it.callback(new Error("Stream has ended before the requested number of bytes was sent."));
			}
			else
				break;
		}
	};
	
	if(!usingBuffer)
	{
		stream.on("data", function(data) {
			buffer = Buffer.concat([ buffer, data ]);
			
			checkRead();
		});
		stream.on("end", function(data) {
			ended = true;
			
			checkRead();
		});
	}
	
	/**
	 * The callback function is called as soon as the specified number of bytes is available, receiving a possible error
	 * message as first argument or a Buffer object with the exact specified amount of bytes as second argument. If the
	 * bytes parameter is set to -1, the callback function will only be called when the readable stream has reached its
	 * end, then passing the full content to the function.
	 * 
	 * If the stream ends before the requested number of bytes is available, the callback function will be called with an error
	 * message.
	*/
	this.read = function(bytes, callback) {
		wantToRead.push({ bytes: bytes, callback: callback });
		checkRead();
	};
}