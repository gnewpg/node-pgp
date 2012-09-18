var config = require("./config");
var fs = require("fs");
var crypto = require("crypto");

function getTempFilename(callback)
{
	var cb = function(err) {
		if(err) { callback(err); return; }
		
		var fname = config.tmpDir+"/"+(new Date()).getTime();
		fs.exists(fname, function(exists) {
			if(exists)
				cb();
			else
				callback(null, fname);
		});
	};

	fs.exists(config.tmpDir, function(exists) {
		if(!exists)
			fs.mkdir(config.tmpDir, 0700, cb);
		else
			cb();
	});
}

function hash(data, algo, toFormat)
{
	var ret = crypto.createHash(algo);
	ret.update(data);
	return ret.digest(toFormat);
}

exports.getTempFilename = getTempFilename;
exports.hash = hash;