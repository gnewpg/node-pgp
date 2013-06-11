var config = require("./config.json");
var fs = require("fs");
var crypto = require("crypto");
var consts = require("./consts");

function getTempFilename(callback)
{
	var cb = function(err) {
		if(err) { callback(err); return; }
		
		var fname = config.tmpDir+"/"+Math.floor(Math.random()*(new Date()).getTime());
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
	if(typeof algo == 'number')
	{
		for(var i in consts.HASHALGO)
		{
			if(consts.HASHALGO[i] == algo)
			{
				algo = i;
				return;
			}
		}
	}

	var ret = crypto.createHash(algo);
	ret.update(data);
	return ret.digest(toFormat);
}

function indexOf(buffer, charCode)
{
	for(var i=0; i<buffer.length; i++)
	{
		if(buffer.readUInt8(i) == charCode)
			return i;
	}
	return -1;
}

function toProperArray(arr) {
	return Array.prototype.slice.call(arr);
}

function proxy(context, func) {
	return function() {
		return func.apply(context, arguments);
	}
}

function extend(obj1, obj2) {
	for(var i=1; i<arguments.length; i++)
	{
		if(arguments[i])
		{
			for(var j in arguments[i])
				obj1[j] = arguments[i][j];
		}
	}
	return obj1;
}

function callback(func) {
	var run = false;
	return function() {
		if(run)
			throw new Error("Run twice");

		run = true;
		func.apply(this, arguments);
	};
}

var RANDOM_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/**
 * Generates a random string of the specified length made of letters and numbers.
 * @param length {Number}
*/
function generateRandomString(length) {
	var ret = "";
	for(var i=0; i<length; i++)
		ret += RANDOM_CHARS.charAt(Math.floor(Math.random()*RANDOM_CHARS.length));
	return ret;
}

exports.getTempFilename = getTempFilename;
exports.hash = hash;
exports.toProperArray = toProperArray;
exports.indexOf = indexOf;
exports.proxy = proxy;
exports.extend = extend;
exports.callback = callback;
exports.generateRandomString = generateRandomString;