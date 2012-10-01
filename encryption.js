var config = require("./config");
var child_process = require("child_process");
var packets = require("./packets")
var utils = require("./utils");
var fs = require("fs");
var consts = require("./consts");
var BufferedStream = require("./bufferedStream");

function encryptData(data, keyring, toKeyId, callback) {
	utils.getTempFilename(function(err, fname) {
		if(err) { callback(err); return; }
		
		fs.writeFile(fname, keyring, function(err) {
			if(err)
				return unlink(err);
			
			var gpg = child_process.spawn(config.gpg, [ "--no-default-keyring", "--keyring", fname, "--output", "-", "--trust-model", "always", "--recipient", toKeyId, "--encrypt" ]);
			gpg.stdin.end(data);
			new BufferedStream(gpg.stdout).readUntilEnd(unlink);
		});
		
		function unlink() {
			/*fs.unlink(fname, function(err) {
				if(err)
					console.log("Error removing temporary file "+fname+".", err);
			});*/
			callback.apply(null, arguments);
		}
	});
}

exports.encryptData = encryptData;