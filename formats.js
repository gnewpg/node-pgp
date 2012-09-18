var child_process = require("child_process");

function decodeKeyFormat(keyBinary, callback) {
	var gpg = child_process.spawn(config.gpg, [ '--dearmor' ]);
	var error = false;

	gpg.stdin.write(keyBinary);
	gpg.stdin.end();
	
	callback(null, gpg.stdout);
}

exports.decodeKeyFormat = decodeKeyFormat;