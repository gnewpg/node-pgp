var config = require("./config");
var child_process = require("child_process");
var packets = require("./packets")
var utils = require("./utils");
var fs = require("fs");
var consts = require("./consts");
var BufferedStream = require("./bufferedStream");
var async = require("async");

function encryptData(keyring, toKeyId, data, callback) {
	if(!Array.isArray(toKeyId))
		toKeyId = [ toKeyId ];

	var recipients = [ ];

	async.auto({
		fname: function(next) {
			utils.getTempFilename(next);
		},
		file: [ "fname", function(next, res) {
			fs.open(res.fname, "w", next);
		} ],
		write: [ "file", function(next, res) {
			async.forEachSeries(toKeyId, function(it, next) {
				keyring.getKeyWithFlag(it, consts.KEYFLAG.ENCRYPT_COMM, function(err, keyInfo) {
					if(err)
						return next(err);
					if(keyInfo == null)
						return next(new Error("No key with encrypting ability found for key "+it+"."));

					recipients.push(keyInfo.id);
					var packet = packets.generatePacket(consts.PKT.PUBLIC_KEY, keyInfo.binary);
					fs.write(res.file, fs.writeFile(res.fname, packet, 0, packet.length, null, next));
				}, [ "id", "binary" ]);
			}, next);
		} ],
		encrypt: [ "write", function(next, res) {
			// TODO: Only use MDC when set in features
			var args = [ "--no-default-keyring", "--keyring", res.fname, "--output", "-", "--trust-model", "always", "--allow-non-selfsigned-uid", "--force-mdc", "--encrypt" ];
			for(var i=0; i<recipients.length; i++)
				args.push("--recipient", recipients[i]);
			var gpg = child_process.spawn(config.gpg, args);
			gpg.stdin.end(data);
			new BufferedStream(gpg.stdout).readUntilEnd(next);
		}]
	}, function(err, res) {
		async.series([
			function(next) {
				if(res && res.file)
					fs.close(res.file, next);
				else
					next();
			},
			function(next) {
				if(res && res.fname)
					fs.unlink(res.fname, next);
				else
					next();
			}
		], function(err) {
				if(err)
					console.log("Error removing temporary file "+res.fname+".", err);
		});

		if(err)
			callback(err);
		else
			callback(null, res.encrypt);
	});
}

exports.encryptData = encryptData;