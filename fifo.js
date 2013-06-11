var utils = require("./utils");
var util = require("util");

module.exports = Fifo;
module.exports.fromArraySingle = function(arr) { return new ArraySingle(arr); };
module.exports.fromArrayMultiple = function(arr) { return new ArrayMultiple(arr); };
module.exports.concat = function(fifos) { return new Multiple(fifos); };

function Fifo() {
	this.__listeners = [ ];
	this.__items = [ ];
	this.__ended = false;
	this.__endedError = null;
}

Fifo.prototype = {
	__check : function() {
		while(this.__items.length > 0 && this.__listeners.length > 0)
			this.__listeners.shift().apply(null, [ null ].concat(this.__items.shift()));
		
		if(this.__items.length == 0 && this.__ended)
		{
			while(this.__listeners.length > 0)
				this.__listeners.shift()(this.__endedError);
		}
	},
	
	_add : function() {
		var args = [ ];
		for(var i=0; i<arguments.length; i++)
			args.push(arguments[i]); // arguments is not a true array
		this.__items.push(args);
		this.__check();
	},
	
	/**
	 * Adds all the values from the items array. items is an array of arrays, and each array in it is an array of arguments to pass to the next()
	 * callback function.
	*/
	_addAllMultiple : function(items) {
		this.__items = this.__items.concat(items);
		this.__check();
	},
	
	/**
	 * Adds all the values from the items array. items is an array of objects that will be passed as first parameter to the next() callback
	 * function.
	*/
	_addAllSingle : function(items) {
		items.forEach(utils.proxy(this, function(it) {
			this.__items.push([ it ]);
		}));
		this.__check();
	},
	
	_end : function(error) {
		this.__ended = true;
		this.__endedError = error || true;
		this.__check();
	},
	
	next : function(callback) {
		this.__listeners.push(callback);
		this.__check();
	},

	forEachLimit : function(limit, iterator, callback) {
		var t = this;
		var running = 0;
		var ended = false;
		var endError = null;

		function startOne() {
			if(limit > 0 && running >= limit || ended)
				return;

			running++;
			t.next(function(err) {
				if(err)
					return finishOne(err);

				var args = utils.toProperArray(arguments);
				iterator.apply(null, args.slice(1).concat([ utils.callback(finishOne) ]));

				setImmediate(startOne);
			})
		}

		function finishOne(err) {
			running--;
			if(err && !ended) {
				ended = true;
				endError = (err === true ? null : err);
			}

			if(running == 0 && ended)
				callback(endError);
			else
				setImmediate(startOne);
		}

		setImmediate(startOne);
	},

	forEachSeries : function(iterator, callback) {
		this.forEachLimit(1, iterator, callback);
	},

	forEach : function(iterator, callback) {
		this.forEachLimit(0, iterator, callback);
	},

	toArraySingle : function(callback) {
		var ret = [ ];
		this.forEachSeries(function() {
			var args = utils.toProperArray(arguments);
			var next = args.pop();
			ret.push(args[0]);
			next();
		}, function(err) {
			if(err)
				callback(err);
			else
				callback(null, ret);
		});
	},

	toArrayMultiple : function(callback) {
		var ret = [ ];
		this.forEachSeries(function() {
			var args = utils.toProperArray(arguments);
			var next = args.pop();
			ret.push(args);
			next();
		}, function(err) {
			if(err)
				callback(err);
			else
				callback(null, ret);
		});
	},

	grep : function(grepFunc) {
		return new Grep(this, grepFunc);
	},

	map : function(mapFunc) {
		return new Map(this, mapFunc);
	},

	concat : function(fifo1) {
		return new Multiple([ this ].concat(utils.toProperArray(arguments)));
	},

	recursive : function() {
		return new Recursive(this);
	}
};

function ArraySingle(array) {
	this.__array = array;
	this.__i = 0;
}

util.inherits(ArraySingle, Fifo);

utils.extend(ArraySingle.prototype, {
	next : function(callback) {
		if(this.__i >= this.__array.length)
			callback(true);
		else
			callback(null, this.__array[this.__i++]);
	},

	toArraySingle : function(callback) {
		callback(null, [ ].concat(this.__array));
	}
});

function ArrayMultiple(array) {
	ArraySingle.apply(this, arguments);
}

util.inherits(ArrayMultiple, ArraySingle);

utils.extend(ArrayMultiple.prototype, {
	next : function(callback) {
		ArraySingle.prototype.next(function(err, items) {
			if(err)
				callback(err);
			else
				callback.apply(null, [ null ].concat(items));
		});
	},

	toArraySingle : Fifo.prototype.toArraySingle,
	
	toArrayMultiple : function(callback) {
		callback(null, this.__array);
	}
});

function Multiple(fifos) {
	this.__fifos = fifos;
	this.__i = 0;
}

util.inherits(Multiple, Fifo);

utils.extend(Multiple.prototype, {
	next : function(callback) {
		if(this.__i >= this.__fifos.length)
			callback(true);
		else
		{
			this.__fifos[this.__i].next(utils.proxy(this, function(err) {
				if(err === true)
				{
					this.__i++;
					this.next(callback);
				}
				else
					callback.apply(null, arguments);
			}));
		}
	}
});

function Recursive(fifoFifo) {
	this.__fifoFifo = fifoFifo;
	this.__parents = [ ];
}

util.inherits(Recursive, Fifo);

utils.extend(Recursive.prototype, {
	next : function(callback) {
		this.__fifoFifo.next(function(err, item) {
			if(err === true)
			{
				if(this.__parents.length == 0)
					callback(true);
				else
				{
					this.__fifoFifo = this.__parents.pop();
					this.next(callback);
				}
			}
			else if(err)
				callback(err);
			else if(item instanceof Fifo)
			{
				this.__parents.push(this.__fifoFifo);
				this.__fifoFifo = item;
				this.next(callback);
			}
			else
				callback.apply(null, arguments);
		}.bind(this));
	}
});


function Grep(fifo, grepFunc) {
	this.__fifo = fifo;
	this.__grepFunc = grepFunc;
}

util.inherits(Grep, Fifo);

utils.extend(Grep.prototype, {
	next : function(callback) {
		this.__fifo.next(utils.proxy(this, function(err, val) {
			if(err)
				return callback(err);

			var args = utils.toProperArray(arguments).slice(1);
			this.__grepFunc.apply(null, args.concat([ utils.proxy(this, function(err, doAdd) {
				if(err)
					callback(err);
				else if(doAdd)
					callback.apply(null, [ null ].concat(args));
				else
					this.next(callback);
			}) ]));
		}));
	}
});


function Map(fifo, mapFunc) {
	this.__fifo = fifo;
	this.__mapFunc = mapFunc;
}

util.inherits(Map, Fifo);

utils.extend(Map.prototype, {
	next : function(callback) {
		this.__fifo.next(utils.proxy(this, function(err, val) {
			if(err)
				return callback(err);

			var args = utils.toProperArray(arguments).slice(1);
			this.__mapFunc.apply(null, args.concat([ callback, utils.proxy(this, function() { this.next(callback); }) ]));
		}));
	}
});