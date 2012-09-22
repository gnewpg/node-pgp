module.exports = function() {
	var listeners = [ ];
	var items = [ ];
	var ended = false;
	var endedError = null;
	
	this._add = add;
	this._addAllMulti = addAllMulti;
	this._addAllSingle = addAllSingle;
	this._end = end;
	this.next = next;
	
	function check() {
		while(items.length > 0 && listeners.length > 0)
			listeners.shift().apply(null, [ null ].concat(items.shift()));
		
		if(items.length == 0 && ended)
		{
			while(listeners.length > 0)
				listeners.shift()(endedError);
		}
	}
	
	function add() {
		var args = [ ];
		for(var i=0; i<arguments.length; i++)
			args.push(arguments[i]); // arguments is not a true array
		items.push(args);
		check();
	}
	
	/**
	 * Adds all the values from the items array. items is an array of arrays, and each array in it is an array of arguments to pass to the next()
	 * callback function.
	*/
	function addAllMulti(items) {
		items = items.concat(items);
		check();
	}
	
	/**
	 * Adds all the values from the items array. items is an array of objects that will be passed as first parameter to the next() callback
	 * function.
	*/
	function addAllSingle(items) {
		items.forEach(function(it) {
			items.push([ it ]);
		});
		check();
	}
	
	function end(error) {
		ended = true;
		endedError = error || true;
		check();
	}
	
	function next(callback) {
		listeners.push(callback);
		check();
	}
};