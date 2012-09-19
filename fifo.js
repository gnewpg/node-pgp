module.exports = function() {
	var listeners = [ ];
	var items = [ ];
	var ended = false;
	var endedError = null;
	
	this._add = add;
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