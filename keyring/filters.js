var util = require("util");
var consts = require("../consts");


var Filter = function() { };

Filter.get = function(filter) {
	if(filter instanceof Filter)
		return filter;
	else if(Array.isArray(filter))
	{
		var filters = [ ];
		for(var i=0; i<filter.length; i++)
			filters.push(Filter.get(filter[i]));
		return new Filter.Or(filters);
	}
	else
		return new Filter.Equals(filter);
};

Filter.Equals = _valueFilter(function(val1, val2) {
	return val1 == val2;
});


Filter.EqualsIgnoreCase = _valueFilter(function(val1, val2) {
	return val1 == val2;
}, function(value) {
	return (""+value).toLowerCase();
});


Filter.ContainsIgnoreCase = _valueFilter(function(val1, val2) {
	return val1.indexOf(val2) != -1;
}, function(value) {
	return (""+value).toLowerCase();
});


Filter.ShortKeyId = _valueFilter(function(val1, val2) {
	return val1.substring(8) == val2;
}, function(value) {
	return (""+value).toLowerCase();
});


Filter.LessThan = _valueFilter(function(val1, val2) {
	return val1 != null && val2 != null && val1 < val2;
});


Filter.LessThanOrEqual = _valueFilter(function(val1, val2) {
	return val1 != null && val2 != null && val1 <= val2;
});


Filter.GreaterThan = _valueFilter(function(val1, val2) {
	return val1 != null && val2 != null && val1 > val2;
});


Filter.GreaterThanOrEqual = _valueFilter(function(val1, val2) {
	return val1 != null && val2 != null && val1 >= val2;
});


Filter.Not = function(filter) {
	this.__filter = filter;
};

util.inherits(Filter.Not, Filter);

Filter.Not.prototype.check = function(checkValue) {
	return !this.__filter.check(checkValue);
};


Filter.Or = function(filter) {
	this.__filters = Array.isArray(filter) ? filter : arguments;
};

util.inherits(Filter.Or, Filter);

Filter.Or.prototype.check = function(checkValue) {
	for(var i=0; i<this.__filters.length; i++)
	{
		if(this.__filters[i].check(checkValue))
			return true;
	}
	return false;
};


Filter.And = function(filter) {
	this.__filters = Array.isArray(filter) ? filter : arguments;
};

util.inherits(Filter.And, Filter);

Filter.And.prototype.check = function(checkValue) {
	for(var i=0; i<this.__filters.length; i++)
	{
		if(!this.__filters[i].check(checkValue))
			return false;
	}
	return true;
};


/**
 * Checks whether a signature sets a specific key flag in its sub-packets
 */
Filter.KeyFlag = _valueFilter(function(subPackets, flag) {
	var pkts = subPackets[consts.SIGSUBPKT.KEY_FLAGS] || [ ];
	for(var i=0; i<pkts.length; i++)
	{
		if(pkts[i].value[flag])
			return true;
	}
	return false;
});

Filter.ArrayContains = _valueFilter(function(array, contains) {
	return array.indexOf(contains) != -1;
});


function _normaliseFilterValue(value) {
	if(value instanceof Date)
		return value.getTime();
	else
		return value;
}

function _valueFilter(check, normalise) {
	if(!normalise)
		normalise = _normaliseFilterValue;

	var ret = function(value) {
		this.__rawValue = value;
		this.__value = normalise(value);
	};

	util.inherits(ret, Filter);

	ret.prototype.check = function(checkValue) {
		return check(normalise(checkValue), this.__value);
	};

	return ret;
}

module.exports = Filter;