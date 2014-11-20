/*
  Copyright (C) 2013
  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.
  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:
  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
*/



var i32x4 = new Int32Array(4);


exports.int32x4 = {};
/**
  * Construct a new instance of int32x4 number.
  * @param {integer} 32-bit value used for x lane.
  * @param {integer} 32-bit value used for y lane.
  * @param {integer} 32-bit value used for z lane.
  * @param {integer} 32-bit value used for w lane.
  * @constructor
  */
exports.int32x4 = function(x, y, z, w, arr) {

  if (!(this instanceof exports.int32x4)) {
    return new exports.int32x4(x, y, z, w, arr);
  }
  this._buff = arr || new Int32Array(4);
  this._buff[0] = x;
  this._buff[1] = y;
  this._buff[2] = z;
  this._buff[3] = w;
};

Object.defineProperty(exports.int32x4.prototype, 'x', {
  get: function () {
    return this._buff[0];
  }
});

Object.defineProperty(exports.int32x4.prototype, 'y', {
  get: function () {
    return this._buff[1];
  }
});

Object.defineProperty(exports.int32x4.prototype, 'z', {
  get: function () {
    return this._buff[2];
  }
});

Object.defineProperty(exports.int32x4.prototype, 'w', {
  get: function () {
    return this._buff[3];
  }
});

/**
  * @param {int32x4} a An instance of int32x4.
  * @param {int32x4} b An instance of int32x4.
  * @return {int32x4} New instance of int32x4 with values of a | b.
  */
exports.int32x4.or = function(a, b) {
  return exports.int32x4(a.x | b.x, a.y | b.y, a.z | b.z, a.w | b.w);
};
exports.int32x4.prototype.or = function(b) {
  this._buff[0] |= b.x;
  this._buff[1] |= b.y;
  this._buff[2] |= b.z;
  this._buff[3] |= b.w;
  return this;
};

/**
  * @param {int32x4} a An instance of int32x4.
  * @param {int32x4} b An instance of int32x4.
  * @return {int32x4} New instance of int32x4 with values of a ^ b.
  */
exports.int32x4.xor = function(a, b) {
  return exports.int32x4(a.x ^ b.x, a.y ^ b.y, a.z ^ b.z, a.w ^ b.w);
};

exports.int32x4.prototype.xor = function(b) {
  this._buff[0] ^= b.x;
  this._buff[1] ^= b.y;
  this._buff[2] ^= b.z;
  this._buff[3] ^= b.w;
  return this;
};

/**
  * @param {int32x4} a An instance of int32x4.
  * @param {int32x4} b An instance of int32x4.
  * @return {int32x4} New instance of int32x4 with values of a + b.
  */
exports.int32x4.add = function(a, b) {
  return exports.int32x4(a.x + b.x, a.y + b.y, a.z + b.z, a.w + b.w);
};
exports.int32x4.prototype.add = function(b) {
  this._buff[0] += b.x;
  this._buff[1] += b.y;
  this._buff[2] += b.z;
  this._buff[3] += b.w;
  return this;
};
/**
  * @param {int32x4} a An instance of int32x4.
  * @param {int32x4} b An instance of int32x4.
  * @return {int32x4} New instance of int32x4 with values of a - b.
  */
exports.int32x4.sub = function(a, b) {
  return exports.int32x4(a.x - b.x, a.y - b.y, a.z - b.z, a.w - b.w);
};

exports.int32x4.prototype.sub = function(b) {
  this._buff[0] -= b.x;
  this._buff[1] -= b.y;
  this._buff[2] -= b.z;
  this._buff[3] -= b.w;
  return this;
};

exports.int32x4.prototype.shiftRightLogical = function (b) {
  this._buff[0] >>>= b.x;
  this._buff[1] >>>= b.y;
  this._buff[2] >>>= b.z;
  this._buff[3] >>>= b.w;
  return this;
};
exports.int32x4.prototype.shiftRightLogicalBy = function (b) {
  this._buff[0] = b.x >>> this._buff[0] ;
  this._buff[1] = b.y >>> this._buff[1];
  this._buff[2] = b.z >>> this._buff[2]; 
  this._buff[3] = b.w >>> this._buff[3];
  return this;
};
exports.int32x4.prototype.shiftLeft =function (b) {
  this._buff[0] <<= b.x;
  this._buff[1] <<= b.y;
  this._buff[2] <<= b.z;
  this._buff[3] <<= b.w;
  return this;
};

/**
  * @param {int32x4} t An instance of float32x4 to be swizzled.
  * @param {integer} x - Index in t for lane x
  * @param {integer} y - Index in t for lane y
  * @param {integer} z - Index in t for lane z
  * @param {integer} w - Index in t for lane w
  * @return {int32x4} New instance of float32x4 with lanes swizzled.
  */
exports.int32x4.swizzle = function(t, x, y, z, w) {
  var storage = i32x4;
  storage[0] = t.x;
  storage[1] = t.y;
  storage[2] = t.z;
  storage[3] = t.w;
  return exports.int32x4(storage[x], storage[y], storage[z], storage[w]);
};

exports.int32x4.prototype.swizzle = function(x, y, z, w) {
  var storage = i32x4;
  storage[0] = this.x;
  storage[1] = this.y;
  storage[2] = this.z;
  storage[3] = this.w;
  this._buff[0] = storage[x];
  this._buff[1] = storage[y];
  this._buff[2] = storage[z];
  this._buff[3] = storage[w];
  return this;
};
/**
  * @param {int32x4} t An instance of int32x4.
  * @param {integer} 32-bit value used for x lane.
  * @return {int32x4} New instance of int32x4 with the values in t and
  * x lane replaced with {x}.
  */

exports.int32x4.withX = function(t, x) {
  return exports.int32x4(x, t.y, t.z, t.w);
};
exports.int32x4.prototype.withX = function(x) {
  this._buff[0] = x;
  return this;
};

exports.int32x4.prototype.clone = function(arr) {
  return new exports.int32x4(this.x, this.y, this.z, this.w, arr);
};