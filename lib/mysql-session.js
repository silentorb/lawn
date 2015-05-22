/// <reference path="../../vineyard/vineyard.d.ts"/>
var express_session = require('express-session');

//class Session_Store extends express_session.Store {
//	db:Ground.Database
//
//	constructor(db:Ground.Database) {
//		super()
//		this.db = db
//	}
//
//	get(id, callback) {
//}
var Session_Store = function (db, callback) {
    if (typeof callback === "undefined") { callback = null; }
    this.db = db;
    return callback && callback();
};

Session_Store.prototype = new express_session.Store();
Session_Store.prototype.constructor = Session_Store;

Session_Store.prototype.get = function (id, callback) {
    var sql = 'SELECT `data` FROM `sessions` WHERE `token` = ?';
    this.db.query_single(sql, [id]).done(function (row) {
        var data = row ? JSON.parse(row.data) : null;
        callback(null, data);
    });
};

Session_Store.prototype.set = function (id, data, callback) {
    var sql = 'REPLACE INTO `sessions` SET ?';

    //var expires
    //if (data.cookie && data.cookie.expires)
    //	expires = data.cookie.expires
    //else
    //	expires = new Date(Date.now() + this.options.expiration)
    // Use whole seconds here; not milliseconds.
    //expires = Math.round(expires.getTime() / 1000)
    var params = {
        token: id,
        user: data.user || 0,
        expires: 0,
        data: JSON.stringify(data),
        hostname: data.ip || null
    };

    this.db.query_single(sql, params).done(function (row) {
        var data = row ? JSON.parse(row.data) : null;
        callback && callback();
    });
};

Session_Store.prototype.destroy = function (id, callback) {
    var sql = 'DELETE FROM `sessions` WHERE `token` = ?';
    this.db.query_single(sql, [id]).done(function (row) {
        callback && callback();
    });
};

Session_Store.prototype['length'] = function (callback) {
    var sql = 'SELECT COUNT(*) AS total FROM `sessions`';
    this.db.query_single(sql).done(function (row) {
        var count = row ? parseInt(row) : 0;
        callback && callback(count);
    });
};

Session_Store.prototype.clear = function (callback) {
    var sql = 'DELETE FROM `sessions`';
    this.db.query_single(sql).done(function (row) {
        callback && callback();
    });
};

module.exports = Session_Store;
//# sourceMappingURL=mysql-session.js.map
