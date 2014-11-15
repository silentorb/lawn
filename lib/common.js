var __extends = this.__extends || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    __.prototype = b.prototype;
    d.prototype = new __();
};
var HttpError = (function () {
    function HttpError(message, status, key) {
        if (typeof status === "undefined") { status = 500; }
        if (typeof key === "undefined") { key = undefined; }
        this.name = "HttpError";
        this.message = message;
        this.status = status;
        this.key = key;
    }
    return HttpError;
})();
exports.HttpError = HttpError;

var Authorization_Error = (function (_super) {
    __extends(Authorization_Error, _super);
    function Authorization_Error(message) {
        _super.call(this, message, 403);
    }
    return Authorization_Error;
})(HttpError);
exports.Authorization_Error = Authorization_Error;

function is_admin(user, fortress) {
    return fortress.user_has_role(user, 'admin');
}
exports.is_admin = is_admin;
//# sourceMappingURL=common.js.map
