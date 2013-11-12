/**
* User: Chris Johnson
* Date: 10/3/13
*/
var Lawn;
(function (Lawn) {
    var User = (function () {
        function User(source) {
            this.uid = source.uid || 0;
            this.name = source.name || '';
        }
        User.prototype.simple = function () {
            return {
                uid: this.uid,
                name: this.name
            };
        };
        return User;
    })();
    Lawn.User = User;
})(Lawn || (Lawn = {}));
//# sourceMappingURL=User.js.map
