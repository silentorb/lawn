var Lawn;
(function (Lawn) {
    var User = (function () {
        function User(source) {
            this.id = source.id || 0;
            this.name = source.name || '';
        }
        User.prototype.simple = function () {
            return {
                uid: this.id,
                name: this.name
            };
        };
        return User;
    })();
    Lawn.User = User;
})(Lawn || (Lawn = {}));
//# sourceMappingURL=User.js.map
