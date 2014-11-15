var common = require('./common');
var HttpError = common.HttpError;

function set_config(data, lawn) {
    if (data.socket) {
        if (typeof data.socket.log == 'boolean') {
            lawn.io.set('log level', data.socket.log ? 3 : 0);
            console.log("Gardener turned socket logging " + (data.socket.log ? 'on' : 'off'));
        }
    }
    return when.resolve({
        message: 'Done',
        key: 'success'
    });
}

function grow(lawn) {
    lawn.create_user_service('vineyard/gardener/config', 'gardener/config', common.is_admin, '../validation/gardener-config.json', function (data) {
        return set_config(data, lawn);
    });
}
exports.grow = grow;
//# sourceMappingURL=gardener.js.map
