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
    var Path = require('path');
    lawn.vineyard.load_json_schema('gardener-config', Path.resolve(__dirname, '../validation/gardener-config.json'));
    lawn.add_service({
        http_path: 'vineyard/gardener/config',
        socket_path: 'gardener/config',
        authorization: common.is_admin,
        validation: 'gardener-config',
        action: function (data) {
            return function (data) {
                return set_config(data, lawn);
            };
        }
    });
}
exports.grow = grow;
//# sourceMappingURL=gardener.js.map
