/**
 * User: Chris Johnson
 * Date: 11/15/2014
 */

/// <reference path="references.ts"/>

class Gardener {
  static set_config(data, lawn) {
    if (data.socket) {
      if (typeof data.socket.log == 'boolean') {
        lawn.io.set('log level', data.socket.log ? 3 : 0)
        console.log("Gardener turned socket logging " + (data.socket.log ? 'on' : 'off'))
      }
    }
    return when.resolve({
      message: 'Done',
      key: 'success'
    })
  }

  static grow(lawn) {
    var Path = require('path')
    lawn.vineyard.load_json_schema('gardener-config', Path.resolve(__dirname, './validation/gardener-config.json'))
    lawn.add_service({
      http_path: 'vineyard/gardener/config',
      socket_path: 'gardener/config',
      authorization: is_admin,
      validation: 'gardener-config',
      action: (data)=> (data)=> Gardener.set_config(data, lawn)
    })
    //lawn.create_user_service('vineyard/gardener/config', 'gardener/config',
    //  is_admin, '../validation/gardener-config.json', (data)=> set_config(data, lawn))
  }
}
