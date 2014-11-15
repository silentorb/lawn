/**
 * User: Chris Johnson
 * Date: 11/15/2014
 */

/// <reference path="../lawn.ts"/>

import common = require('./common')
var HttpError = common.HttpError

function set_config(data, lawn) {
  if (data.socket) {
    if (typeof data.socket.log == 'boolean') {
      lawn.io.set('log level', data.socket.log ? 3 : 0)
      console.log("Gardener turned socket logging " + (data.socket.log  ? 'on' : 'off'))
    }
  }
  return when.resolve({
    message: 'Done',
    key: 'success'
  })
}

export function grow(lawn) {
  //lawn.listen_user_http('/vineyard/gardener/config', (req, res, user)=> set_config(req, res, user, lawn))
  lawn.create_user_service('vineyard/gardener/config', 'gardener/config',
    common.is_admin, '../validation/gardener-config.json', (data)=> set_config(data, lawn))
}