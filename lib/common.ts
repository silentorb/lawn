/**
 * User: Chris Johnson
 * Date: 11/15/2014
 */
/// <reference path="references.ts"/>

///***var when = require('when')
///***var MetaHub = require('vineyard-metahub')
///***var Ground = require('vineyard-ground')
///***var Vineyard = require('vineyard')

class HttpError {
  name = "HttpError"
  message
  stack
  status
  details
  key

  constructor(message:string, status = 500, key = undefined) {
    this.message = message
    this.status = status
    this.key = key
  }
}

class Authorization_Error extends HttpError {
  constructor(message:string, user) {
    super(message, user.username == 'anonymous' ? 401 : 403)
  }
}

function is_authenticated(user, fortress) {
  return user && typeof user.id == 'number' && user.username != 'anonymous'
}

function is_admin(user, fortress) {
  return fortress.user_has_role(user, 'admin')
}

interface Update_Request {
  objects:any[]
  version?:number
}

interface Service_Definition {
  http_path:string
  socket_path:string
  authorization:(user, fortress)=>any
  validation:string
  action:(data, user)=>Promise
}
