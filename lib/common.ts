/**
 * User: Chris Johnson
 * Date: 11/15/2014
 */
/// <reference path="../../vineyard/vineyard.d.ts"/>

export class HttpError {
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

export class Authorization_Error extends HttpError {
  constructor(message:string) {
    super(message, 403)
  }
}

export function is_authenticated(user, fortress) {
  return user && typeof user.id == 'number' && user.username != 'anonymous'
}

export function is_admin(user, fortress) {
  return fortress.user_has_role(user, 'admin')
}

export interface Update_Request {
  objects:any[]
  version?:number
}

export interface Service_Definition {
  http_path:string
  socket_path:string
  authorization:(user, fortress)=>any
  validation:string
  action:(data, user)=>Promise
}