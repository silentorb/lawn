/**
 * User: Chris Johnson
 * Date: 11/15/2014
 */

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

export function is_admin(user, fortress) {
  return fortress.user_has_role(user, 'admin')
}
