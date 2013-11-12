///<reference path="socket.io.d.ts"/>
///<reference path="../lib/User.ts"/>

interface ISocket extends Socket {
  user?
  this(any)
}