/**
 * User: Chris Johnson
 * Date: 10/3/13
 */
module Lawn {
  export interface IUser {
    uid?
    name?:string
  }

  export class User {
    uid:number;
    name:string;
    session;

    constructor(source:IUser) {
      this.uid = source.uid || 0;
      this.name = source.name || '';
    }

    simple():IUser {
      return {
        uid: this.uid,
        name: this.name
      };
    }
  }
}