
module Lawn {
  export interface IUser {
    id?
    name?:string
  }

  export class User {
    id:number;
    name:string;
    session;

    constructor(source:IUser) {
      this.id = source.id || 0;
      this.name = source.name || '';
    }

    simple():IUser {
      return {
        uid: this.id,
        name: this.name
      };
    }
  }
}