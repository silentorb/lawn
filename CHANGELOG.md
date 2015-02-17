# Changelog - Vineyard Lawn #

## 0.2.16 ##
1. Now Lawn will only start a Socket.IO server if a webs socket port is configured.

## 0.2.15 ##
1. Fixed session handling bugs

## 0.2.14 ##
1. Now Lawn uses db.is_active() so it requires Ground version 0.1.76 or higher.
2. Created new MySQL session store module specifically for Vineyard and Express.
3. Changed error logging to use console.error instead of console.log.
4. Fixed bugs with the update logging so it can be used again.

## 0.2.13 ##
1. Keeping the old Songbird code inside Lawn caused as many problems as I'd hoped to solve so it was removed.
   That was a short deprecation.
2. Moved the notification schema out of common.json and into the songbird module.
3. The Lawn schema files are now automatically loaded and should not be included in configuration files.

## 0.2.12 ##
1. Songbird was moved to its own npm module (vineyard-songbird).  The embedded Songbird module is deprecated.

## 0.2.11 ##
1. Lawn.add_service callbacks now also get passed the Node.js req object.

## 0.2.10 ##
1. Fixed a bug where add_service sometimes created socket.io endpoints instead of http endpoints.
2. Now Irrigation and queries track the originating user to support injecting user specific info into queries.

## 0.2.9 ##
1. Anonymous is now automatically the fallback user.
2. Authorization errors for Anonymous now return 401 instead of 403.

## 0.2.8 ##
1. Fixed regressive but where anonymous was accidentally locked out from query and update.

## 0.2.7 ##
1. Removed express-mysql-session.  It was causing too many problems.  Will eventually replace with a custom solution.

## 0.2.6 ##
1. Upgraded web sockets to use the newer web service code.

## 0.2.5 ##
1. Fixed a typo where a response message said "username" when it should have said "password".

## 0.2.4 ##
1. Added a much improved method for defining services.
2. Created the start of a gardener admin service.  Currently it allows toggling socket.io console logging.
3. Moved Irrigation into a separate file.

## 0.2.3 ##
1. Now request syntax errors (generally with JSON) return JSON responses instead of HTML.

## 0.2.2 ##
1. Upgraded installed version of express and all related modules.
2. Created vineyard/logout service.

### Migration ###
  1. Delete all the modules (or at least all express related modules) inside lawn's node_modules folder
  and run `npm install --production`. 
  2. Any site that contained an explicit logout service should probably remove it.
  
## 0.2.1 ##
1. Removed address trellises from the common.json schema file.  May eventually add them back in a separate file.
2. Added log_authorization_errors?: boolean to lawn.config.  Defaults to false.  Mostly intended for debugging.

### Migration ###
  1. Move trellis/table address, country, province, and user-address-references into you site schema.

## 0.2.0 ##
1. Abstracted user.name so it could be named differently from one site to another.
  The new default for what was user.name is user.display_name.  The lawn user and role
  schema was broken out into a separate file.  Two versions of this file exist:
   * schema/old-user.json
   * schema/new-user.json

### Migration ###
  1. Add "node_modules/vineyard-lawn/schema/user-old.json"
  to "trellis_files" configuration.  New sites should use user-new.json.

## 0.1.41 ##
1. Added require_version?:bool to lawn.config.  Defaults to false.  
When true and a request does not have a version property, query and update return a 400. 
Eventually this behavior will be added to every endpoint. 