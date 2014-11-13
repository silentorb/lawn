# Changelog - Vineyard Lawn #

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