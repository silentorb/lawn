module.exports = function (grunt) {

  grunt.loadNpmTasks('grunt-ts')
  grunt.loadNpmTasks('grunt-contrib-concat')
  grunt.loadNpmTasks('grunt-contrib-watch')
  grunt.loadNpmTasks('grunt-contrib-copy')
  grunt.loadNpmTasks('grunt-text-replace')

  grunt.initConfig({
    ts: {
      lawn: {                                 // a particular target
        src: ["lib/Lawn.ts", "lib/Irrigation.ts"],        // The source typescript files, http://gruntjs.com/configuring-tasks#files
        out: 'lawn.js',                // If specified, generate an out.js file which is the merged js file
        options: {                    // use to override the default options, http://gruntjs.com/configuring-tasks#options
          target: 'es5',            // 'es3' (default) | 'es5'
          module: 'commonjs',       // 'amd' (default) | 'commonjs'
          declaration: true,       // true | false  (default)
          verbose: true
        }
      }
    },
    concat: {
      options: {
        separator: ''
      },
      lawn: {
        src: [
          'lib/lawn_header.js',
          'lawn.js',
          'lib/lawn_footer.js'
        ],
        dest: 'lawn.js'
      },
      "lawn-def": {
        src: [
          'lawn.d.ts',
          'lib/lawn_definition_footer'
        ],
        dest: 'lawn.d.ts'
      }
    },
    replace: {
      "lawn-def": {
        src: ["lawn.d.ts"],
        overwrite: true,
        replacements: [
          {
            from: 'defs/',
            to: ""
          },
          {
            from: '/// <reference path="node_redis.d.ts" />',
            to: ""
          },
          {
            from: '/// <reference path="express.d.ts" />',
            to: ""
          }
        ]
      }
    },
    copy: {
      "lawn-def": {
        files: [
          { src: 'lawn.d.ts', dest: '../../defs/'},
          { src: 'lawn.d.ts', dest: '../plantlab/defs/'}

        ]
      }
    },
    watch: {
      lawn: {
        files: 'lib/**/*.ts',
        tasks: ['default']
      }
    }
  })

  grunt.registerTask('default', ['ts:lawn', 'concat:lawn', 'concat:lawn-def', 'replace:lawn-def', 'copy:lawn-def']);

}