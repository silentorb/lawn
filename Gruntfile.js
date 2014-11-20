module.exports = function (grunt) {

  grunt.loadNpmTasks('grunt-ts')
  grunt.loadNpmTasks('grunt-contrib-watch')
  grunt.loadNpmTasks('grunt-text-replace')

  grunt.initConfig({
    ts: {
      lawn: {                                 // a particular target
        src: ["lib/export.ts"],        // The source typescript files, http://gruntjs.com/configuring-tasks#files
        out: 'lawn.js',                // If specified, generate an out.js file which is the merged js file
        options: {                    // use to override the default options, http://gruntjs.com/configuring-tasks#options
          target: 'es5',            // 'es3' (default) | 'es5'
          module: 'commonjs',       // 'amd' (default) | 'commonjs'
          sourcemap: true,          // true  (default) | false
          declaration: true,       // true | false  (default)
          verbose: true,
          removeComments: false
        }
      }
    },
    replace: {
      "export": {
        src: 'lawn.js',
        overwrite: true,
        replacements: [
          {
            from: '///***',
            to: ""
          }
        ]
      }
    },
    watch: {
      lib: {
        files: 'lib/**/*.ts',
        tasks: ['default']
      }
    }
  })

  grunt.registerTask('default', ['ts', 'replace']);

}